// internal/browser/jsexec/runtime.go
package jsexec

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/jsbind"
)

// Runtime provides a persistent environment for executing JavaScript using Goja,
// integrated with the browser's DOM via the DOMBridge.
type Runtime struct {
	bridge    *jsbind.DOMBridge
	logger    *zap.Logger
	eventLoop *eventloop.EventLoop
	execMutex sync.Mutex
}

// NewRuntime creates a new, initialized JavaScript runtime and its associated DOM bridge.
// This is called once per session.
func NewRuntime(logger *zap.Logger, eventLoop *eventloop.EventLoop, browserEnv jsbind.BrowserEnvironment, persona schemas.Persona) *Runtime {
	if logger == nil {
		logger = zap.NewNop()
	}
	log := logger.Named("jsec")

	// The DOM bridge is created once and holds the persistent state (DOM, storage).
	bridge := jsbind.NewDOMBridge(log, browserEnv, persona)

	return &Runtime{
		bridge:    bridge,
		logger:    log,
		eventLoop: eventLoop,
	}
}

// GetBridge returns the associated DOMBridge, allowing the session to update the DOM state.
func (r *Runtime) GetBridge() *jsbind.DOMBridge {
	return r.bridge
}

// ExecuteScript runs a JavaScript snippet within a clean, ephemeral VM environment.
// It handles context based cancellation, timeouts, and asynchronous Promises.
func (r *Runtime) ExecuteScript(ctx context.Context, script string, args []interface{}) (interface{}, error) {
	r.execMutex.Lock()
	defer r.execMutex.Unlock()

	vm := goja.New()

	// Call our new function to inject the timers.
	r.injectTimers(vm)

	// Bind the rest of the browser environment.
	r.bridge.BindToRuntime(vm, "about:blank")

	stopInterruptListener := make(chan struct{})
	defer close(stopInterruptListener)

	go func() {
		select {
		case <-ctx.Done():
			vm.Interrupt(ctx.Err())
		case <-stopInterruptListener:
			return
		}
	}()

	var result goja.Value
	var err error

	if r.isFunctionWrapper(script) {
		result, err = r.executeFunctionWrapper(vm, script, args)
	} else {
		if len(args) > 0 {
			r.logger.Debug("Arguments provided to ExecuteScript in snippet mode are ignored.")
		}
		result, err = vm.RunString(script)
	}

	if err != nil {
		if _, ok := err.(*goja.InterruptedError); ok {
			return nil, fmt.Errorf("javascript execution interrupted by context: %w", ctx.Err())
		}
		if jsErr, ok := err.(*goja.Exception); ok {
			return nil, fmt.Errorf("javascript exception: %s", jsErr.String())
		}
		return nil, fmt.Errorf("javascript error: %w", err)
	}

	if _, ok := result.Export().(*goja.Promise); ok {
		return r.waitForPromise(ctx, vm, result)
	}

	return result.Export(), nil
}

// injectTimers manually creates and sets timer functions (setTimeout, etc.)
// on a given VM instance, connecting them to the runtime's event loop.
func (r *Runtime) injectTimers(vm *goja.Runtime) {
	// setTimeout(callback, delay, ...args)
	vm.Set("setTimeout", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return goja.Undefined()
		}
		callback, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			// Browsers often allow strings (eval), but we restrict to functions for safety.
			return goja.Undefined()
		}

		delay := int64(0)
		if len(call.Arguments) > 1 {
			delay = call.Argument(1).ToInteger()
		}

		var args []goja.Value
		if len(call.Arguments) > 2 {
			args = call.Arguments[2:]
		}

		// The callback provided to SetTimeout must accept a *goja.Runtime argument.
		timer := r.eventLoop.SetTimeout(func(_ *goja.Runtime) {
			// This func() is what the event loop executes after the delay.
			// It calls the original JavaScript callback function.
			// 'this' will be the global object (Undefined in strict mode, which Goja defaults to)
			callback(goja.Undefined(), args...)
		}, time.Duration(delay)*time.Millisecond)

		// Return the timer object so JavaScript can pass it to clearTimeout.
		return vm.ToValue(timer)
	})

	// clearTimeout(timer)
	vm.Set("clearTimeout", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return goja.Undefined()
		}
		// Export the argument and check if it's the correct timer type from the eventloop package.
		if timer, ok := call.Argument(0).Export().(*eventloop.Timer); ok {
			r.eventLoop.ClearTimeout(timer)
		}
		return goja.Undefined()
	})

	// setInterval(callback, delay, ...args)
	vm.Set("setInterval", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return goja.Undefined()
		}
		callback, ok := goja.AssertFunction(call.Argument(0))
		if !ok {
			return goja.Undefined()
		}

		delay := int64(0)
		if len(call.Arguments) > 1 {
			delay = call.Argument(1).ToInteger()
		}

		var args []goja.Value
		if len(call.Arguments) > 2 {
			args = call.Arguments[2:]
		}

		// The callback must also accept a *goja.Runtime argument.
		timer := r.eventLoop.SetInterval(func(_ *goja.Runtime) {
			callback(goja.Undefined(), args...)
		}, time.Duration(delay)*time.Millisecond)

		return vm.ToValue(timer)
	})

	// clearInterval(timer)
	vm.Set("clearInterval", func(call goja.FunctionCall) goja.Value {
		if len(call.Arguments) < 1 {
			return goja.Undefined()
		}
		// setInterval returns an *Interval, not a *Timer.
		if timer, ok := call.Argument(0).Export().(*eventloop.Interval); ok {
			r.eventLoop.ClearInterval(timer)
		}
		return goja.Undefined()
	})
}

// isFunctionWrapper uses heuristics to detect common function wrappers.
func (r *Runtime) isFunctionWrapper(script string) bool {
	s := strings.TrimSpace(script)
	if len(s) < 5 {
		return false
	}

	// Exclude IIFEs (Immediately Invoked Function Expressions)
	if (strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")()")) || (strings.HasPrefix(s, "(async") && strings.HasSuffix(s, ")()")) {
		return false
	}

	return strings.HasPrefix(s, "(function") || strings.HasPrefix(s, "(async function") ||
		strings.HasPrefix(s, "function") || strings.HasPrefix(s, "async function") ||
		strings.HasPrefix(s, "(()=>") || strings.HasPrefix(s, "(async (")
}

// executeFunctionWrapper attempts to evaluate the script and call it as a function.
// It now requires the vm instance to be passed in.
func (r *Runtime) executeFunctionWrapper(vm *goja.Runtime, script string, args []interface{}) (goja.Value, error) {
	prog, err := goja.Compile("", script, false)
	if err != nil {
		return nil, fmt.Errorf("failed to compile function wrapper script: %w", err)
	}

	val, err := vm.RunProgram(prog)
	if err != nil {
		return nil, err
	}

	fn, ok := goja.AssertFunction(val)
	if !ok {
		return nil, fmt.Errorf("script did not evaluate to a callable function wrapper")
	}

	gojaArgs := make([]goja.Value, len(args))
	for i, arg := range args {
		gojaArgs[i] = vm.ToValue(arg)
	}

	return fn(vm.GlobalObject(), gojaArgs...)
}

// waitForPromise waits for a Goja promise to resolve or reject, respecting the context.
// It now requires the specific vm instance that the promise belongs to.
func (r *Runtime) waitForPromise(ctx context.Context, vm *goja.Runtime, promiseVal goja.Value) (interface{}, error) {
	promise, ok := promiseVal.Export().(*goja.Promise)
	if !ok {
		return nil, fmt.Errorf("internal error: waitForPromise called with non-promise")
	}

	switch promise.State() {
	case goja.PromiseStateFulfilled:
		return promise.Result().Export(), nil
	case goja.PromiseStateRejected:
		rejectionReason := promise.Result()
		var errMsg string
		if obj := rejectionReason.ToObject(vm); obj != nil {
			if stack := obj.Get("stack"); stack != nil && !goja.IsUndefined(stack) && stack.String() != "" {
				errMsg = stack.String()
			} else {
				errMsg = rejectionReason.String()
			}
		} else {
			errMsg = rejectionReason.String()
		}
		return nil, fmt.Errorf("javascript promise rejected: %s", errMsg)
	}

	resultChan := make(chan interface{}, 1)
	errChan := make(chan error, 1)

	// This must run on the shared event loop, but it operates on the specific vm.
	r.eventLoop.RunOnLoop(func(loopVm *goja.Runtime) {
		// NOTE: loopVm is the event loop's internal VM, we must use our ephemeral `vm`.
		onFulfilled := func(call goja.FunctionCall) goja.Value {
			resolvedValue := call.Argument(0)
			resultChan <- resolvedValue.Export()
			return goja.Undefined()
		}

		onRejected := func(call goja.FunctionCall) goja.Value {
			rejectedValue := call.Argument(0)
			var errMsg string
			if obj := rejectedValue.ToObject(vm); obj != nil {
				if stack := obj.Get("stack"); stack != nil && !goja.IsUndefined(stack) && stack.String() != "" {
					errMsg = stack.String()
				} else {
					errMsg = rejectedValue.String()
				}
			} else {
				errMsg = rejectedValue.String()
			}

			errChan <- fmt.Errorf("promise rejected: %s", errMsg)
			return goja.Undefined()
		}

		promiseObject := promiseVal.ToObject(vm)
		if promiseObject == nil {
			errChan <- fmt.Errorf("internal error: promise value is not an object")
			return
		}

		then, ok := goja.AssertFunction(promiseObject.Get("then"))
		if !ok {
			errChan <- fmt.Errorf("internal error: promise object is missing .then method")
			return
		}

		if _, err := then(promiseObject, vm.ToValue(onFulfilled), vm.ToValue(onRejected)); err != nil {
			errChan <- fmt.Errorf("error calling promise.then: %w", err)
		}
	})

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		select {
		case result := <-resultChan:
			return result, nil
		case err := <-errChan:
			return nil, err
		default:
			return nil, fmt.Errorf("context done while waiting for promise: %w", ctx.Err())
		}
	}
}