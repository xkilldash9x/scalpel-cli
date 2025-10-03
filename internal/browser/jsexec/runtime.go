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

	"github.com/xkilldash9x/scalpel-cli/internal/browser/jsbind"
)

// Runtime provides a persistent environment for executing JavaScript using Goja,
// integrated with the browser's DOM via the DOMBridge.
type Runtime struct {
	vm        *goja.Runtime
	bridge    *jsbind.DOMBridge
	logger    *zap.Logger
	eventLoop *eventloop.EventLoop
	execMutex sync.Mutex // -- Added to serialize script execution --
}

// DefaultTimeout is the fallback execution timeout if the context has no deadline.
const DefaultTimeout = 30 * time.Second

// NewRuntime creates a new, initialized JavaScript runtime and its associated DOM bridge.
// This is called once per session.
func NewRuntime(logger *zap.Logger, eventLoop *eventloop.EventLoop, browserEnv jsbind.BrowserEnvironment) *Runtime {
	if logger == nil {
		logger = zap.NewNop()
	}
	log := logger.Named("jsexec")

	// 1. Initialize the Goja VM.
	vm := goja.New()

	// 2. Initialize the DOM Bridge. This configures the VM with DOM bindings
	// (e.g., window, document, console, setTimeout). The bridge needs access to the
	// event loop to provide asynchronous browser APIs.
	bridge := jsbind.NewDOMBridge(log, eventLoop, browserEnv)

	return &Runtime{
		vm:        vm,
		bridge:    bridge,
		logger:    log,
		eventLoop: eventLoop,
	}
}

// GetBridge returns the associated DOMBridge, allowing the session to update the DOM state.
func (r *Runtime) GetBridge() *jsbind.DOMBridge {
	return r.bridge
}

// ExecuteScript runs a JavaScript snippet within the persistent VM environment.
// It handles context based cancellation, timeouts, and asynchronous Promises.
// Args can be passed if the script is structured as a function wrapper.
func (r *Runtime) ExecuteScript(ctx context.Context, script string, args []interface{}) (interface{}, error) {
	// -- This lock ensures that only one script can execute at a time, preventing
	// race conditions on the VM's interrupt channel.
	r.execMutex.Lock()
	defer r.execMutex.Unlock()

	// If the parent context has no deadline, create a child context with a default timeout.
	// This is a safeguard to prevent scripts from running indefinitely.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
		defer cancel()
	}

	// Set up interruption handling. Goja can be interrupted by closing the channel
	// passed to SetInterrupt. By passing ctx.Done(), Goja will automatically
	// interrupt execution when the context is canceled or its deadline is exceeded.
	r.vm.SetInterrupt(ctx.Done())
	// It is critical to clear the interrupt handler after execution to prevent
	// it from affecting the next script run.
	defer r.vm.ClearInterrupt()

	// Execute the script or function wrapper.
	var result goja.Value
	var err error

	if r.isFunctionWrapper(script) {
		result, err = r.executeFunctionWrapper(script, args)
	} else {
		if len(args) > 0 {
			r.logger.Debug("Arguments provided to ExecuteScript in snippet mode are ignored.")
		}
		result, err = r.vm.RunString(script)
	}

	// Handle any errors that occurred during execution.
	if err != nil {
		// Check if the error was due to context interruption.
		if _, ok := err.(*goja.InterruptedError); ok {
			// If so, return the context's error for a clearer message (canceled vs. deadline exceeded).
			return nil, fmt.Errorf("javascript execution interrupted by context: %w", ctx.Err())
		}
		if jsErr, ok := err.(*goja.Exception); ok {
			return nil, fmt.Errorf("javascript exception: %s", jsErr.String())
		}
		return nil, fmt.Errorf("javascript error: %w", err)
	}

	// If the script returns a Promise, we must wait for it to settle.
	if promise, ok := result.Export().(*goja.Promise); ok {
		return r.waitForPromise(ctx, promise)
	}

	// For synchronous results, export the value from the VM back to a Go type.
	return result.Export(), nil
}

// isFunctionWrapper uses heuristics to detect common function wrappers.
func (r *Runtime) isFunctionWrapper(script string) bool {
	s := strings.TrimSpace(script)
	if len(s) < 5 {
		return false
	}

	return strings.HasPrefix(s, "(function") || strings.HasPrefix(s, "(async function") ||
		strings.HasPrefix(s, "function") || strings.HasPrefix(s, "async function") ||
		strings.HasPrefix(s, "(()=>") || strings.HasPrefix(s, "(async (")
}

// executeFunctionWrapper attempts to evaluate the script and call it as a function.
func (r *Runtime) executeFunctionWrapper(script string, args []interface{}) (goja.Value, error) {
	prog, err := goja.Compile("", script, false)
	if err != nil {
		return nil, fmt.Errorf("failed to compile function wrapper script: %w", err)
	}

	val, err := r.vm.RunProgram(prog)
	if err != nil {
		return nil, err
	}

	fn, ok := goja.AssertFunction(val)
	if !ok {
		return nil, fmt.Errorf("script did not evaluate to a callable function wrapper")
	}

	gojaArgs := make([]goja.Value, len(args))
	for i, arg := range args {
		gojaArgs[i] = r.vm.ToValue(arg)
	}

	return fn(r.vm.GlobalObject(), gojaArgs...)
}

// waitForPromise waits for a Goja promise to resolve or reject, respecting the context.
// It leverages the event loop to handle the asynchronous nature of Promises.
func (r *Runtime) waitForPromise(ctx context.Context, promise *goja.Promise) (interface{}, error) {
	// A quick check for already settled promises to avoid the overhead of the event loop.
	switch promise.State() {
	case goja.PromiseStateFulfilled:
		return promise.Result().Export(), nil
	case goja.PromiseStateRejected:
		rejectionReason := promise.Result().Export()
		return nil, fmt.Errorf("javascript promise rejected: %v", rejectionReason)
	}

	resultChan := make(chan interface{}, 1)
	errChan := make(chan error, 1)

	// We must schedule the .Then() call on the event loop's goroutine
	// to ensure thread safe access to the VM.
	r.eventLoop.RunOnLoop(func() {
		onFulfilled := func(v goja.Value) {
			resultChan <- v.Export()
		}
		onRejected := func(v goja.Value) {
			errChan <- fmt.Errorf("promise rejected: %v", v.Export())
		}

		// Attach the handlers to the promise.
		promise.Then(r.vm.ToValue(onFulfilled), r.vm.ToValue(onRejected))
	})

	// Wait for the result, an error, or the context to be done.
	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("context done while waiting for promise: %w", ctx.Err())
	}
}

