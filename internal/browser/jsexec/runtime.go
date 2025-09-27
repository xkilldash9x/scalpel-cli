// internal/browser/jsexec/runtime.go
package jsexec

import (
	"context"
	"fmt"
    "strings"
	"time"

	"github.com/dop251/goja"
    "go.uber.org/zap"

    "github.com/xkilldash9x/scalpel-cli/internal/browser/jsbind"
)

// Runtime provides a persistent environment for executing JavaScript using Goja,
// integrated with the browser's DOM via the DOMBridge.
type Runtime struct {
    vm *goja.Runtime
    bridge *jsbind.DOMBridge
    logger *zap.Logger
}

const DefaultTimeout = 30 * time.Second

// NewRuntime creates a new, initialized JavaScript runtime and its associated DOM bridge.
// This is called once per session.
func NewRuntime(logger *zap.Logger) *Runtime {
    if logger == nil {
        logger = zap.NewNop()
    }
    log := logger.Named("jsexec")

    // 1. Initialize the Goja VM.
	vm := goja.New()

    // Ensure basic global utilities like JSON are available.
    // Goja automatically provides JSON object, but explicitly ensuring it helps clarity.
    if vm.Get("JSON") == nil {
        // Should typically not happen in modern Goja, but safe fallback if necessary.
        vm.Set("JSON", vm.NewObject())
    }

    // 2. Initialize the DOM Bridge. This configures the VM with DOM bindings (window, document, console, etc.).
    bridge := jsbind.NewDOMBridge(vm, logger)

	return &Runtime{
        vm: vm,
        bridge: bridge,
        logger: log,
    }
}

// GetBridge returns the associated DOMBridge, allowing the session to update the DOM state.
func (r *Runtime) GetBridge() *jsbind.DOMBridge {
    return r.bridge
}

// ExecuteScript runs a JavaScript snippet within the persistent VM environment.
// Args can be passed if the script is structured as a function wrapper.
func (r *Runtime) ExecuteScript(ctx context.Context, script string, args []interface{}) (interface{}, error) {
	// 1. Determine the execution timeout.
	timeout := DefaultTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeToDeadline := time.Until(deadline)
		if timeToDeadline < timeout && timeToDeadline > 0 {
			timeout = timeToDeadline
		}
	}

	// 2. Set up timeout/cancellation handling using vm.Interrupt().
    // The VM is shared, so we must manage interrupts carefully.
	done := make(chan struct{})
	interruptHandler := make(chan struct{})

    // Clear potential stale interrupts from previous executions.
    r.vm.ClearInterrupt()


	go func() {
        defer close(interruptHandler)
		select {
		case <-time.After(timeout):
            r.logger.Warn("JavaScript execution timeout", zap.Duration("timeout", timeout))
			r.vm.Interrupt(fmt.Sprintf("Execution timeout exceeded (%v)", timeout))
		case <-ctx.Done():
			// Interrupt the VM execution upon context cancellation.
            r.logger.Debug("JavaScript execution context canceled")
			r.vm.Interrupt(ctx.Err().Error())
		case <-done:
			// Execution finished normally.
		}
	}()

    // 3. Execute the script or function.
    var result goja.Value
    var err error

    // Check if the script is intended to be executed as a function wrapper (common in automation).
    if r.isFunctionWrapper(script) {
        result, err = r.executeFunctionWrapper(script, args)
    } else {
        // Execute as a plain script snippet.
        if len(args) > 0 {
            r.logger.Debug("Arguments provided to ExecuteScript in snippet mode are ignored.")
        }
	    result, err = r.vm.RunString(script)
    }

    // Signal the interrupt monitor to stop and wait for it to acknowledge.
	close(done)
    <-interruptHandler


	if err != nil {
		// Check if the error was due to the interruption.
		if intErr, ok := err.(*goja.InterruptedError); ok {
			return nil, fmt.Errorf("javascript execution interrupted: %s", intErr.Error())
		}
		// Handle general JavaScript errors.
		if jsErr, ok := err.(*goja.Exception); ok {
			return nil, fmt.Errorf("javascript exception: %s", jsErr.String())
		}
		return nil, fmt.Errorf("javascript error: %w", err)
	}

    // 4. Handle Promises.
    if promise, ok := result.Export().(*goja.Promise); ok {
        return r.waitForPromise(ctx, promise)
    }

	// 5. Export the result from the VM back to a Go type.
	return result.Export(), nil
}

// isFunctionWrapper uses heuristics to detect common function wrappers.
func (r *Runtime) isFunctionWrapper(script string) bool {
    s := strings.TrimSpace(script)
    if len(s) < 5 {
        return false
    }

    // Check for (function, (async function, function, async function, arrow functions.
    if strings.HasPrefix(s, "(function") || strings.HasPrefix(s, "(async function") ||
       strings.HasPrefix(s, "function") || strings.HasPrefix(s, "async function") ||
       strings.HasPrefix(s, "(()=>") || strings.HasPrefix(s, "(async (") {
        return true
    }
    return false
}

// executeFunctionWrapper attempts to evaluate the script and call it as a function.
func (r *Runtime) executeFunctionWrapper(script string, args []interface{}) (goja.Value, error) {
    // Compile the script.
    prog, err := goja.Compile("", script, false)
    if err != nil {
        return nil, fmt.Errorf("failed to compile function wrapper script: %w", err)
    }

    // Run the program to get the evaluated value (expected to be a function).
    val, err := r.vm.RunProgram(prog)
    if err != nil {
        return nil, err
    }

    // Assert that the result is a callable function.
    fn, ok := goja.AssertFunction(val)
    if !ok {
        // If the script evaluates to something else (e.g., undefined for a plain function declaration), it's not an immediately callable wrapper.
        return nil, fmt.Errorf("script did not evaluate to a callable function wrapper")
    }

    // Convert Go arguments to Goja values.
    gojaArgs := make([]goja.Value, len(args))
    for i, arg := range args {
        gojaArgs[i] = r.vm.ToValue(arg)
    }

    // Call the function. 'this' context is the global object (window).
    return fn(r.vm.GlobalObject(), gojaArgs...)
}

// waitForPromise waits for a Goja promise to resolve or reject.
func (r *Runtime) waitForPromise(ctx context.Context, promise *goja.Promise) (interface{}, error) {
    // (CRITICAL LIMITATION: Goja requires an event loop for asynchronous promise resolution).
    // Without a full event loop, we can only handle promises that are already settled.

    state := promise.State()
    switch state {
    case goja.PromiseStateFulfilled:
        return promise.Result().Export(), nil
    case goja.PromiseStateRejected:
        return nil, fmt.Errorf("javascript promise rejected: %v", promise.Result().Export())
    case goja.PromiseStatePending:
        // Pending promises will never resolve without an event loop.
        r.logger.Warn("JavaScript returned a pending Promise. Asynchronous operations are not fully supported without an event loop.")
        // Return the promise object itself.
        return promise.Export(), nil
    }
    return nil, fmt.Errorf("unknown promise state")
}
