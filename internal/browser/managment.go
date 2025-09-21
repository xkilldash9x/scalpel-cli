// internal/browser/management.go
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime/debug" // For stack traces on panic recovery

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// ExposeFunction allows Go functions to be called from the browser's JavaScript context.
// This is a manual implementation to handle specific types and provide robust type conversion.
func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	// 1. Add the binding to the browser. This tells the JS runtime that this function name is special.
	err := s.runActions(ctx, runtime.AddBinding(name))
	if err != nil {
		return fmt.Errorf("failed to add binding '%s': %w", name, err)
	}

	// Reflect on the provided Go function definition once.
	fnVal := reflect.ValueOf(function)
	fnType := fnVal.Type()

	if fnType.Kind() != reflect.Func {
		// Log error and return error if the provided object is not a function.
		s.logger.Error("Exposed implementation is not a function.", zap.String("name", name))
		return fmt.Errorf("provided implementation for '%s' is not a function", name)
	}

	// 2. Listen for the binding to be called.
	chromedp.ListenTarget(s.ctx, func(ev interface{}) {
		if ev, ok := ev.(*runtime.EventBindingCalled); ok && ev.Name == name {
			// This callback runs in a separate goroutine.
			
			// Unmarshal the payload from the JS call.
			var args []interface{}
			if err := json.Unmarshal([]byte(ev.Payload), &args); err != nil {
				s.logger.Error("Could not unmarshal payload for exposed function.", zap.String("name", name), zap.Error(err), zap.String("payload", ev.Payload))
				return
			}

			// Prepare arguments for the Go function call.
			numIn := fnType.NumIn()
			if len(args) != numIn {
				s.logger.Error("Mismatch in argument count for exposed function.",
					zap.String("name", name),
					zap.Int("expected", numIn),
					zap.Int("got", len(args)))
				return
			}

			in := make([]reflect.Value, numIn)
			for i := 0; i < numIn; i++ {
				arg := args[i]
				paramType := fnType.In(i)
				argVal := reflect.ValueOf(arg)

				// Handle nil arguments from JS.
				if !argVal.IsValid() {
					in[i] = reflect.Zero(paramType)
					continue
				}

				// Check if the type matches exactly or is assignable.
				if argVal.Type().AssignableTo(paramType) {
					in[i] = argVal
					continue
				}

				// Attempt conversion (e.g., JSON number/float64 to Go int/string).
				if argVal.Type().ConvertibleTo(paramType) {
					in[i] = argVal.Convert(paramType)
					continue
				}

				// If types are incompatible.
				s.logger.Error("Incompatible argument type for exposed function.",
					zap.String("name", name),
					zap.Int("arg_index", i),
					zap.String("expected", paramType.String()),
					zap.String("got", argVal.Type().String()))
				return
			}

			// Call the Go function safely.
			func() {
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error("Panic during exposed function call.",
							zap.String("name", name),
							zap.Any("panic_reason", r),
							zap.String("stack", string(debug.Stack())))
					}
				}()
				fnVal.Call(in)
			}()
		}
	})
	return nil
}

// InjectScriptPersistently adds a script that will be executed on all new documents in the session.
func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	var scriptID page.ScriptIdentifier
	err := s.runActions(ctx, chromedp.ActionFunc(func(c context.Context) error {
		var err error
		scriptID, err = page.AddScriptToEvaluateOnNewDocument(script).Do(c)
		return err
	}))
	if err != nil {
		// Check if the context was canceled during the operation.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("could not inject persistent script: %w", err)
	}
	s.logger.Debug("Injected persistent script.", zap.String("scriptID", string(scriptID)))
	return nil
}

// ExecuteScript runs a snippet of JavaScript in the current document and optionally unmarshals the result into res.
func (s *Session) ExecuteScript(ctx context.Context, script string, res interface{}) error {
	// chromedp.Evaluate handles the case where res is nil (no result expected).
	return s.runActions(ctx, chromedp.Evaluate(script, res))
}