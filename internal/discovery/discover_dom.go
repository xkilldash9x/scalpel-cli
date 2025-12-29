// internal/discovery/discover_dom.go
package discovery

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
	"go.uber.org/zap"
)

// detectionMethod represents a single method for detecting a technology.
type detectionMethod struct {
	// JavaScript expression to evaluate. Should return a boolean.
	jsCheck string
	// Substring to look for in <script> src attributes.
	srcCheck string
}

// technologyChecks is a map of technologies and the methods to detect them.
var technologyChecks = map[string]detectionMethod{
	"jQuery": {
		jsCheck:  "typeof window.jQuery !== 'undefined'",
		srcCheck: "jquery",
	},
	"React": {
		jsCheck:  "typeof window.React !== 'undefined' || document.querySelector('[data-reactroot]') !== null",
		srcCheck: "react",
	},
	"Angular": {
		jsCheck:  "typeof window.angular !== 'undefined' || document.querySelector('.ng-scope') !== null",
		srcCheck: "angular",
	},
	"Vue.js": {
		jsCheck:  "typeof window.Vue !== 'undefined' || document.querySelector('[data-v-app]') !== null",
		srcCheck: "vue",
	},
}

// DOMTechnologyDiscoverer uses the browser session context to identify technologies.
type DOMTechnologyDiscoverer struct{}

// NewDOMTechnologyDiscoverer creates a new DOMTechnologyDiscoverer.
func NewDOMTechnologyDiscoverer() *DOMTechnologyDiscoverer {
	return &DOMTechnologyDiscoverer{}
}

// Discover concurrently checks for web technologies on the page for high performance.
func (d *DOMTechnologyDiscoverer) Discover(ctx context.Context, session schemas.SessionContext) ([]Technology, error) {
	logger := observability.GetLogger().Named("dom-discoverer")

	// Use a sync.Map for concurrent-safe writes. The key is the tech name, value is bool.
	techSet := &sync.Map{}
	var wg sync.WaitGroup

	// -- 1. Concurrently check for JavaScript global variables --
	for techName, method := range technologyChecks {
		// Avoid closing over loop variables in a goroutine.
		name := techName
		check := method.jsCheck

		if check == "" {
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Execute the JavaScript evaluation using the session context.
			rawResult, err := session.ExecuteScript(ctx, check, nil)
			if err != nil {
				logger.Debug("Error executing script for tech check", zap.String("tech", name), zap.Error(err))
				return
			}

			var result bool
			// Unmarshal the JSON result into our boolean.
			if err := json.Unmarshal(rawResult, &result); err != nil {
				logger.Debug("Error unmarshaling JS result for tech check", zap.String("tech", name), zap.Error(err))
				return
			}

			if result {
				techSet.Store(name, true)
			}
		}()
	}

	// -- 2. Get all script tag sources once using ExecuteScript --
	// This script grabs all script elements with a 'src' attribute, maps them to their 'src' value,
	// and returns it as a JSON string array.
	scriptQuery := `JSON.stringify(Array.from(document.querySelectorAll('script[src]')).map(s => s.src))`
	rawSrcs, err := session.ExecuteScript(ctx, scriptQuery, nil)
	if err != nil {
		// If we can't get script sources, we can't check them, but we should still wait for JS checks.
		logger.Warn("Could not retrieve script sources for technology discovery", zap.Error(err))
	} else {
		var scriptSrcs []string
		if err := json.Unmarshal(rawSrcs, &scriptSrcs); err != nil {
			logger.Warn("Could not unmarshal script sources from JS result", zap.Error(err))
		} else {
			// -- 3. Check script sources --
			// This part is fast enough not to need its own goroutines.
			for _, src := range scriptSrcs {
				for techName, method := range technologyChecks {
					if method.srcCheck != "" && strings.Contains(src, method.srcCheck) {
						techSet.Store(techName, true)
						// For more complex cases, you might remove this `break`.
						break
					}
				}
			}
		}
	}

	// Wait for all the JavaScript evaluation goroutines to finish.
	wg.Wait()

	// -- 4. Compile the results --
	var technologies []Technology
	techSet.Range(func(key, value interface{}) bool {
		if techName, ok := key.(string); ok {
			technologies = append(technologies, Technology{Name: techName})
		}
		return true
	})

	return technologies, nil
}