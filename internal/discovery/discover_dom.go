// internal/discovery/discover_dom.go
package discovery

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	interfaces "github.com/xkilldash9x/scalpel-cli/internal/agent" // using an interface for the session
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
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

// DOMTechnologyDiscoverer uses the Chrome DevTools Protocol to identify technologies.
type DOMTechnologyDiscoverer struct{}

// NewDOMTechnologyDiscoverer creates a new DOMTechnologyDiscoverer.
func NewDOMTechnologyDiscoverer() *DOMTechnologyDiscoverer {
	return &DOMTechnologyDiscoverer{}
}

// Discover concurrently checks for web technologies on the page for high performance.
func (d *DOMTechnologyDiscoverer) Discover(ctx context.Context, session interfaces.SessionContext) ([]Technology, error) {
	logger := observability.GetLogger().Named("dom-discoverer")
	cdpCtx := session.GetContext()
	if cdpCtx == nil {
		return nil, fmt.Errorf("session does not provide a valid CDP context")
	}

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
			var result bool
			// Execute the JavaScript evaluation.
			if err := chromedp.Run(cdpCtx, chromedp.Evaluate(check, &result)); err != nil {
				// Log errors instead of ignoring them.
				logger.Debug("Error evaluating JS for tech check", zap.String("tech", name), zap.Error(err))
				return
			}
			if result {
				techSet.Store(name, true)
			}
		}()
	}

	// -- 2. Get all script tags once --
	var nodes []*cdp.Node
	if err := chromedp.Run(cdpCtx, chromedp.Nodes(`script[src]`, &nodes, chromedp.ByQueryAll)); err != nil {
		// If we can't get script nodes, we can't check them, but we should still wait for JS checks.
		logger.Warn("Could not retrieve script nodes for technology discovery", zap.Error(err))
	} else {
		// -- 3. Concurrently check script sources (simple iteration is fast enough here) --
		for _, node := range nodes {
			src := node.AttributeValue("src")
			for techName, method := range technologyChecks {
				if method.srcCheck != "" && strings.Contains(src, method.srcCheck) {
					techSet.Store(techName, true)
					// Found one, no need to check this src for other techs if they share keywords.
					// For more complex cases, you might remove this `break`.
					break
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