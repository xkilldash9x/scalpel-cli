// pkg/browser/cdp/discovery.go
package cdp

import (
	"context"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/discovery"
)

// DOMTechnologyDiscoverer uses CDP to identify technologies on a page.
type DOMTechnologyDiscoverer struct{}

func NewDOMTechnologyDiscoverer() *DOMTechnologyDiscoverer {
	return &DOMTechnologyDiscoverer{}
}

// Discover operates on an existing browser session for efficiency.
func (d *DOMTechnologyDiscoverer) Discover(ctx context.Context, session browser.SessionContext) ([]discovery.Technology, error) {
	var technologies []discovery.Technology
	techSet := make(map[string]bool)

	// Get the underlying chromedp context.
	sessionCtx := session.GetContext()

	// Create a derived context that respects the deadline of the incoming context (ctx),
	// while retaining the chromedp executor from the sessionCtx.
	runCtx, cancel := chromedp.NewContext(sessionCtx, chromedp.WithTaskContext(ctx))
	defer cancel()

	// Helper function to add a technology only once.
	addTech := func(name string) {
		if !techSet[name] {
			technologies = append(technologies, discovery.Technology{Name: name})
			techSet[name] = true
		}
	}

	// Combine all checks into a single script for one CDP round trip.
	discoveries := map[string]string{
		"jQuery":  "typeof window.jQuery !== 'undefined'",
		"React":   "typeof window.React !== 'undefined' || document.querySelector('[data-reactroot]') !== null",
		"Angular": "typeof window.angular !== 'undefined' || document.querySelector('.ng-scope') !== null",
		"Vue.js":  "typeof window.Vue !== 'undefined' || document.querySelector('[data-v-app]') !== null",
	}

	var script strings.Builder
	script.WriteString("(() => { const results = {};")
	for tech, check := range discoveries {
		fmt.Fprintf(&script, "try { results['%s'] = !!(%s); } catch(e) { results['%s'] = false; }", tech, check, tech)
	}
	script.WriteString("return results; })()")

	var results map[string]bool
	if err := chromedp.Run(runCtx, chromedp.Evaluate(script.String(), &results)); err == nil {
		for tech, found := range results {
			if found {
				addTech(tech)
			}
		}
	}

	// Check script tags as a fallback.
	var nodes []*cdp.Node
	if err := chromedp.Run(runCtx, chromedp.Nodes(`script[src]`, &nodes, chromedp.ByQueryAll)); err == nil {
		for _, node := range nodes {
			src := node.AttributeValue("src")
			if strings.Contains(src, "jquery") {
				addTech("jQuery")
			}
			if strings.Contains(src, "react") {
				addTech("React")
			}
			if strings.Contains(src, "angular") {
				addTech("Angular")
			}
			if strings.Contains(src, "vue") {
				addTech("Vue.js")
			}
		}
	}

	return technologies, nil
}