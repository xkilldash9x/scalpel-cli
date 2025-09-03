// pkg/discovery/discover_dom.go
package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
)

// DOMTechnologyDiscoverer uses CDP to identify technologies on a page.
// This component was moved from the browser package to break an import cycle.
type DOMTechnologyDiscoverer struct{}

// NewDOMTechnologyDiscoverer creates a new DOMTechnologyDiscoverer.
func NewDOMTechnologyDiscoverer() *DOMTechnologyDiscoverer {
	return &DOMTechnologyDiscoverer{}
}

// Discover now operates on a browser.SessionContext, making it implementation-agnostic at the interface level.
func (d *DOMTechnologyDiscoverer) Discover(ctx context.Context, session browser.SessionContext) ([]Technology, error) {
	// Get the underlying chromedp context from the session interface.
	// This allows us to use chromedp-specific commands while keeping the dependency direction correct.
	cdpCtx := session.GetContext()
	if cdpCtx == nil {
		return nil, fmt.Errorf("session does not provide a valid CDP context")
	}

	var technologies []Technology
	techSet := make(map[string]bool)

	// Helper function to add a technology only once.
	addTech := func(name string) {
		if !techSet[name] {
			technologies = append(technologies, Technology{Name: name})
			techSet[name] = true
		}
	}

	// Discover technologies by checking for global JavaScript variables.
	discoveries := map[string]string{
		"jQuery":  "typeof window.jQuery !== 'undefined'",
		"React":   "typeof window.React !== 'undefined' || document.querySelector('[data-reactroot]') !== null",
		"Angular": "typeof window.angular !== 'undefined' || document.querySelector('.ng-scope') !== null",
		"Vue.js":  "typeof window.Vue !== 'undefined' || document.querySelector('[data-v-app]') !== null",
	}

	for tech, script := range discoveries {
		var result bool
		if err := chromedp.Run(cdpCtx, chromedp.Evaluate(script, &result)); err == nil && result {
			addTech(tech)
		}
	}

	// Also check script tags for further evidence.
	var nodes []*cdp.Node
	if err := chromedp.Run(cdpCtx, chromedp.Nodes(`script[src]`, &nodes, chromedp.ByQueryAll)); err == nil {
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
