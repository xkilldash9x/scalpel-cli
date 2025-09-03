// pkg/browser/cdp/discovery.go
package cdp

import (
	"context"
	"strings"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/pkg/discovery"
)

// DOMTechnologyDiscoverer uses CDP to identify technologies on a page.
type DOMTechnologyDiscoverer struct{}

func NewDOMTechnologyDiscoverer() *DOMTechnologyDiscoverer {
	return &DOMTechnologyDiscoverer{}
}

// Discover now operates on an existing session, which is way more efficient.
// No point spinning up a whole new browser just for this.
func (d *DOMTechnologyDiscoverer) Discover(ctx context.Context, s *Session) ([]discovery.Technology, error) {
	var technologies []discovery.Technology
	techSet := make(map[string]bool)

	runCtx, cancel := s.combineContexts(ctx)
	defer cancel()

	// Helper function to add a technology only once.
	addTech := func(name string) {
		if !techSet[name] {
			technologies = append(technologies, discovery.Technology{Name: name})
			techSet[name] = true
		}
	}

	// we can discover a lot just by checking for global variables.
	discoveries := map[string]string{
		"jQuery":  "typeof window.jQuery !== 'undefined'",
		"React":   "typeof window.React !== 'undefined' || document.querySelector('[data-reactroot]') !== null",
		"Angular": "typeof window.angular !== 'undefined' || document.querySelector('.ng-scope') !== null",
		"Vue.js":  "typeof window.Vue !== 'undefined' || document.querySelector('[data-v-app]') !== null",
	}

	for tech, script := range discoveries {
		var result bool
		if err := chromedp.Run(runCtx, chromedp.Evaluate(script, &result)); err == nil && result {
			addTech(tech)
		}
	}

	// also check script tags, sometimes the global isn't exposed.
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
