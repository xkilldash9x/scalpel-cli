// internal/discovery/scope.go
package discovery

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// BasicScopeManager implements the interfaces.ScopeManager interface.
// this defines the boundaries of the engagement. absolutely critical.
type BasicScopeManager struct {
	rootDomain        string
	includeSubdomains bool
	// potentially add explicit inclusions/exclusions lists later
}

// NewBasicScopeManager initializes a scope based on the initial target URL.
func NewBasicScopeManager(initialURL string, includeSubdomains bool) (*BasicScopeManager, error) {
	u, err := url.Parse(initialURL)
	if err != nil {
		return nil, err
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("initial URL must have a hostname: %s", initialURL)
	}

	// use the Public Suffix List to accurately extract the eTLD+1 (the organizational domain).
	// this correctly handles domains like 'example.co.uk' and 'sub.example.com'. don't roll your own domain parser.
	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return nil, fmt.Errorf("could not determine effective TLD+1 for %s: %w", hostname, err)
	}

	return &BasicScopeManager{
		rootDomain:        domain,
		includeSubdomains: includeSubdomains,
	}, nil
}

// IsInScope checks if the URL belongs to the target domain or its subdomains (if configured).
func (s *BasicScopeManager) IsInScope(u *url.URL) bool {
	host := u.Hostname()

	// direct match
	if host == s.rootDomain {
		return true
	}

	// check if it's a subdomain.
	// ensure it ends with a dot followed by the root domain to prevent matching domains like "notourdomain.com"
	if s.includeSubdomains && strings.HasSuffix(host, "."+s.rootDomain) {
		return true
	}

	// if we're here, it's out of scope.
	return false
}

// GetRootDomain returns the eTLD+1 defining the scope.
func (s *BasicScopeManager) GetRootDomain() string {
	return s.rootDomain
}
