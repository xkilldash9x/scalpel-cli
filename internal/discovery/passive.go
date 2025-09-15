// internal/discovery/passive.go
package discovery

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"

	// The 'scope' package import has been removed as ScopeManager is now defined in this package.
	"github.com/xkilldash9x/scalpel-cli/internal/network"
)

// PassiveRunner handles passive discovery techniques. These are designed to be less noisy
// and yield high value intelligence without directly engaging the target in an aggressive manner.
type PassiveRunner struct {
	config      Config
	httpClient  network.HTTPClient
	// Use the ScopeManager interface now defined locally within the discovery package.
	scope       ScopeManager
	logger      *zap.Logger
	// resilience: rate limiter for external services. gotta be a good net citizen.
	crtLimiter  *rate.Limiter
	// A semaphore to limit concurrent outbound HTTP requests for things like sitemaps.
	httpLimiter chan struct{}
}

// NewPassiveRunner creates a new PassiveRunner.
// The signature is updated to use the local ScopeManager interface.
func NewPassiveRunner(cfg Config, client network.HTTPClient, scope ScopeManager, logger *zap.Logger) *PassiveRunner {
	// Ensure defaults are applied if this runner is initialized independently.
	cfg.SetDefaults()

	if logger == nil {
		logger = zap.NewNop()
	}

	// Set a reasonable default for passive concurrency if not configured.
	passiveConcurrency := 10
	if cfg.PassiveConcurrency > 0 {
		passiveConcurrency = cfg.PassiveConcurrency
	}

	return &PassiveRunner{
		config:      cfg,
		httpClient:  client,
		scope:       scope,
		logger:      logger.Named("DiscoveryPassive"),
		// Setting the rate limit for crt.sh based on the configuration.
		crtLimiter:  rate.NewLimiter(rate.Limit(cfg.CrtShRateLimit), 1),
		httpLimiter: make(chan struct{}, passiveConcurrency),
	}
}

// Run executes passive discovery methods and returns a channel of discovered URL strings.
func (p *PassiveRunner) Run(ctx context.Context, initialURL *url.URL) <-chan string {
	resultsChan := make(chan string, 1000)
	var wg sync.WaitGroup

	// 1. Certificate transparency logs (crt.sh).
	rootDomain := p.scope.GetRootDomain()
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.checkCrtSh(ctx, rootDomain, resultsChan)
	}()

	// 2. robots.txt and sitemaps.
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.checkRobotsAndSitemaps(ctx, initialURL, resultsChan)
	}()

	// This goroutine waits for all passive checks to complete, then closes the channel.
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	return resultsChan
}

// -- Certificate Transparency (crt.sh) Implementation --

// CrtShEntry defines the structure for a single JSON entry from the crt.sh API.
type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

// CrtCache defines the structure for storing crt.sh results locally.
type CrtCache struct {
	RootDomain string    `json:"rootDomain"`
	Timestamp  time.Time `json:"timestamp"`
	Domains    []string  `json:"domains"`
}

// checkCrtSh queries crt.sh for subdomains of a given domain.
func (p *PassiveRunner) checkCrtSh(ctx context.Context, domain string, resultsChan chan<- string) {
	if domains, ok := p.loadCrtCache(domain); ok {
		p.logger.Info("Using cached CT log data.", zap.String("domain", domain), zap.Int("count", len(domains)))
		for _, d := range domains {
			resultsChan <- "https://" + d
		}
		return
	}

	p.logger.Info("Querying Certificate Transparency logs (crt.sh)", zap.String("domain", domain))

	if err := p.crtLimiter.Wait(ctx); err != nil {
		p.logger.Warn("Context cancelled while waiting for rate limiter (crt.sh)", zap.Error(err))
		return
	}

	queryURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	body, status, err := p.httpClient.Get(ctx, queryURL)
	if err != nil || status != http.StatusOK {
		p.logger.Warn("Failed to fetch CT logs from crt.sh", zap.Error(err), zap.Int("status", status))
		return
	}

	var entries []CrtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		p.logger.Warn("Failed to parse crt.sh JSON response.", zap.Error(err))
		return
	}

	foundDomains := make(map[string]bool)
	for _, entry := range entries {
		domains := strings.Split(entry.NameValue, "\n")
		for _, d := range domains {
			cleanDomain := strings.TrimPrefix(d, "*.")
			if strings.Contains(cleanDomain, ".") && strings.HasSuffix(cleanDomain, domain) {
				foundDomains[cleanDomain] = true
			}
		}
	}

	var domainList []string
	for d := range foundDomains {
		resultsChan <- "https://" + d
		domainList = append(domainList, d)
	}
	p.logger.Info("Finished processing CT logs", zap.Int("count", len(domainList)))

	p.saveCrtCache(domain, domainList)
}

// -- Cache Helpers --

// getCachePath generates a domain specific cache file path.
func (p *PassiveRunner) getCachePath(domain string) string {
	sanitizedDomain := strings.ReplaceAll(domain, ".", "_")
	return filepath.Join(p.config.CacheDir, fmt.Sprintf("crt_cache_%s.json", sanitizedDomain))
}

// loadCrtCache attempts to load and validate a cache file for a given domain.
func (p *PassiveRunner) loadCrtCache(domain string) ([]string, bool) {
	cachePath := p.getCachePath(domain)
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false
	}

	var cache CrtCache
	if err := json.Unmarshal(data, &cache); err != nil {
		p.logger.Warn("Cache file corrupted, it will be ignored.", zap.Error(err), zap.String("path", cachePath))
		return nil, false
	}

	if cache.RootDomain == domain && time.Since(cache.Timestamp) < 24*time.Hour {
		return cache.Domains, true
	}

	return nil, false
}

// saveCrtCache writes a list of domains to the cache for a specific root domain.
func (p *PassiveRunner) saveCrtCache(domain string, domains []string) {
	if err := os.MkdirAll(p.config.CacheDir, 0755); err != nil {
		p.logger.Warn("Could not create cache directory", zap.Error(err))
		return
	}

	cache := CrtCache{RootDomain: domain, Timestamp: time.Now(), Domains: domains}
	data, err := json.Marshal(cache)
	if err != nil {
		p.logger.Error("Failed to marshal cache data to JSON. Cache not saved.", zap.Error(err), zap.String("domain", domain))
		return
	}

	if err := os.WriteFile(p.getCachePath(domain), data, 0644); err != nil {
		p.logger.Warn("Could not write cache file", zap.Error(err))
	}
}

// -- Robots.txt and Sitemap Implementation --

// checkRobotsAndSitemaps fetches and parses robots.txt to find sitemaps and disallowed paths.
func (p *PassiveRunner) checkRobotsAndSitemaps(ctx context.Context, targetURL *url.URL, resultsChan chan<- string) {
	baseURL := targetURL.Scheme + "://" + targetURL.Host
	robotsURL := baseURL + "/robots.txt"
	sitemaps := []string{baseURL + "/sitemap.xml"}

	body, status, err := p.httpClient.Get(ctx, robotsURL)
	if err == nil && status == http.StatusOK {
		p.logger.Info("Found robots.txt, parsing...", zap.String("url", robotsURL))
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") || line == "" {
				continue
			}

			lowerLine := strings.ToLower(line)

			if strings.HasPrefix(lowerLine, "sitemap:") {
				sitemapURL := strings.TrimSpace(line[8:])
				if sitemapURL != "" {
					sitemaps = append(sitemaps, sitemapURL)
				}
			} else if strings.HasPrefix(lowerLine, "disallow:") || strings.HasPrefix(lowerLine, "allow:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					path := strings.TrimSpace(parts[1])
					if strings.HasPrefix(path, "/") {
						path = strings.Split(path, "*")[0]
						path = strings.Split(path, "?")[0]

						if len(path) > 1 {
							resultsChan <- baseURL + path
						}
					}
				}
			}
		}
	} else {
		p.logger.Debug("robots.txt not found or inaccessible", zap.String("url", robotsURL))
	}

	var wg sync.WaitGroup
	uniqueSitemaps := make(map[string]bool)
	for _, s := range sitemaps {
		uniqueSitemaps[s] = true
	}

	for sitemapURL := range uniqueSitemaps {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			p.parseSitemap(ctx, url, resultsChan)
		}(sitemapURL)
	}
	wg.Wait()
}

// -- XML Structures for Sitemap parsing --
type SitemapIndex struct {
	XMLName  xml.Name     `xml:"sitemapindex"`
	Sitemaps []SitemapRef `xml:"sitemap"`
}
type SitemapRef struct {
	Loc string `xml:"loc"`
}
type URLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []URLLoc `xml:"url"`
}
type URLLoc struct {
	Loc string `xml:"loc"`
}

// parseSitemap recursively handles sitemap indexes and standard sitemaps.
func (p *PassiveRunner) parseSitemap(ctx context.Context, sitemapURL string, resultsChan chan<- string) {
	p.logger.Debug("Parsing sitemap", zap.String("url", sitemapURL))

	select {
	case p.httpLimiter <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-p.httpLimiter }()

	body, status, err := p.httpClient.Get(ctx, sitemapURL)
	if err != nil || status != http.StatusOK {
		p.logger.Debug("Failed to fetch sitemap", zap.String("url", sitemapURL), zap.Error(err))
		return
	}

	var sitemapIndex SitemapIndex
	errIndex := xml.Unmarshal(body, &sitemapIndex)

	if errIndex == nil && sitemapIndex.XMLName.Local == "sitemapindex" && len(sitemapIndex.Sitemaps) > 0 {
		p.logger.Debug("Found sitemap index, processing nested sitemaps", zap.Int("count", len(sitemapIndex.Sitemaps)))
		var wg sync.WaitGroup
		for _, ref := range sitemapIndex.Sitemaps {
			if ref.Loc != "" {
				parsedLoc, err := url.Parse(ref.Loc)
				if err != nil {
					p.logger.Debug("Invalid nested sitemap URL", zap.String("url", ref.Loc), zap.Error(err))
					continue
				}
				if !p.scope.IsInScope(parsedLoc) {
					p.logger.Debug("Nested sitemap URL out of scope, skipping.", zap.String("url", ref.Loc))
					continue
				}

				wg.Add(1)
				go func(url string) {
					defer wg.Done()
					p.parseSitemap(ctx, url, resultsChan) // Recursive call
				}(ref.Loc)
			}
		}
		wg.Wait()
		return
	}

	var urlSet URLSet
	errSet := xml.Unmarshal(body, &urlSet)

	if errSet == nil && urlSet.XMLName.Local == "urlset" && len(urlSet.URLs) > 0 {
		p.logger.Debug("Found URL set", zap.Int("count", len(urlSet.URLs)))
		for _, u := range urlSet.URLs {
			if u.Loc != "" {
				resultsChan <- u.Loc
			}
		}
		return
	}

	p.logger.Debug("Could not parse sitemap format (not index or urlset)", zap.String("url", sitemapURL))
}

// min is a helper function to find the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
