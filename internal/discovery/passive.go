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

	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)

// PassiveRunner handles passive discovery techniques. less noise, high value intel.
type PassiveRunner struct {
	config     Config
	httpClient interfaces.HTTPClient
	scope      interfaces.ScopeManager // Add scope manager
	logger     *zap.Logger
	// resilience: rate limiter for external services. gotta be a good net citizen.
	crtLimiter *rate.Limiter
	httpLimiter chan struct{} // Add concurrency limiter
}

// NewPassiveRunner creates a new PassiveRunner.
// Updated to accept *zap.Logger and the scope manager.
func NewPassiveRunner(cfg Config, client interfaces.HTTPClient, scope interfaces.ScopeManager, logger *zap.Logger) *PassiveRunner {
	// ensure defaults are applied if this runner is initialized independently
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
		config:     cfg,
		httpClient: client,
		scope:      scope,
		logger:     logger.Named("DiscoveryPassive"),
		// setting the rate limit based on config
		crtLimiter: rate.NewLimiter(rate.Limit(cfg.CrtShRateLimit), 1),
		httpLimiter: make(chan struct{}, passiveConcurrency),
	}
}

// Run executes passive discovery methods. returns a channel for discovered URLs.
func (p *PassiveRunner) Run(ctx context.Context, initialURL *url.URL, scope interfaces.ScopeManager) <-chan string {
	resultsChan := make(chan string, 1000) // increased buffer for passive results
	var wg sync.WaitGroup

	// 1. certificate transparency logs (crt.sh)
	// we use the root domain for CT logs
	rootDomain := scope.GetRootDomain()
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.checkCrtSh(ctx, rootDomain, resultsChan)
	}()

	// 2. robots.txt and sitemaps
	// these are specific to the initial host
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.checkRobotsAndSitemaps(ctx, initialURL, resultsChan)
	}()

	// maybe add wayback machine, commoncrawl etc later.

	// close the channel when all passive checks are complete.
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	return resultsChan
}

// --- Certificate Transparency (crt.sh) Implementation ---

type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

// CrtCache structure for local storage
type CrtCache struct {
	RootDomain string    `json:"rootDomain"`
	Timestamp  time.Time `json:"timestamp"`
	Domains    []string  `json:"domains"`
}

func (p *PassiveRunner) checkCrtSh(ctx context.Context, domain string, resultsChan chan<- string) {
	// 1. check cache first. optimization.
	if domains, ok := p.loadCrtCache(domain); ok {
		p.logger.Info("Using cached CT log data.", zap.String("domain", domain), zap.Int("count", len(domains)))
		for _, d := range domains {
			// default to https for domains found via CT logs
			resultsChan <- "https://" + d
		}
		return
	}

	// 2. fetch fresh data
	p.logger.Info("Querying Certificate Transparency logs (crt.sh)", zap.String("domain", domain))

	// resilience: wait for the rate limiter.
	if err := p.crtLimiter.Wait(ctx); err != nil {
		p.logger.Warn("Context cancelled while waiting for rate limiter (crt.sh)", zap.Error(err))
		return
	}

	queryURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	// using our centralized http client for consistency and resilience
	body, status, err := p.httpClient.Get(ctx, queryURL)
	if err != nil || status != http.StatusOK {
		p.logger.Warn("Failed to fetch CT logs from crt.sh", zap.Error(err), zap.Int("status", status))
		return
	}

	var entries []CrtShEntry
	// crt.sh usually returns a JSON array.
	if err := json.Unmarshal(body, &entries); err != nil {
		p.logger.Warn("Failed to parse crt.sh JSON response.", zap.Error(err))
		return
	}

	foundDomains := make(map[string]bool)
	for _, entry := range entries {
		// the name_value can sometimes contain multiple domains separated by newline
		domains := strings.Split(entry.NameValue, "\n")
		for _, d := range domains {
			// clean up wildcard certs
			cleanDomain := strings.TrimPrefix(d, "*.")
			// basic validation: must contain a dot and match the root domain suffix
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

	// 3. save cache
	p.saveCrtCache(domain, domainList)
}

// Cache Helpers

// getCachePath generates a domain specific cache file path. crucial for multi target operations.
func (p *PassiveRunner) getCachePath(domain string) string {
	// sanitize the domain name for use in a filename
	sanitizedDomain := strings.ReplaceAll(domain, ".", "_")
	return filepath.Join(p.config.CacheDir, fmt.Sprintf("crt_cache_%s.json", sanitizedDomain))
}

func (p *PassiveRunner) loadCrtCache(domain string) ([]string, bool) {
	cachePath := p.getCachePath(domain)
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, false
	}
	var cache CrtCache
	if err := json.Unmarshal(data, &cache); err != nil {
		// corrupted cache file, remove it
		p.logger.Warn("Cache file corrupted, attempting to remove.", zap.Error(err), zap.String("path", cachePath))
		if removeErr := os.Remove(cachePath); removeErr != nil {
			p.logger.Error("Failed to remove corrupted cache file.", zap.Error(removeErr), zap.String("path", cachePath))
		}
		return nil, false
	}
	// check if cache is less than 24 hours old and matches the domain. standard operational window.
	if cache.RootDomain == domain && time.Since(cache.Timestamp) < 24*time.Hour {
		return cache.Domains, true
	}
	return nil, false
}

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

	// simple write is fine for cache data.
	if err := os.WriteFile(p.getCachePath(domain), data, 0644); err != nil {
		p.logger.Warn("Could not write cache file", zap.Error(err))
	}
}


// --- Robots.txt and Sitemap Implementation ---

func (p *PassiveRunner) checkRobotsAndSitemaps(ctx context.Context, targetURL *url.URL, resultsChan chan<- string) {
	baseURL := targetURL.Scheme + "://" + targetURL.Host
	robotsURL := baseURL + "/robots.txt"
	// start with the default sitemap location
	sitemaps := []string{baseURL + "/sitemap.xml"}

	// 1. parse robots.txt
	body, status, err := p.httpClient.Get(ctx, robotsURL)
	if err == nil && status == http.StatusOK {
		p.logger.Info("Found robots.txt, parsing...", zap.String("url", robotsURL))
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// ignore comments
			if strings.HasPrefix(line, "#") {
				continue
			}

			lowerLine := strings.ToLower(line)

			// look for sitemap directives
			if strings.HasPrefix(lowerLine, "sitemap:") {
				sitemapURL := strings.TrimSpace(line[8:])
				if sitemapURL != "" {
					sitemaps = append(sitemaps, sitemapURL)
				}
			} else if strings.HasPrefix(lowerLine, "disallow:") || strings.HasPrefix(lowerLine, "allow:") {
				// look for paths, often reveals hidden directories or admin areas
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					path := strings.TrimSpace(parts[1])
					if strings.HasPrefix(path, "/") {
						// remove wildcards and query params for basic path discovery
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

	// 2. parse Sitemaps (concurrently)
	var wg sync.WaitGroup
	// deduplicate sitemap list before processing
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

// XML Structures for Sitemap parsing
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

	// Acquire semaphore before making the HTTP request
	select {
	case p.httpLimiter <- struct{}{}:
		// Acquired
	case <-ctx.Done():
		return
	}
	// Ensure semaphore is released when done
	defer func() { <-p.httpLimiter }()


	body, status, err := p.httpClient.Get(ctx, sitemapURL)
	if err != nil || status != http.StatusOK {
		// non critical failure, just move on
		p.logger.Debug("Failed to fetch sitemap", zap.String("url", sitemapURL), zap.Error(err))
		return
	}

	// check if it's a Sitemap Index
	var sitemapIndex SitemapIndex
	errIndex := xml.Unmarshal(body, &sitemapIndex)

	// we check XMLName and Sitemaps length to be sure it's a valid index
	if errIndex == nil && sitemapIndex.XMLName.Local == "sitemapindex" && len(sitemapIndex.Sitemaps) > 0 {
		p.logger.Debug("Found sitemap index, processing nested sitemaps", zap.Int("count", len(sitemapIndex.Sitemaps)))
		var wg sync.WaitGroup
		for _, ref := range sitemapIndex.Sitemaps {
			if ref.Loc != "" {
				// SECURITY: Validate scope before recursive call
				parsedLoc, err := url.Parse(ref.Loc)
				if err != nil {
					p.logger.Debug("Invalid nested sitemap URL", zap.String("url", ref.Loc), zap.Error(err))
					continue
				}
				// Assumes p.scope is initialized
				if !p.scope.IsInScope(parsedLoc) {
					p.logger.Debug("Nested sitemap URL out of scope, skipping.", zap.String("url", ref.Loc))
					continue
				}

				wg.Add(1)
				go func(url string) {
					defer wg.Done()
					p.parseSitemap(ctx, url, resultsChan) // recursive call
				}(ref.Loc)
			}
		}
		wg.Wait()
		return
	}

	// check if it's a standard URL Set
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

	// if we reach here, it wasn't a recognizable sitemap format (or it was empty/invalid xml)
	p.logger.Debug("Could not parse sitemap format (not index or urlset)", zap.String("url", sitemapURL))
}