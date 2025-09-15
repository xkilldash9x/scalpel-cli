// internal/discovery/engine.go
package discovery

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// FIX: Removed the incorrect 'scope' package import as the interface is now local.
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	// NOTE: EventBus dependency has been fully removed from the engine.
)

// FIX: Added the ScopeManager interface definition here.
// This allows engine.go and other files in the 'discovery' package to use it without circular dependencies.
type ScopeManager interface {
	IsInScope(u *url.URL) bool
	GetRootDomain() string
}

// Engine orchestrates the discovery process (passive and active crawling).
type Engine struct {
	config        Config
	// FIX: Use the specific interface types from their new packages or defined in this package.
	scope         ScopeManager
	kg            knowledgegraph.KnowledgeGraph
	browser       browser.BrowserInteractor
	passiveRunner *PassiveRunner
	logger        *zap.Logger

	// state management for the active crawl
	queue         chan crawlTask
	processedUrls sync.Map
	taskWG        sync.WaitGroup
	activeWorkers int32
	sessionID     string
}

// Package level definition for ignored extensions
var ignoredExtensions = map[string]struct{}{
	".css": {}, ".png": {}, ".jpg": {}, ".jpeg": {}, ".gif": {},
	".woff": {}, ".woff2": {}, ".ico": {}, ".svg": {}, ".ttf": {}, ".eot": {},
}

// NewEngine creates a new Discovery Engine instance.
func NewEngine(
	cfg Config,
	// FIX: Updated the function signature to use the correct local interface type.
	scope ScopeManager,
	kg knowledgegraph.KnowledgeGraph,
	browser browser.BrowserInteractor,
	passive *PassiveRunner,
	logger *zap.Logger,
) *Engine {
	cfg.SetDefaults()

	if logger == nil {
		logger = zap.NewNop()
	}

	return &Engine{
		config:        cfg,
		scope:         scope,
		kg:            kg,
		browser:       browser,
		passiveRunner: passive,
		logger:        logger.Named("DiscoveryEngine"),
		// initialize the queue with a large buffer to handle bursts of discovered links without blocking.
		queue: make(chan crawlTask, 5000),
	}
}

// Run starts the reconnaissance process. blocks until all discovery is complete.
func (e *Engine) Run(ctx context.Context, initialURL string) error {
	e.sessionID = uuid.New().String()
	// Use a session-specific logger
	log := e.logger.With(zap.String("sessionID", e.sessionID))
	log.Info("Starting discovery session", zap.String("target", initialURL), zap.Int("maxDepth", e.config.MaxDepth))

	// 1. normalize and validate initial URL
	parsedInitialURL, err := e.normalizeAndValidate(initialURL, "")
	if err != nil {
		return fmt.Errorf("invalid initial URL: %w", err)
	}

	// 2. initialize Knowledge Graph with the root asset.
	rootDomain := e.scope.GetRootDomain()
	if _, err := e.kg.AddNode(ctx, rootDomain, schemas.NodeDomain, map[string]interface{}{"source": "seed"}); err != nil {
		log.Warn("Failed to add root domain to Knowledge Graph", zap.Error(err))
	}

	// 3. start the worker pool
	workerWG := &sync.WaitGroup{}
	// create a derived context for the session. handles graceful shutdown if the main context ends.
	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	for i := 0; i < e.config.Concurrency; i++ {
		workerWG.Add(1)
		go e.worker(sessionCtx, workerWG)
	}

	// 4. passive Discovery Phase
	// ensure we check the pointer value correctly before dereferencing.
	if e.config.PassiveEnabled != nil && *e.config.PassiveEnabled && e.passiveRunner != nil {
		log.Info("Launching passive discovery...")
		// run passive discovery and process results asynchronously.
		go func() {
			passiveResults := e.passiveRunner.Run(sessionCtx, parsedInitialURL, e.scope)
			count := 0
			for resultURL := range passiveResults {
				// normalize, validate, and process each passive result.
				if parsedResult, err := e.normalizeAndValidate(resultURL, ""); err == nil {
					// depth 0 for initial passive results.
					e.processAsset(sessionCtx, parsedResult, 0, "PassiveDiscovery")
					count++
				} else {
					// trace level logging (Debug in Zap) for discarded links keeps the main log clean
					log.Debug("Discarding invalid passive result", zap.Error(err), zap.String("url", resultURL))
				}
			}
			log.Info("Passive discovery processing complete", zap.Int("count", count))
		}()
	} else {
		log.Info("Passive discovery disabled or not configured.")
	}

	// 5. enqueue the initial URL (Active Crawl Start Point)
	e.processAsset(sessionCtx, parsedInitialURL, 0, "Seed")

	// 6. wait for completion
	// wait until taskWG hits zero (queue is empty and all in flight tasks are done).
	e.taskWG.Wait()

	// 7. shutdown
	// signal workers to stop by closing the queue.
	close(e.queue)

	// wait for all workers to gracefully shut down.
	workerWG.Wait()

	log.Info("Discovery session finished")
	// The event bus call for RECON_FINISHED has been removed.
	return nil
}

// worker is the concurrent function that processes tasks from the queue.
func (e *Engine) worker(ctx context.Context, workerWG *sync.WaitGroup) {
	defer workerWG.Done()

	for {
		select {
		case task, ok := <-e.queue:
			if !ok {
				return // queue closed, worker exits.
			}

			// mark worker as active for monitoring.
			atomic.AddInt32(&e.activeWorkers, 1)

			// process the task. using an anonymous function for cleaner defer handling.
			func() {
				defer func() {
					if r := recover(); r != nil {
						e.logger.Error("Crawl task panicked",
							zap.String("url", task.URL),
							zap.Any("panicValue", r),
							zap.String("stack", string(debug.Stack())),
						)
					}
				}()
				// ensure taskWG is decremented when processing is finished. crucial.
				defer e.taskWG.Done()
				// ensure worker is marked as inactive when finished.
				defer atomic.AddInt32(&e.activeWorkers, -1)

				// resilience: apply timeout to individual crawl operations. don't let one slow page hang the system.
				crawlCtx, cancel := context.WithTimeout(ctx, e.config.Timeout)
				defer cancel()

				e.crawlPage(crawlCtx, task)
			}()

		case <-ctx.Done():
			// context cancelled (e.g., global timeout or interrupt).
			e.logger.Warn("Worker shutting down due to context cancellation")
			return
		}
	}
}

// crawlPage performs the active crawling of a single URL using the BrowserInteractor.
func (e *Engine) crawlPage(ctx context.Context, task crawlTask) {
	// note: depth check is handled during enqueue in processAsset. if a task is here, it's within depth limits.

	log := e.logger.With(zap.String("url", task.URL), zap.Int("depth", task.Depth))
	log.Debug("Actively crawling page") // reduced to debug, info is too noisy for every page crawl

	// use the injected browser interactor. this leverages the humanoid and stealth capabilities we built.
	links, err := e.browser.NavigateAndExtract(ctx, task.URL)
	if err != nil {
		// errors during navigation/extraction are non critical. just log and move on.
		log.Warn("Error during active crawl", zap.Error(err))
		return
	}

	log.Debug("Extracted links", zap.Int("linkCount", len(links)))

	// process discovered links.
	nextDepth := task.Depth + 1
	for _, link := range links {
		parsedLink, err := e.normalizeAndValidate(link, task.URL)
		if err != nil {
			log.Debug("Discarding link", zap.Error(err), zap.String("link", link))
			continue
		}
		// process the discovered link (deduplicate, report, and enqueue if applicable).
		e.processAsset(ctx, parsedLink, nextDepth, "Crawler")
	}
}

// processAsset handles deduplication, reporting, and enqueueing of a discovered URL.
func (e *Engine) processAsset(ctx context.Context, u *url.URL, depth int, source string) {
	urlString := u.String()

	// 1. deduplication (thread safe check using sync.Map)
	// if the URL was already processed (loaded=true), return immediately. efficiency matters.
	if _, loaded := e.processedUrls.LoadOrStore(urlString, true); loaded {
		return
	}

	// total observability: log the discovery of a new, unique asset.
	e.logger.Info("New asset discovered",
		zap.String("url", urlString),
		zap.Int("depth", depth),
		zap.String("source", source))

	// 2. report the asset to the KnowledgeGraph
	// 2a. add to Knowledge Graph
	if _, err := e.kg.AddNode(ctx, urlString, schemas.NodeURL, map[string]interface{}{
		"depth":     depth,
		"source":    source,
		"sessionID": e.sessionID,
	}); err != nil {
		e.logger.Warn("Failed to add URL node to KG", zap.Error(err), zap.String("url", urlString))
	}

	// handle Domain/Subdomain relationships
	hostname := u.Hostname()
	// attempt to add the hostname as a domain node. the KG implementation handles duplicates.
	if _, err := e.kg.AddNode(ctx, hostname, schemas.NodeDomain, map[string]interface{}{"source": source}); err != nil {
		e.logger.Warn("Failed to add/update Domain node in KG", zap.Error(err), zap.String("hostname", hostname))
	}

	// create the relationship between the specific domain/subdomain and the URL
	if err := e.kg.AddRelationship(ctx, hostname, urlString, schemas.RelationshipHostsURL, map[string]interface{}{"source": source}); err != nil {
		e.logger.Warn("Failed to add HostsURL relationship in KG", zap.Error(err), zap.String("from", hostname), zap.String("to", urlString))
	}

	// if this is a subdomain, ensure the relationship to the root domain is captured.
	rootDomain := e.scope.GetRootDomain()
	if hostname != rootDomain {
		if err := e.kg.AddRelationship(ctx, rootDomain, hostname, schemas.RelationshipHasSubdomain, map[string]interface{}{"source": source, "confidence": 1.0}); err != nil {
			e.logger.Warn("Failed to add HasSubdomain relationship in KG", zap.Error(err), zap.String("from", rootDomain), zap.String("to", hostname))
		}
	}

	// 2b. The event bus publish call for ASSET_DISCOVERED has been removed. Other modules will need to query the Knowledge Graph.

	// 3. enqueue for Active Crawling
	// we only enqueue if the current depth is less than the maximum allowed depth.
	if depth < e.config.MaxDepth {
		e.taskWG.Add(1) // CRITICAL: increment the WG before adding to the channel.
		// non blocking send to the queue.
		select {
		case e.queue <- crawlTask{URL: urlString, Depth: depth}:
			// success
		default:
			// resilience: handle full queue. this shouldn't happen if the buffer is sized right, but we plan for failure.
			e.logger.Error("Discovery queue is full, dropping task. Increase buffer size or concurrency.")
			e.taskWG.Done() // decrement WG as the task was dropped.
		}
	}
}

// normalizeAndValidate cleans the URL, resolves relative paths, checks the scope, and normalizes the format.
// this function must be bulletproof.
func (e *Engine) normalizeAndValidate(rawURL, baseURL string) (*url.URL, error) {
	// 1. parse the raw URL.
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	// 2. resolve relative URLs
	if !u.IsAbs() {
		if baseURL == "" {
			// cannot resolve relative URL without a base (e.g. from passive discovery)
			// if the host is present but the scheme is missing (e.g. //example.com/path), try adding https as a sensible default.
			if u.Host != "" && u.Scheme == "" {
				u.Scheme = "https"
			} else if u.Host == "" {
				// truly relative path (e.g. /api/v1) without a base URL provided
				return nil, fmt.Errorf("relative URL without base: %s", rawURL)
			}
		} else {
			base, err := url.Parse(baseURL)
			if err != nil {
				// should not happen if baseURL came from a successful crawl.
				return nil, fmt.Errorf("invalid base URL provided: %w", err)
			}
			u = base.ResolveReference(u)
		}
	}

	// 3. basic normalization: remove fragments. they don't typically change server side behavior.
	u.Fragment = ""

	// 4. check scheme (we only handle http/https).
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	// 5. check scope. critical boundary control.
	if !e.scope.IsInScope(u) {
		return nil, fmt.Errorf("out of scope: %s", u.String())
	}

	// 6. further normalization: standardize port if default.
	host := u.Host
	// clean up :80 for http and :443 for https
	if (u.Scheme == "http" && strings.HasSuffix(host, ":80")) || (u.Scheme == "https" && strings.HasSuffix(host, ":443")) {
		// use Hostname() to correctly get the host without the port (handles ipv6 literals), then reassign Host
		u.Host = u.Hostname()
	}

	// ensure path is set to "/" if empty.
	if u.Path == "" {
		u.Path = "/"
	}

	// 7. IMPROVEMENT: Sort query parameters for canonicalization.
	// This prevents crawling the same page twice if parameters are reordered.
	if u.RawQuery != "" {
		// url.Values.Encode() automatically sorts the parameters by key.
		u.RawQuery = u.Query().Encode()
	}

	// 8. optimization: filter common static assets not typically useful for analysis. reduces noise.
	// Use filepath.Ext to correctly extract the extension (includes the dot) and convert to lower case.
	ext := strings.ToLower(filepath.Ext(u.Path))
	if _, ignore := ignoredExtensions[ext]; ignore {
		// CRITICAL: Ensure .js is not in the ignoredExtensions map.
		return nil, fmt.Errorf("static asset ignored")
	}

	return u, nil
}
