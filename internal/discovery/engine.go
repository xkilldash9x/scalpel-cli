// internal/discovery/engine.go
package discovery

import (
	"context"
	"encoding/json"
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
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// ScopeManager is an interface that defines the boundaries of the engagement.
type ScopeManager interface {
	IsInScope(u *url.URL) bool
	GetRootDomain() string
}

// crawlTask represents a URL to be crawled, including its depth.
type crawlTask struct {
	URL   string
	Depth int
}

// Engine orchestrates the discovery process (passive and active crawling).
type Engine struct {
	config        config.Interface
	scope         ScopeManager
	kg            schemas.KnowledgeGraphClient
	browser       schemas.BrowserInteractor
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
	cfg config.Interface,
	scope ScopeManager,
	kg schemas.KnowledgeGraphClient,
	browser schemas.BrowserInteractor,
	passive *PassiveRunner,
	logger *zap.Logger,
) *Engine {
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
		queue:         make(chan crawlTask, 5000),
	}
}

// Start kicks off the reconnaissance process.
// FIX: This method now implements the schemas.DiscoveryEngine interface.
// It returns a channel that streams discovered tasks and blocks until initial seeding is done.
func (e *Engine) Start(ctx context.Context, initialTargets []string) (<-chan schemas.Task, error) {
	e.sessionID = uuid.New().String()
	log := e.logger.With(zap.String("sessionID", e.sessionID))
	log.Info("Starting discovery session", zap.Strings("targets", initialTargets), zap.Int("maxDepth", e.config.Discovery().MaxDepth))

	if len(initialTargets) == 0 {
		return nil, fmt.Errorf("at least one initial target must be provided")
	}

	taskChan := make(chan schemas.Task, 100)

	// This context governs the entire discovery session, including all workers.
	sessionCtx, cancelSession := context.WithCancel(ctx)

	// This goroutine manages the lifecycle of the discovery process.
	go func() {
		defer close(taskChan)
		defer cancelSession() // Ensure session context is cancelled on exit
		defer log.Info("Discovery session finished")

		// --- Worker Pool Setup ---
		// This WaitGroup ensures we don't exit the main goroutine until all workers are done.
		workerWG := &sync.WaitGroup{}
		for i := 0; i < e.config.Discovery().Concurrency; i++ {
			workerWG.Add(1)
			go e.worker(sessionCtx, workerWG, taskChan)
		}

		// --- Seeding Phase ---
		// This WaitGroup tracks the completion of initial and passive seeding.
		seedingWG := &sync.WaitGroup{}

		// Process all initial targets.
		for _, targetURL := range initialTargets {
			parsedInitialURL, err := e.normalizeAndValidate(targetURL, "")
			if err != nil {
				log.Error("Invalid initial target URL, skipping", zap.String("url", targetURL), zap.Error(err))
				continue
			}
			// (KG seeding logic remains the same...)
			rootDomain := e.scope.GetRootDomain()
			if err := e.kg.AddNode(ctx, schemas.Node{ID: rootDomain, Type: schemas.NodeDomain, Label: rootDomain, Status: schemas.StatusNew}); err != nil {
				log.Warn("Failed to add root domain to KG", zap.Error(err))
			}

			// Start passive discovery in parallel.
			if e.config.Discovery().PassiveEnabled != nil && *e.config.Discovery().PassiveEnabled && e.passiveRunner != nil {
				log.Info("Launching passive discovery for target...", zap.String("target", targetURL))
				seedingWG.Add(1)
				go func(initialURL *url.URL) {
					defer seedingWG.Done()
					passiveResults := e.passiveRunner.Run(sessionCtx, initialURL)
					count := 0
					for resultURL := range passiveResults {
						if parsedResult, err := e.normalizeAndValidate(resultURL, ""); err == nil {
							// Each passive result is an asset to be processed.
							e.processAsset(sessionCtx, parsedResult, 0, "PassiveDiscovery", taskChan)
							count++
						}
					}
					log.Info("Passive discovery for target finished", zap.Int("count", count), zap.String("target", initialURL.String()))
				}(parsedInitialURL)
			}

			// Seed the active crawler with the initial target.
			e.processAsset(sessionCtx, parsedInitialURL, 0, "Seed", taskChan)
		}

		// --- Shutdown Orchestration ---
		// This is the critical change to fix the race condition.
		go func() {
			// 1. Wait for all initial seeds (including passive discovery) to be added to the queue.
			seedingWG.Wait()

			// 2. Wait for all active crawl tasks generated by those seeds (and their children) to complete.
			e.taskWG.Wait()

			// 3. Now it is safe to close the queue. No new tasks can be legally added.
			close(e.queue)
		}()

		// 4. Finally, wait for the worker pool to shut down. They will exit once the queue is closed and empty.
		workerWG.Wait()
	}()

	return taskChan, nil
}

func (e *Engine) Stop() {
	// The lifecycle is now managed by the context passed to Start().
	// A manual Stop method is less necessary but can be kept for explicit shutdown signaling if needed.
}

// worker is the concurrent function that processes tasks from the queue.
func (e *Engine) worker(ctx context.Context, workerWG *sync.WaitGroup, taskChan chan<- schemas.Task) {
	defer workerWG.Done()

	for {
		select {
		case task, ok := <-e.queue:
			if !ok {
				return
			}
			atomic.AddInt32(&e.activeWorkers, 1)
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
				defer e.taskWG.Done()
				defer atomic.AddInt32(&e.activeWorkers, -1)
				crawlCtx, cancel := context.WithTimeout(ctx, e.config.Discovery().Timeout)
				defer cancel()
				e.crawlPage(crawlCtx, task, taskChan)
			}()
		case <-ctx.Done():
			e.logger.Warn("Worker shutting down due to context cancellation")
			return
		}
	}
}

// crawlPage performs the active crawling of a single URL using the BrowserInteractor.
func (e *Engine) crawlPage(ctx context.Context, task crawlTask, taskChan chan<- schemas.Task) {
	log := e.logger.With(zap.String("url", task.URL), zap.Int("depth", task.Depth))
	log.Debug("Actively crawling page")

	links, err := e.browser.NavigateAndExtract(ctx, task.URL)
	if err != nil {
		log.Warn("Error during active crawl", zap.Error(err))
		return
	}

	log.Debug("Extracted links", zap.Int("linkCount", len(links)))

	nextDepth := task.Depth + 1
	for _, link := range links {
		parsedLink, err := e.normalizeAndValidate(link, task.URL)
		if err != nil {
			log.Debug("Discarding link", zap.Error(err), zap.String("link", link))
			continue
		}
		e.processAsset(ctx, parsedLink, nextDepth, "Crawler", taskChan)
	}
}

// processAsset handles deduplication, reporting, and enqueueing of a discovered URL.
func (e *Engine) processAsset(ctx context.Context, u *url.URL, depth int, source string, taskChan chan<- schemas.Task) {
	urlString := u.String()
	if _, loaded := e.processedUrls.LoadOrStore(urlString, true); loaded {
		return
	}

	e.logger.Info("New asset discovered",
		zap.String("url", urlString),
		zap.Int("depth", depth),
		zap.String("source", source))

	e.dispatchTasksForAsset(ctx, urlString, taskChan)

	props, _ := json.Marshal(map[string]interface{}{
		"depth":     depth,
		"source":    source,
		"sessionID": e.sessionID,
	})

	if err := e.kg.AddNode(ctx, schemas.Node{
		ID:         urlString,
		Type:       schemas.NodeURL,
		Label:      urlString,
		Status:     schemas.StatusNew,
		Properties: props,
	}); err != nil {
		e.logger.Warn("Failed to add URL node to KG", zap.Error(err), zap.String("url", urlString))
	}

	hostname := u.Hostname()
	if err := e.kg.AddNode(ctx, schemas.Node{
		ID:     hostname,
		Type:   schemas.NodeDomain,
		Label:  hostname,
		Status: schemas.StatusNew,
	}); err != nil {
		e.logger.Warn("Failed to add/update Domain node in KG", zap.Error(err), zap.String("hostname", hostname))
	}

	if err := e.kg.AddEdge(ctx, schemas.Edge{
		ID:    uuid.NewString(),
		From:  hostname,
		To:    urlString,
		Type:  schemas.RelationshipHostsURL,
		Label: "HOSTS_URL",
	}); err != nil {
		e.logger.Warn("Failed to add HostsURL relationship in KG", zap.Error(err), zap.String("from", hostname), zap.String("to", urlString))
	}

	rootDomain := e.scope.GetRootDomain()
	if hostname != rootDomain {
		if err := e.kg.AddEdge(ctx, schemas.Edge{
			ID:    uuid.NewString(),
			From:  rootDomain,
			To:    hostname,
			Type:  schemas.RelationshipHasSubdomain,
			Label: "HAS_SUBDOMAIN",
		}); err != nil {
			e.logger.Warn("Failed to add HasSubdomain relationship in KG", zap.Error(err), zap.String("from", rootDomain), zap.String("to", hostname))
		}
	}

	if depth < int(e.config.Discovery().MaxDepth) {
		e.taskWG.Add(1)
		select {
		case e.queue <- crawlTask{URL: urlString, Depth: depth}:
		default:
			e.logger.Error("Discovery queue is full, dropping task. Increase buffer size or concurrency.")
			e.taskWG.Done()
		}
	}
}

// dispatchTasksForAsset creates and sends tasks based on the enabled scanners in config.
func (e *Engine) dispatchTasksForAsset(ctx context.Context, urlString string, taskChan chan<- schemas.Task) {
	scanners := e.config.Scanners()

	// Helper to send a task while respecting context cancellation.
	sendTask := func(taskType schemas.TaskType) {
		task := schemas.Task{
			TaskID:    uuid.NewString(),
			ScanID:    e.sessionID,
			Type:      taskType,
			TargetURL: urlString,
		}
		select {
		case taskChan <- task:
			e.logger.Debug("Dispatched task for asset", zap.String("url", urlString), zap.String("type", string(taskType)))
		case <-ctx.Done():
			e.logger.Warn("Context cancelled, could not dispatch task", zap.String("url", urlString), zap.String("type", string(taskType)))
		}
	}

	if scanners.Active.Taint.Enabled {
		sendTask(schemas.TaskAnalyzeWebPageTaint)
	}
	if scanners.Active.ProtoPollution.Enabled {
		sendTask(schemas.TaskAnalyzeWebPageProtoPP)
	}
	if scanners.Passive.Headers.Enabled {
		sendTask(schemas.TaskAnalyzeHeaders)
	}
	if scanners.Static.JWT.Enabled {
		sendTask(schemas.TaskAnalyzeJWT)
	}
	// Note: Timeslip, ATO and IDOR are more complex and are typically not dispatched per-URL.
	// They would be dispatched by a higher-level orchestrator logic based on scan strategy.
}

// normalizeAndValidate cleans the URL, resolves relative paths, checks the scope, and normalizes the format.
func (e *Engine) normalizeAndValidate(rawURL, baseURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL format: %w", err)
	}

	if !u.IsAbs() {
		if baseURL == "" {
			if u.Host != "" && u.Scheme == "" {
				u.Scheme = "https"
			} else if u.Host == "" {
				return nil, fmt.Errorf("relative URL without base: %s", rawURL)
			}
		} else {
			base, err := url.Parse(baseURL)
			if err != nil {
				return nil, fmt.Errorf("invalid base URL provided: %w", err)
			}
			u = base.ResolveReference(u)
		}
	}

	u.Fragment = ""

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	if !e.scope.IsInScope(u) {
		return nil, fmt.Errorf("out of scope: %s", u.String())
	}

	host := u.Host
	if (u.Scheme == "http" && strings.HasSuffix(host, ":80")) || (u.Scheme == "https" && strings.HasSuffix(host, ":443")) {
		u.Host = u.Hostname()
	}

	if u.Path == "" {
		u.Path = "/"
	}

	if u.RawQuery != "" {
		u.RawQuery = u.Query().Encode()
	}

	ext := strings.ToLower(filepath.Ext(u.Path))
	if _, ignore := ignoredExtensions[ext]; ignore {
		return nil, fmt.Errorf("static asset ignored")
	}

	return u, nil
}
