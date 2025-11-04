// File: internal/agent/long_term_memory.go
package agent

import ( // This is a comment to force a change
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Heuristic flags for classifying observations.
const (
	FlagCritical      = "IS_CRITICAL"
	FlagRedundant     = "IS_REDUNDANT"
	FlagError         = "IS_ERROR"
	FlagVulnerability = "IS_VULNERABILITY"
)

// ltm (Long-Term Memory) manages context summarization, heuristic flagging,
// and redundancy detection for the agent's mind.
type ltm struct {
	logger *zap.Logger
	cfg    config.LTMConfig
	mu     sync.RWMutex

	// Main cache mapping observation ID to its data.
	cache map[string]cachedObservation
	// A set of payload hashes for near-instant redundancy checks (O(1)).
	payloadHashes map[[32]byte]string

	stopOnce sync.Once
	// Channel to signal the background janitor goroutine to stop.
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// cachedObservation stores the original payload along with its hash and timestamp for eviction.
type cachedObservation struct {
	Payload     []byte
	PayloadHash [32]byte
	Timestamp   time.Time
}

// NewLTM creates a new Long-Term Memory module. Its background processes must be
// started by calling the Start() method.
func NewLTM(cfg config.LTMConfig, logger *zap.Logger) LTM {
	return &ltm{
		logger:        logger.Named("ltm"),
		cfg:           cfg,
		cache:         make(map[string]cachedObservation),
		payloadHashes: make(map[[32]byte]string),
		stopChan:      make(chan struct{}),
	}
}

// Start launches the background cache cleanup process for the LTM.
func (l *ltm) Start() {
	l.wg.Add(1)
	go l.runJanitor()
}

// ProcessAndFlagObservation analyzes an observation to apply heuristic flags
// and detect semantic redundancy. This is the primary entry point for the LLMMind.
func (l *ltm) ProcessAndFlagObservation(ctx context.Context, obs Observation) map[string]bool {
	flags := make(map[string]bool)

	// -- Heuristic Flagging for Critical Events --
	if obs.Result.Status == "failed" && obs.Result.ErrorCode != "" {
		flags[FlagError] = true
		flags[FlagCritical] = true
	}
	if len(obs.Result.Findings) > 0 {
		flags[FlagVulnerability] = true
		flags[FlagCritical] = true
	}
	if obs.Type == ObservedEvolutionResult {
		flags[FlagCritical] = true
	}

	// -- Semantic Redundancy Detection via Hashing --
	payloadBytes, err := json.Marshal(obs.Data)
	if err != nil {
		l.logger.Warn("Failed to marshal observation data for redundancy check", zap.Error(err))
		return flags // Return flags identified so far.
	}
	payloadHash := sha256.Sum256(payloadBytes)

	if l.isRedundant(payloadHash) {
		l.logger.Debug("Flagging observation as redundant based on payload hash.", zap.String("obs_id", obs.ID))
		flags[FlagRedundant] = true
	} else {
		// Only cache non-redundant payloads to keep the comparison set relevant.
		l.addObservationToCache(obs.ID, payloadBytes, payloadHash)
	}

	return flags
}

// isRedundant checks if a payload hash already exists in our cache.
func (l *ltm) isRedundant(payloadHash [32]byte) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, exists := l.payloadHashes[payloadHash]
	return exists
}

// addObservationToCache adds a new observation's data to the internal caches.
func (l *ltm) addObservationToCache(obsID string, payload []byte, payloadHash [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// A simple check to prevent adding the same observation ID twice.
	if _, exists := l.cache[obsID]; exists {
		return
	}

	l.cache[obsID] = cachedObservation{
		Payload:     payload,
		PayloadHash: payloadHash,
		Timestamp:   time.Now(),
	}
	l.payloadHashes[payloadHash] = obsID
}

// runJanitor is a background goroutine that periodically purges expired items from the cache.
func (l *ltm) runJanitor() {
	defer l.wg.Done()
	// Use a ticker to trigger cleanup at a configurable interval.
	interval := time.Duration(l.cfg.CacheJanitorIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second // Default to 1 minute if not configured.
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	l.logger.Info("LTM cache janitor started.", zap.Duration("interval", interval))

	for {
		select {
		case <-ticker.C:
			l.purgeExpiredCache()
		case <-l.stopChan:
			l.logger.Info("LTM cache janitor stopped.")
			return
		}
	}
}

// purgeExpiredCache iterates over the cache and removes items that have exceeded their TTL.
func (l *ltm) purgeExpiredCache() {
	l.mu.Lock()
	defer l.mu.Unlock()

	ttl := time.Duration(l.cfg.CacheTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute // Default to 5 minutes.
	}
	now := time.Now()
	purgedCount := 0

	for obsID, entry := range l.cache {
		if now.Sub(entry.Timestamp) > ttl {
			// The entry is expired, remove it from both the main cache and the hash set.
			delete(l.cache, obsID)
			delete(l.payloadHashes, entry.PayloadHash)
			purgedCount++
		}
	}

	if purgedCount > 0 {
		l.logger.Debug("Purged expired entries from LTM cache.", zap.Int("count", purgedCount))
	}
}

// Stop gracefully shuts down the LTM's background processes.
func (l *ltm) Stop() {
	// Use sync.Once to ensure Stop is idempotent and won't panic on closing a closed channel.
	l.stopOnce.Do(func() {
		// Closing the stopChan signals the janitor to exit its loop.
		close(l.stopChan)
		// Wait for the janitor goroutine to finish completely.
		l.wg.Wait()
	})
}

var _ LTM = (*ltm)(nil)
