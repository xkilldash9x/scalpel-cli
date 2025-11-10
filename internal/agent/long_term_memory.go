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

// ltm (Long-Term Memory) provides the agent with a memory system that can
// detect redundant or novel observations. It uses a caching mechanism with a
// background cleanup process to manage its memory footprint.
type ltm struct {
	logger        *zap.Logger
	cfg           config.LTMConfig
	mu            sync.RWMutex
	cache         map[string]cachedObservation
	payloadHashes map[[32]byte]string // A set of hashes for fast redundancy checks.
	stopOnce      sync.Once
	stopChan      chan struct{} // Signals the background janitor to stop.
	wg            sync.WaitGroup
}

// cachedObservation stores an observation's payload, its hash, and a timestamp
// for time-to-live (TTL) based eviction.
type cachedObservation struct {
	Payload     []byte
	PayloadHash [32]byte
	Timestamp   time.Time
}

// NewLTM creates a new Long-Term Memory module. The background cache cleanup
// process must be started by calling the Start() method.
func NewLTM(cfg config.LTMConfig, logger *zap.Logger) LTM {
	return &ltm{
		logger:        logger.Named("ltm"),
		cfg:           cfg,
		cache:         make(map[string]cachedObservation),
		payloadHashes: make(map[[32]byte]string),
		stopChan:      make(chan struct{}),
	}
}

// Start launches the background goroutine that periodically cleans up expired
// entries from the LTM cache.
func (l *ltm) Start() {
	l.wg.Add(1)
	go l.runJanitor()
}

// ProcessAndFlagObservation is the primary entry point for the LTM. It analyzes
// a new observation to apply heuristic flags (e.g., for errors or vulnerabilities)
// and checks if the observation's payload is a duplicate of one seen recently.
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

// isRedundant performs a thread-safe check to see if a payload hash already
// exists in the LTM cache.
func (l *ltm) isRedundant(payloadHash [32]byte) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, exists := l.payloadHashes[payloadHash]
	return exists
}

// addObservationToCache adds a new observation's data and hash to the internal
// caches in a thread-safe manner.
func (l *ltm) addObservationToCache(obsID string, payload []byte, payloadHash [32]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()

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

// runJanitor is the background process that periodically calls
// purgeExpiredCache to maintain the LTM cache.
func (l *ltm) runJanitor() {
	defer l.wg.Done()
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

// purgeExpiredCache iterates through the cache and removes any entries that are
// older than the configured time-to-live (TTL).
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
			delete(l.cache, obsID)
			delete(l.payloadHashes, entry.PayloadHash)
			purgedCount++
		}
	}

	if purgedCount > 0 {
		l.logger.Debug("Purged expired entries from LTM cache.", zap.Int("count", purgedCount))
	}
}

// Stop gracefully shuts down the LTM's background janitor process. It is safe
// to call multiple times.
func (l *ltm) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		l.wg.Wait()
	})
}

var _ LTM = (*ltm)(nil)
