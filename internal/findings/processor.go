// internal/findings/processor.go
package findings

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Processor manages the ingestion, batching, and persistence of findings.
type Processor struct {
	inputChan <-chan schemas.Finding
	// We use dbPool directly here for efficient batch operations (pgx.CopyFrom),
	// as the store.Store interface is optimized for ResultEnvelope transactions.
	dbPool *pgxpool.Pool
	logger *zap.Logger
	cfg    config.EngineConfig

	buffer []schemas.Finding
	mu     sync.Mutex
	wg     sync.WaitGroup

	// Signals for synchronization
	flushSignal chan struct{}
	stopSignal  chan struct{}
}

// NewProcessor initializes a new findings processor.
func NewProcessor(inputChan <-chan schemas.Finding, dbPool *pgxpool.Pool, logger *zap.Logger, engineCfg config.EngineConfig) *Processor {
	// Ensure sane defaults (validation in config.go ensures they are positive if set)
	batchSize := engineCfg.FindingsBatchSize
	if batchSize <= 0 {
		batchSize = 100 // Default
		engineCfg.FindingsBatchSize = batchSize
	}
	if engineCfg.FindingsFlushInterval <= 0 {
		engineCfg.FindingsFlushInterval = 2 * time.Second // Default
	}

	return &Processor{
		inputChan:   inputChan,
		dbPool:      dbPool,
		logger:      logger.Named("findings_processor"),
		cfg:         engineCfg,
		buffer:      make([]schemas.Finding, 0, batchSize),
		flushSignal: make(chan struct{}, 1), // Buffered channel to prevent blocking on signal send
		stopSignal:  make(chan struct{}),
	}
}

// Start runs the main processing loop.
func (p *Processor) Start(ctx context.Context) {
	p.wg.Add(1)
	defer p.wg.Done()

	ticker := time.NewTicker(p.cfg.FindingsFlushInterval)
	defer ticker.Stop()

	p.logger.Info("Findings processor started.",
		zap.Int("batch_size", p.cfg.FindingsBatchSize),
		zap.Duration("flush_interval", p.cfg.FindingsFlushInterval))

	for {
		select {
		case finding, ok := <-p.inputChan:
			if !ok {
				// Input channel closed (should not happen if producers stop first, but handled defensively).
				p.logger.Warn("Input channel closed unexpectedly. Finalizing processing.")
				p.flush()
				return
			}
			p.processFinding(finding)

		case <-ticker.C:
			// Time-based flush
			p.flush()

		case <-p.flushSignal:
			// Explicit flush requested (e.g., batch size reached)
			p.flush()

		case <-ctx.Done():
			// Context cancelled (e.g., immediate server termination).
			p.logger.Warn("Context cancelled. Stopping processor immediately and attempting final flush.")
			p.drainChannel()
			p.flush()
			return

		case <-p.stopSignal:
			// Explicit stop requested (Graceful shutdown).
			p.logger.Info("Stop signal received. Draining channel and flushing remaining buffer.")
			p.drainChannel()
			p.flush()
			return
		}
	}
}

// drainChannel reads any remaining findings from the input channel until it's empty.
func (p *Processor) drainChannel() {
	p.logger.Debug("Draining input channel.")
	count := 0
	for {
		select {
		case finding, ok := <-p.inputChan:
			if !ok {
				return // Channel closed and drained
			}
			p.processFinding(finding)
			count++
		default:
			// Channel is empty
			p.logger.Debug("Channel drained.", zap.Int("count", count))
			return
		}
	}
}

// processFinding adds a finding to the buffer and triggers a flush if the batch size is reached.
func (p *Processor) processFinding(finding schemas.Finding) {
	// Ensure essential fields are populated before buffering
	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now().UTC()
	}

	p.mu.Lock()
	p.buffer = append(p.buffer, finding)
	bufferLen := len(p.buffer)
	p.mu.Unlock()

	if bufferLen >= p.cfg.FindingsBatchSize {
		// Trigger asynchronous flush if batch size reached
		select {
		case p.flushSignal <- struct{}{}:
		default:
			// Signal already pending, skip sending another one.
		}
	}
}

// flush persists the current buffer to the database.
func (p *Processor) flush() {
	p.mu.Lock()
	if len(p.buffer) == 0 {
		p.mu.Unlock()
		return
	}
	// Create a copy of the buffer to persist, and reset the main buffer.
	toPersist := make([]schemas.Finding, len(p.buffer))
	copy(toPersist, p.buffer)
	p.buffer = p.buffer[:0] // Reset buffer
	p.mu.Unlock()

	p.logger.Debug("Flushing findings.", zap.Int("count", len(toPersist)))

	// Persist the batch (in a separate goroutine to avoid blocking the main loop)
	p.wg.Add(1)
	go func(batch []schemas.Finding) {
		defer p.wg.Done()
		// Use a context with timeout for the database operation
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := p.persistBatch(ctx, batch); err != nil {
			p.logger.Error("Failed to persist findings batch.", zap.Error(err), zap.Int("batch_size", len(batch)))
			// TODO: Implement retry mechanism or dead-letter queue for failed batches.
		}
	}(toPersist)
}

// persistBatch handles the actual database insertion logic using pgx.CopyFrom.
func (p *Processor) persistBatch(ctx context.Context, batch []schemas.Finding) error {
	if p.dbPool == nil {
		// If running in an environment without a database, log and continue.
		p.logger.Warn("Database pool not initialized. Findings will not be persisted.")
		return nil
	}

	// Prepare data for pgx.CopyFrom
	rows := make([][]interface{}, len(batch))
	validCount := 0

	for i, f := range batch {
		// Data validation: Ensure required fields are present.
		if f.ScanID == "" {
			// Findings MUST be associated with a ScanID for correlation.
			p.logger.Warn("Finding missing ScanID, skipping persistence.", zap.String("finding_id", f.ID), zap.String("module", f.Module))
			rows[i] = nil // Mark row as invalid/skippable
			continue
		}

		evidence := f.Evidence
		if evidence == "" || evidence == "null" {
			evidence = "{}" // Ensure valid JSON object
		}

		// Align columns with the database schema (as defined in store.go)
		rows[i] = []interface{}{
			f.ID, f.ScanID, f.TaskID,
			f.Target, f.Module, f.Vulnerability.Name,
			string(f.Severity), f.Description,
			evidence,
			f.Recommendation, f.CWE,
			f.Timestamp,
		}
		validCount++
	}

	// Filter out nil rows (skipped findings) to create a clean slice for CopyFrom
	validRows := make([][]interface{}, 0, validCount)
	for _, row := range rows {
		if row != nil {
			validRows = append(validRows, row)
		}
	}

	if len(validRows) == 0 {
		if len(batch) > 0 {
			p.logger.Debug("No valid findings in batch to persist (all skipped).")
		}
		return nil
	}

	// Execute CopyFrom
	copyCount, err := p.dbPool.CopyFrom(
		ctx,
		pgx.Identifier{"findings"},
		// Ensure column names match the database schema (observed_at for Timestamp)
		[]string{"id", "scan_id", "task_id", "target", "module", "vulnerability", "severity", "description", "evidence", "recommendation", "cwe", "observed_at"},
		pgx.CopyFromRows(validRows),
	)

	if err != nil {
		return fmt.Errorf("failed to copy findings batch: %w", err)
	}
	if int(copyCount) != len(validRows) {
		// This indicates a mismatch between the data provided and what the database accepted.
		p.logger.Warn("Mismatch in persisted findings count.", zap.Int("expected", len(validRows)), zap.Int64("actual", copyCount))
		return fmt.Errorf("mismatch in copied findings count: expected %d, got %d", len(validRows), copyCount)
	}

	p.logger.Debug("Successfully persisted findings batch.", zap.Int("count", len(validRows)))
	return nil
}

// Stop gracefully shuts down the processor, ensuring all buffered findings are persisted.
func (p *Processor) Stop() {
	p.logger.Info("Stopping findings processor...")
	// Signal the main loop to stop. This will trigger drainChannel() and flush().
	// We use a select to avoid panic if Stop() is called multiple times (idempotent)
	select {
	case <-p.stopSignal:
		// Already closed
	default:
		close(p.stopSignal)
	}

	// Wait for the main loop and any ongoing persistence operations to complete.
	p.wg.Wait()
	p.logger.Info("Findings processor stopped.")
}
