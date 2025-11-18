// File: internal/service/initializers.go
package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
)

// InitializeKGClient connects to the database or starts an in-memory Knowledge Graph.
// This provides a centralized way to handle KG initialization, including fallbacks and standardized config.
// (Moved from cmd/evolution.go)
func InitializeKGClient(ctx context.Context, cfg config.KnowledgeGraphConfig, logger *zap.Logger, useInMemory bool) (schemas.KnowledgeGraphClient, func(), error) {
	// Determine if we're falling back to the in-memory graph due to configuration,
	// rather than an explicit command-line flag.
	isInMemoryByDefault := !useInMemory && (cfg.Type == "memory" || cfg.Type == "in-memory" || cfg.Type == "")

	if useInMemory || isInMemoryByDefault {
		// If we are using the in-memory graph because of the config file (and not the explicit flag),
		// log a loud warning that this is not suitable for production.
		if isInMemoryByDefault {
			logger.Warn("No persistent Knowledge Graph configured; defaulting to a temporary in-memory store. All learned data will be lost on exit. This is not recommended for production use.")
		}
		logger.Info("Initializing In-Memory Knowledge Graph.")
		kg, err := knowledgegraph.NewInMemoryKG(logger)
		return kg, nil, err
	}

	if cfg.Type == "postgres" {
		logger.Info("Initializing PostgreSQL Knowledge Graph.", zap.String("host", cfg.Postgres.Host))
		connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Host, cfg.Postgres.Port, cfg.Postgres.DBName, cfg.Postgres.SSLMode)

		poolConfig, err := pgxpool.ParseConfig(connString)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse PGX pool config: %w", err)
		}
		// Robustness improvement: Centralized DB connection pooling settings.
		poolConfig.MaxConns = 10
		poolConfig.MinConns = 2
		poolConfig.MaxConnLifetime = 1 * time.Hour
		poolConfig.MaxConnIdleTime = 30 * time.Minute

		pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create PGX connection pool: %w", err)
		}

		// Robustness improvement: Ensure the connection is valid before proceeding.
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			return nil, nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
		}

		kg := knowledgegraph.NewPostgresKG(pool, logger)
		cleanup := func() {
			logger.Info("Closing PostgreSQL connection pool (standalone KG).")
			pool.Close()
		}
		return kg, cleanup, nil
	}

	return nil, nil, fmt.Errorf("unsupported Knowledge Graph type: %s", cfg.Type)
}

// InitializeLLMClient creates a new LLM client based on the configuration.
// This helper centralizes LLM initialization for commands like 'evolve' and 'self-heal'.
func InitializeLLMClient(ctx context.Context, cfg config.AgentConfig, logger *zap.Logger) (schemas.LLMClient, error) {
	llmClient, err := llmclient.NewClient(ctx, cfg, logger)
	if err != nil {
		logger.Error("Failed to initialize LLM client. Features requiring AI agents will fail.", zap.Error(err))
		return nil, fmt.Errorf("failed to initialize LLM client: %w", err)
	}
	return llmClient, nil
}

// StartFindingsConsumer launches a goroutine that reads from the findings channel and persists them using batching.
// It manages its lifecycle using the provided WaitGroup.
// Implements batching and robust draining on shutdown.
func StartFindingsConsumer(ctx context.Context, wg *sync.WaitGroup, findingsChan <-chan schemas.Finding, dbStore schemas.Store, logger *zap.Logger) {
	wg.Add(1) // Increment WaitGroup before starting the goroutine.
	go func() {
		defer wg.Done() // Decrement WaitGroup when the goroutine exits.
		logger.Info("Starting findings consumer goroutine (with batching)...")
		defer logger.Info("Findings consumer goroutine shut down.")

		// Define batching parameters
		const batchSize = 50
		const batchTimeout = 2 * time.Second

		batch := make([]schemas.Finding, 0, batchSize)
		ticker := time.NewTicker(batchTimeout)
		defer ticker.Stop()

		// Helper function to process the current batch
		processBatch := func() {
			if len(batch) == 0 {
				return
			}

			logger.Debug("Persisting findings batch.", zap.Int("count", len(batch)))

			// Create an envelope for the batch.
			envelope := &schemas.ResultEnvelope{
				// Individual findings contain their respective IDs.
				Timestamp: time.Now(),
				Findings:  batch,
			}

			// Use a background context with a timeout for persistence, not the main 'ctx'.
			// This ensures persistence attempts complete even if the main context is canceled during shutdown.
			persistCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := dbStore.PersistData(persistCtx, envelope); err != nil {
				// Robustness improvement: Handle persistence errors gracefully.
				logger.Error("Failed to persist findings batch. Data may be lost.", zap.Error(err), zap.Int("batch_size", len(batch)))
				// Depending on requirements, one might implement retry logic or a dead-letter queue here.
			}

			// Clear the batch
			batch = batch[:0]
		}

		// Main consumer loop
		for {
			select {
			case finding, ok := <-findingsChan:
				if !ok {
					// Channel closed (graceful shutdown signal via Components.Shutdown).
					// Process any remaining findings in the batch and exit.
					logger.Info("Findings channel closed, processing remaining batch and shutting down.")
					processBatch()
					return
				}

				batch = append(batch, finding)
				if len(batch) >= batchSize {
					processBatch()
					// Reset ticker since we processed a full batch, avoiding unnecessary timeout flush.
					ticker.Reset(batchTimeout)
				}

			case <-ticker.C:
				// Timeout reached, process whatever is in the batch.
				processBatch()

			case <-ctx.Done():
				// Context cancelled (e.g., immediate shutdown signal via CtrlC).
				// Attempt to quickly drain the channel buffer and process remaining items before exiting.
				logger.Warn("Findings consumer context canceled, attempting to drain channel and process remaining batch.")
				drainChannel(findingsChan, &batch)
				processBatch()
				return
			}
		}
	}()
}

// drainChannel attempts to read any remaining items from the channel buffer into the batch.
// It stops when the channel is closed or the buffer is empty.
func drainChannel(findingsChan <-chan schemas.Finding, batch *[]schemas.Finding) {
	for {
		select {
		case finding, ok := <-findingsChan:
			if !ok {
				// Channel closed and empty
				return
			}
			*batch = append(*batch, finding)
		default:
			// Channel buffer is currently empty
			return
		}
	}
}