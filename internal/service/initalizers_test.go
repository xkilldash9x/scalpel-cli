package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

func TestDrainChannel(t *testing.T) {
	ch := make(chan schemas.Finding, 3)
	ch <- schemas.Finding{ID: "1"}
	ch <- schemas.Finding{ID: "2"}
	close(ch)

	var batch []schemas.Finding
	drainChannel(ch, &batch)

	assert.Len(t, batch, 2)
	assert.Equal(t, "1", batch[0].ID)
	assert.Equal(t, "2", batch[1].ID)
}

func TestStartFindingsConsumer(t *testing.T) {
	logger := zap.NewNop()

	t.Run("BatchProcessing", func(t *testing.T) {
		mockStore := new(MockStore)
		findingsChan := make(chan schemas.Finding, 100)
		wg := &sync.WaitGroup{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Expect PersistData to be called
		mockStore.On("PersistData", mock.Anything, mock.MatchedBy(func(env *schemas.ResultEnvelope) bool {
			return len(env.Findings) > 0
		})).Return(nil)

		StartFindingsConsumer(ctx, wg, findingsChan, mockStore, logger)

		// Send enough findings to trigger a batch (batchSize is 50 in source)
		for i := 0; i < 55; i++ {
			findingsChan <- schemas.Finding{ID: "test"}
		}

		// Give some time for processing
		time.Sleep(100 * time.Millisecond)

		// Close channel to trigger final drain and exit
		close(findingsChan)
		wg.Wait()

		mockStore.AssertExpectations(t)
	})

	t.Run("GracefulShutdown", func(t *testing.T) {
		mockStore := new(MockStore)
		findingsChan := make(chan schemas.Finding, 10)
		wg := &sync.WaitGroup{}
		ctx := context.Background()

		mockStore.On("PersistData", mock.Anything, mock.Anything).Return(nil).Maybe()

		StartFindingsConsumer(ctx, wg, findingsChan, mockStore, logger)

		findingsChan <- schemas.Finding{ID: "1"}
		close(findingsChan) // Signal shutdown

		wg.Wait() // Should finish
	})
}

func TestInitializeKGClient(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	t.Run("InMemoryDefault", func(t *testing.T) {
		cfg := config.KnowledgeGraphConfig{Type: "memory"}
		kg, cleanup, err := InitializeKGClient(ctx, cfg, logger, false)
		assert.NoError(t, err)
		assert.NotNil(t, kg)
		assert.Nil(t, cleanup)
	})

	t.Run("InMemoryFlag", func(t *testing.T) {
		cfg := config.KnowledgeGraphConfig{Type: "postgres"}
		kg, cleanup, err := InitializeKGClient(ctx, cfg, logger, true)
		assert.NoError(t, err)
		assert.NotNil(t, kg)
		assert.Nil(t, cleanup)
	})

	t.Run("UnsupportedType", func(t *testing.T) {
		cfg := config.KnowledgeGraphConfig{Type: "invalid"}
		kg, cleanup, err := InitializeKGClient(ctx, cfg, logger, false)
		assert.Error(t, err)
		assert.Nil(t, kg)
		assert.Nil(t, cleanup)
		assert.Contains(t, err.Error(), "unsupported Knowledge Graph type")
	})
}
