// internal/worker/worker_performance_test.go
package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

func Benchmark_ProcessTask(b *testing.B) {
	cfg, logger, globalCtx := setupTestEnvironment(b)
	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	if err != nil {
		b.Fatalf("failed to create worker: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := schemas.Task{
		Type:      schemas.TaskAnalyzeHeaders,
		TargetURL: server.URL,
	}

	analysisCtx := &core.AnalysisContext{
		Task:   task,
		Logger: logger,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = w.ProcessTask(context.Background(), analysisCtx)
	}
}
