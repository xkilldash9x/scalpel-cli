package core

import (
	"context"
	"net/http"
	"net/url"
	"sync"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	// CORRECTED: All dependencies point to central packages
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// ... (AnalyzerType, Analyzer, BaseAnalyzer are the same)

// GlobalContext now holds interfaces
type GlobalContext struct {
	Config         *config.Config
	Logger         *zap.Logger
	HTTPClient     *http.Client
	BrowserManager interfaces.SessionManager
	KGClient       interfaces.KnowledgeGraph
}

// AnalysisContext now holds schemas.Artifacts
type AnalysisContext struct {
	Global    *GlobalContext
	Task      schemas.Task
	TargetURL *url.URL
	Logger    *zap.Logger
	Findings  []schemas.Finding
	KGUpdates *schemas.KGUpdates
	Artifacts *schemas.Artifacts // CORRECTED
	mu        sync.Mutex
}

// ... (AddFinding and AddKGUpdate are the same)
