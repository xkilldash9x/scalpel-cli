// internal/analysis/core/context.go
package core

import (
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// KnowledgeGraphClient defines the interface for interacting with the Knowledge Graph.
// This allows analyzers to read context or update the graph during analysis.
type KnowledgeGraphClient interface {
	// Define necessary methods (e.g., GetNode, AddNode, AddEdge)
	// For now, we keep it empty as the exact methods used by analyzers are not fully defined in the context.
}

// OASTProvider defines the interface for Out-of-Band testing services.
type OASTProvider interface {
	// Define necessary methods (e.g., GetServerURL, FetchInteractions)
}

// GlobalContext holds application-wide services and configurations shared across all tasks.
type GlobalContext struct {
	Config         *config.Config
	Logger         *zap.Logger
	BrowserManager *browser.Manager
	DBPool         *pgxpool.Pool // Added this field
	KGClient       KnowledgeGraphClient
	OASTProvider   OASTProvider // Optional
	// Add other global services like HTTPClient, LLMClient, etc.
}

// AnalysisContext provides the specific context for a single analysis task.
// It includes the task details, the target, and access to the global context.
type AnalysisContext struct {
	Global    *GlobalContext
	Task      schemas.Task
	TargetURL *url.URL
	Logger    *zap.Logger

	// Artifacts collected prior to analysis (e.g., HAR, DOM snapshot).
	// This is primarily used by passive analyzers.
	Artifacts *schemas.Artifacts

	// Findings and KGUpdates are populated by the analyzer during execution.
	Findings  []schemas.Finding
	KGUpdates *schemas.KnowledgeGraphUpdate
}

// AddFinding is a helper method to append a finding to the context.
func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	// Ensure ScanID is populated if missing
	if finding.ScanID == "" && ac.Task.ScanID != "" {
		finding.ScanID = ac.Task.ScanID
	}
	ac.Findings = append(ac.Findings, finding)
}