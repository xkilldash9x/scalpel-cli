// File: internal/analysis/core/context.go
package core

import (
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// AdapterRegistry is a type alias for a map that associates a specific task type
// with its corresponding `Analyzer` implementation. This registry is used by
// workers to dispatch tasks to the correct analysis module.
type AdapterRegistry map[schemas.TaskType]Analyzer

// GlobalContext provides a centralized container for application-wide services,
// configurations, and resources that are shared across all analysis tasks. This
// includes database connections, loggers, and the browser manager.
type GlobalContext struct {
	Config         config.Interface
	Logger         *zap.Logger
	BrowserManager schemas.BrowserManager
	DBPool         *pgxpool.Pool
	KGClient       schemas.KnowledgeGraphClient
	OASTProvider   schemas.OASTProvider
	FindingsChan   chan<- schemas.Finding
	// Adapters provides access to the registry of all available analysis adapters,
	// allowing for dynamic invocation by components like the agent.
	Adapters AdapterRegistry
}

// AnalysisContext encapsulates all the information and resources required for a
// single, specific analysis task. It contains the task details, the target URL,
// a task-specific logger, and access to the shared `GlobalContext`.
type AnalysisContext struct {
	Global    *GlobalContext
	Task      schemas.Task
	TargetURL *url.URL
	Logger    *zap.Logger
	Artifacts *schemas.Artifacts
	Findings  []schemas.Finding
	KGUpdates *schemas.KnowledgeGraphUpdate
	// Session allows an analyzer to operate on a pre-existing browser session,
	// which is crucial for agent-driven, multi-step analysis scenarios.
	Session schemas.SessionContext
}

// AddFinding is a convenience method for analyzers to report a new vulnerability
// finding. It automatically populates the finding with the scan ID from the
// current task context before appending it to the list of findings.
func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	if finding.ScanID == "" && ac.Task.ScanID != "" {
		finding.ScanID = ac.Task.ScanID
	}
	ac.Findings = append(ac.Findings, finding)
}
