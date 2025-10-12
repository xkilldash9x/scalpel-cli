package core

import (
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// GlobalContext holds application-wide services and configurations shared across all tasks.
type GlobalContext struct {
	Config         config.Interface
	Logger         *zap.Logger
	BrowserManager schemas.BrowserManager
	DBPool         *pgxpool.Pool
	KGClient       schemas.KnowledgeGraphClient
	OASTProvider   schemas.OASTProvider
	FindingsChan   chan<- schemas.Finding
}

// AnalysisContext provides the specific context for a single analysis task.
// It includes the task details, the target, and access to the global context.
type AnalysisContext struct {
	Global    *GlobalContext
	Task      schemas.Task
	TargetURL *url.URL
	Logger    *zap.Logger
	Artifacts *schemas.Artifacts
	Findings  []schemas.Finding
	KGUpdates *schemas.KnowledgeGraphUpdate
}

// AddFinding is a helper method to append a finding to the context.
func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	if finding.ScanID == "" && ac.Task.ScanID != "" {
		finding.ScanID = ac.Task.ScanID
	}
	ac.Findings = append(ac.Findings, finding)
}
