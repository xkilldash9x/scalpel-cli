// pkg/analysis/core/types.go
package core

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/knowledgegraph"
	"github.com/xkilldash9x/evolution-scalpel/pkg/remote_exec"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
	//"github.com/xkilldash9x/scalpel-clil/pkg/tao_policy"
)

// -- Definitions --

// SeverityLevel defines the severity of a finding.
type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "Critical"
	SeverityHigh     SeverityLevel = "High"
	SeverityMedium   SeverityLevel = "Medium"
	SeverityLow      SeverityLevel = "Low"
	SeverityInfo     SeverityLevel = "Info"
)

// Status defines the status of a finding.
type Status string

const (
	StatusOpen   Status = "Open"
	StatusClosed Status = "Closed"
)

// AnalysisResult represents a finding discovered during active analysis.
type AnalysisResult struct {
	ScanID            uuid.UUID
	AnalyzerName      string
	Timestamp         time.Time
	VulnerabilityType string
	Title             string
	Description       string
	Severity          SeverityLevel
	Status            Status
	Confidence        float64
	TargetURL         string
	Evidence          *Evidence
	CWE               string
}

// Evidence holds the raw data supporting a finding.
type Evidence struct {
	Summary        string
	Request        *SerializedRequest
	Response       *SerializedResponse
	AdditionalData map[string]interface{} // Added for flexible, structured evidence
}

// SerializedRequest holds a representation of the HTTP request.
type SerializedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    string
}

// SerializedResponse holds a representation of the HTTP response.
type SerializedResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
}

// Reporter is the interface for publishing analysis results.
// Implementations MUST be safe for concurrent use by multiple goroutines.
type Reporter interface {
	Publish(finding AnalysisResult) error
}

// -- End Definitions --

type TaskType string

const (
	TaskAgentMission          TaskType = "AGENT_MISSION"
	TaskHardenBinary          TaskType = "HARDEN_BINARY"
	TaskAnalyzeWebPageTaint   TaskType = "ANALYZE_WEB_PAGE_TAINT"
	TaskAnalyzeWebPageProtoPP TaskType = "ANALYZE_WEB_PAGE_PROTOPP"
	TaskAnalyzeArtifacts      TaskType = "ANALYZE_ARTIFACTS"
	TaskTestRaceCondition     TaskType = "TEST_RACE_CONDITION"
	TaskTestAuth              TaskType = "TEST_AUTH"
)

type AnalyzerType string

const (
	TypeActive  AnalyzerType = "Active"
	TypePassive AnalyzerType = "Passive"
	TypeStatic  AnalyzerType = "Static"
	TypeAuth    AnalyzerType = "Auth"
	TypeAgent   AnalyzerType = "Agent"
)

type Analyzer interface {
	Analyze(ctx context.Context, analysisCtx *AnalysisContext) error
	Name() string
	Type() AnalyzerType
}

type GlobalContext struct {
	Config            *config.Config
	Logger            *zap.Logger
	BrowserInteractor browser.BrowserInteractor
	KGClient          KnowledgeGraphClient
	HTTPClient        *http.Client
	PolicyEngine      *tao_policy.Engine
	RemoteInteractor  remote_exec.RemoteInteractor
	Reporter          Reporter // Added Reporter for centralized access
}

type KnowledgeGraphClient interface {
	Ingest(ctx context.Context, updates *schemas.KGUpdates) error
	FindApplicationParameters(ctx context.Context, hostname string) ([]string, error)
	GetGraph() *knowledgegraph.KnowledgeGraph
}

// AnalysisContext holds the state for a specific analysis task.
type AnalysisContext struct {
	Global    *GlobalContext
	Task      schemas.Task
	TargetURL *url.URL
	Logger    *zap.Logger
	Findings  []schemas.Finding
	KGUpdates *schemas.KGUpdates
	Artifacts *browser.Artifacts // Holds collected data (e.g., HTTP responses, requests, storage)
	mu        sync.Mutex
}

// AddFinding adds a schemas.Finding (typically for passive/static analysis).
func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.Findings == nil {
		ac.Findings = []schemas.Finding{}
	}
	ac.Findings = append(ac.Findings, finding)
}

// ReportResult reports an AnalysisResult (typically for active analysis) via the GlobalContext Reporter.
func (ac *AnalysisContext) ReportResult(result AnalysisResult) {
	if ac.Global != nil && ac.Global.Reporter != nil {
		if err := ac.Global.Reporter.Publish(result); err != nil {
			ac.Logger.Error("Failed to publish analysis result", zap.Error(err), zap.String("title", result.Title))
		}
	} else {
		// Fallback if reporter isn't configured (e.g., in tests or specific environments)
		ac.Logger.Warn("Reporter not available in context, cannot publish result.", zap.String("title", result.Title))
	}
}

func (ac *AnalysisContext) AddKGUpdate(update *schemas.KGUpdates) {
	if update == nil {
		return
	}
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.KGUpdates == nil {
		ac.KGUpdates = &schemas.KGUpdates{
			Nodes: []schemas.KGNode{},
			Edges: []schemas.KGEdge{},
		}
	}
	ac.KGUpdates.Nodes = append(ac.KGUpdates.Nodes, update.Nodes...)
	ac.KGUpdates.Edges = append(ac.KGUpdates.Edges, update.Edges...)
}

type BaseAnalyzer struct {
	name string
	typ  AnalyzerType
}

func NewBaseAnalyzer(name string, typ AnalyzerType) BaseAnalyzer {
	return BaseAnalyzer{name: name, typ: typ}
}

func (b *BaseAnalyzer) Name() string {
	return b.name
}

func (b *BaseAnalyzer) Type() AnalyzerType {
	return b.typ
}

func ParseURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, nil
	}
	return url.Parse(rawURL)
}