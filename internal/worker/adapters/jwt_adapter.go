// internal/worker/adapters/jwt_adapter.go
package adapters

import (
	"context"
	"fmt"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/static/jwt"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

type JWTAdapter struct {
	core.BaseAnalyzer
}

func NewJWTAdapter() *JWTAdapter {
	return &JWTAdapter{
		BaseAnalyzer: core.NewBaseAnalyzer("JWT Adapter", core.TypeStatic),
	}
}

func (a *JWTAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Starting JWT static analysis via adapter.")

	// CORRECTED: Use robust type assertion.
	var params schemas.JWTTaskParams
	switch p := analysisCtx.Task.Parameters.(type) {
	case schemas.JWTTaskParams:
		params = p
	case *schemas.JWTTaskParams:
		if p == nil {
			return fmt.Errorf("invalid parameters: nil pointer for JWT task")
		}
		params = *p
	default:
		return fmt.Errorf("invalid parameters type for JWT task; expected schemas.JWTTaskParams or *schemas.JWTTaskParams, got %T", analysisCtx.Task.Parameters)
	}

	analyzer := jwt.NewAnalyzer(analysisCtx.Global.Config.Scanners.Static.JWT)
	findings, err := analyzer.Analyze(params.Token)
	if err != nil {
		return fmt.Errorf("JWT analysis logic failed: %w", err)
	}

	for _, finding := range findings {
		analysisCtx.AddFinding(finding) // The analyzer now creates the full finding object
	}

	return nil
}
