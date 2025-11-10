// internal/worker/adapters/timeslip_adapter.go
package adapters

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/timeslip"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

type TimeslipAdapter struct {
	core.BaseAnalyzer
}

func NewTimeslipAdapter() *TimeslipAdapter {
	return &TimeslipAdapter{
		BaseAnalyzer: *core.NewBaseAnalyzer("TimeslipAdapter_v1", "Performs concurrency analysis to find race conditions.", core.TypeActive, zap.NewNop()),
	}
}

func (a *TimeslipAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))
	logger.Info("Initializing timeslip analysis")

	cfg := analysisCtx.Global.Config.Scanners().Active.TimeSlip
	timeslipConfig := &timeslip.Config{
		Concurrency:        cfg.MaxConcurrency,
		Timeout:            analysisCtx.Global.Config.Engine().DefaultTaskTimeout,
		ThresholdMs:        cfg.ThresholdMs,
		InsecureSkipVerify: analysisCtx.Global.Config.Browser().IgnoreTLSErrors,
	}

	scanID, err := uuid.Parse(analysisCtx.Task.ScanID)
	if err != nil {
		return fmt.Errorf("invalid ScanID format: %w", err)
	}

	analyzer, err := timeslip.NewAnalyzer(
		scanID,
		timeslipConfig,
		logger,
		NewContextReporter(analysisCtx),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize timeslip analyzer: %w", err)
	}

	var params schemas.RaceConditionParams
	if err := remarshalParams(analysisCtx.Task.Parameters, &params); err != nil {
		return fmt.Errorf("invalid parameters for race condition task: %w", err)
	}

	candidate := &timeslip.RaceCandidate{
		URL:     analysisCtx.TargetURL.String(),
		Method:  params.Method,
		Headers: params.Headers,
		Body:    params.Body,
	}

	if err := analyzer.Analyze(ctx, candidate); err != nil {
		if ctx.Err() != nil {
			logger.Warn("Timeslip analysis interrupted or timed out", zap.Error(err))
			return nil // An interrupt isn't a failure of the adapter itself.
		}
		return fmt.Errorf("timeslip analysis failed during execution: %w", err)
	}

	logger.Info("Timeslip analysis execution completed")
	return nil
}
