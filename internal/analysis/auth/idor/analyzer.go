package idor

import (
	"log"
)

// IDORAnalyzer implements the Analyzer interface and contains the logic for detecting IDOR vulnerabilities.
type IDORAnalyzer struct {
	// logger can be used for logging internal state or errors during analysis.
	logger *log.Logger
}

// NewIDORAnalyzer creates and returns a new instance of the IDORAnalyzer.
func NewIDORAnalyzer(logger *log.Logger) Analyzer {
	return &IDORAnalyzer{
		logger: logger,
	}
}

// AnalyzeTraffic is the main entry point for the analysis logic.
func (a *IDORAnalyzer) AnalyzeTraffic(traffic []RequestResponsePair, config Config) ([]Finding, error) {
	if a.logger == nil {
		a.logger = log.Default()
	}
	a.logger.Println("Starting IDOR analysis...")

	if len(traffic) == 0 {
		a.logger.Println("No traffic provided to analyze.")
		return nil, nil
	}

	if config.Session == nil || config.SecondSession == nil || !config.Session.IsAuthenticated() || !config.SecondSession.IsAuthenticated() {
		return nil, &ErrUnauthenticated{}
	}

	findings, err := Detect(traffic, config, a.logger)
	if err != nil {
		a.logger.Printf("An error occurred during IDOR detection: %v", err)
		return nil, err
	}

	a.logger.Printf("IDOR analysis complete. Found %d potential findings.", len(findings))
	return findings, nil
}