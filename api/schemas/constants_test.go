package schemas_test

import (
	"fmt"
	"testing"

	// Third party libraries for expressive and robust assertions.
	"github.com/stretchr/testify/assert"

	// Import the package we are testing.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestConstants verifies that all defined constants hold their expected string values.
// This is a good way to prevent accidental changes to values that might be used in APIs.
func TestConstants(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		constant interface{} // Use interface{} to handle various constant types
		expected string
	}{
		// TaskTypes
		{"TaskAgentMission", schemas.TaskAgentMission, "AGENT_MISSION"},
		{"TaskAnalyzeWebPageTaint", schemas.TaskAnalyzeWebPageTaint, "ANALYZE_WEB_PAGE_TAINT"},
		{"TaskAnalyzeHeaders", schemas.TaskAnalyzeHeaders, "ANALYZE_HEADERS"},
		{"TaskAnalyzeJWT", schemas.TaskAnalyzeJWT, "ANALYZE_JWT"},

		// Severities
		{"SeverityCritical", schemas.SeverityCritical, "critical"},
		{"SeverityHigh", schemas.SeverityHigh, "high"},
		{"SeverityInformational", schemas.SeverityInfo, "info"},

		// LLM ModelTiers
		{"TierFast", schemas.TierFast, "fast"},
		{"TierPowerful", schemas.TierPowerful, "powerful"},

		// TaintSinks
		{"SinkEval", schemas.SinkEval, "EVAL"},
		{"SinkFunctionConstructor", schemas.SinkFunctionConstructor, "FUNCTION_CONSTRUCTOR"},
		{"SinkSetTimeout", schemas.SinkSetTimeout, "SET_TIMEOUT"},
		{"SinkSetInterval", schemas.SinkSetInterval, "SET_INTERVAL"},
		{"SinkEventHandler", schemas.SinkEventHandler, "EVENT_HANDLER"},
		{"SinkInnerHTML", schemas.SinkInnerHTML, "INNER_HTML"},
		{"SinkOuterHTML", schemas.SinkOuterHTML, "OUTER_HTML"},
		{"SinkInsertAdjacentHTML", schemas.SinkInsertAdjacentHTML, "INSERT_ADJACENT_HTML"},
		{"SinkDocumentWrite", schemas.SinkDocumentWrite, "DOCUMENT_WRITE"},
		{"SinkScriptSrc", schemas.SinkScriptSrc, "SCRIPT_SRC"},
		{"SinkIframeSrc", schemas.SinkIframeSrc, "IFRAME_SRC"},
		{"SinkIframeSrcDoc", schemas.SinkIframeSrcDoc, "IFRAME_SRCDOC"},
		{"SinkWorkerSrc", schemas.SinkWorkerSrc, "WORKER_SRC"},
		{"SinkEmbedSrc", schemas.SinkEmbedSrc, "EMBED_SRC"},
		{"SinkObjectData", schemas.SinkObjectData, "OBJECT_DATA"},
		{"SinkBaseHref", schemas.SinkBaseHref, "BASE_HREF"},
		{"SinkNavigation", schemas.SinkNavigation, "NAVIGATION"},
		{"SinkFetch", schemas.SinkFetch, "FETCH_BODY"},
		{"SinkFetchURL", schemas.SinkFetchURL, "FETCH_URL"},
		{"SinkXMLHTTPRequest", schemas.SinkXMLHTTPRequest, "XHR_BODY"},
		{"SinkXMLHTTPRequestURL", schemas.SinkXMLHTTPRequestURL, "XHR_URL"},
		{"SinkWebSocketSend", schemas.SinkWebSocketSend, "WEBSOCKET_SEND"},
		{"SinkSendBeacon", schemas.SinkSendBeacon, "SEND_BEACON"},
		{"SinkPostMessage", schemas.SinkPostMessage, "POST_MESSAGE"},
		{"SinkWorkerPostMessage", schemas.SinkWorkerPostMessage, "WORKER_POST_MESSAGE"},
		{"SinkStyleCSS", schemas.SinkStyleCSS, "STYLE_CSS"},
		{"SinkStyleInsertRule", schemas.SinkStyleInsertRule, "STYLE_INSERT_RULE"},
		{"SinkExecution", schemas.SinkExecution, "EXECUTION_PROOF"},
		{"SinkOASTInteraction", schemas.SinkOASTInteraction, "OAST_INTERACTION"},
		{"SinkPrototypePollution", schemas.SinkPrototypePollution, "PROTOTYPE_POLLUTION_CONFIRMED"},
	}

	for _, tc := range testCases {
		// Capture range variable for parallel execution.
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Dynamically resolve the string representation of the constant.
			var actual string
			if stringer, ok := tt.constant.(fmt.Stringer); ok {
				actual = stringer.String()
			} else {
				// Fallback for basic types like string aliases.
				actual = fmt.Sprintf("%v", tt.constant)
			}
			assert.Equal(t, tt.expected, actual)
		})
	}
}
