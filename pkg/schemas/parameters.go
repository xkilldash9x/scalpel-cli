// -- pkg/schemas/parameters.go --
package schemas

import "net/http"

// This file defines the specific parameter structures for each task type.
// Using distinct structs provides compile-time type safety and code clarity.

// AgentMissionParams defines the parameters for a TaskAgentMission.
type AgentMissionParams struct {
	MissionBrief string `json:"mission_brief"`
}

// TaintTaskParams defines the parameters for a TaskAnalyzeWebPageTaint.
type TaintTaskParams struct {
	// The depth of interaction for the humanoid crawler.
	InteractionDepth int `json:"interaction_depth"`
	// Specifies a particular area or form on the page to focus the analysis.
	FocusSelector string `json:"focus_selector,omitempty"`
}

// ProtoPollutionTaskParams defines parameters for a TaskAnalyzeWebPageProtoPP.
// Currently, this task type requires no special parameters beyond the TargetURL.
type ProtoPollutionTaskParams struct{}

// ATOTaskParams defines the parameters for a TaskTestAuthATO.
type ATOTaskParams struct {
	// A list of known usernames to use in password spraying attacks.
	Usernames []string `json:"usernames"`
	// A specific list of passwords to try; if empty, a default list is used.
	PasswordList []string `json:"password_list,omitempty"`
}

// IDORTaskParams defines the parameters for a TaskTestAuthIDOR.
// This requires a full HTTP request context to replay with modified identifiers.
type IDORTaskParams struct {
	// The HTTP method of the request to be tested (e.g., "GET", "POST").
	HTTPMethod string `json:"http_method"`
	// The request body, if any.
	HTTPBody []byte `json:"http_body,omitempty"`
	// A map of HTTP headers representing an authenticated session.
	// http.Header correctly handles multiple values per key.
	HTTPHeaders http.Header `json:"http_headers"`
}

// JWTTaskParams defines the parameters for a TaskAnalyzeJWT.
type JWTTaskParams struct {
	// The JWT string to be analyzed.
	Token string `json:"token"`
	// Whether to attempt a brute-force attack on the signature.
	BruteForceEnabled bool `json:"brute_force_enabled"`
}

// RaceConditionTaskParams defines the parameters for a TaskTestRaceCondition.
type RaceConditionTaskParams struct {
	// The HTTP method of the request to be tested.
	HTTPMethod string `json:"http_method"`
	// The request body.
	HTTPBody []byte `json:"http_body,omitempty"`
	// The number of concurrent requests to send.
	Concurrency int `json:"concurrency"`
}

// HeadersTaskParams defines parameters for a TaskAnalyzeHeaders.
// This is a passive task and requires no special parameters.
type HeadersTaskParams struct{}