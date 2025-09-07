package schemas

import "net/http"

// This file defines the specific parameter structures for each task type.

type AgentMissionParams struct {
	MissionBrief string `json:"mission_brief"`
}

type TaintTaskParams struct {
	InteractionDepth int    `json:"interaction_depth"`
	FocusSelector    string `json:"focus_selector,omitempty"`
}

type ProtoPollutionTaskParams struct{}

type ATOTaskParams struct {
	Usernames    []string `json:"usernames"`
	PasswordList []string `json:"password_list,omitempty"`
}

type IDORTaskParams struct {
	HTTPMethod  string      `json:"http_method"`
	HTTPBody    []byte      `json:"http_body,omitempty"`
	HTTPHeaders http.Header `json:"http_headers"`
}

type JWTTaskParams struct {
	Token             string `json:"token"`
	BruteForceEnabled bool   `json:"brute_force_enabled"`
}

type RaceConditionTaskParams struct {
	HTTPMethod  string `json:"http_method"`
	HTTPBody    []byte `json:"http_body,omitempty"`
	Concurrency int    `json:"concurrency"`
}

type HeadersTaskParams struct{}