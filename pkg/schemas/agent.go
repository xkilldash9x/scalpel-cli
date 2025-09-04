package schemas

// AgentState captures the agent's "thoughts" and what it's currently observing.
// This is used for logging, debugging, and the agent's decision-making loop. It
// represents a single snapshot of the agent's context at a given moment.
type AgentState struct {
	InternalMonologue string `json:"internal_monologue"`
	Observation       string `json:"observation"`
}

// Action represents a single, discrete operation that the agent can perform,
// such as "click" or "type_text". This is the fundamental command unit

// that the agent's "mind" executes in the browser.
type Action struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}