package schemas

// -- Task Schemas --

// TaskType defines the type of task to be executed by a module.
type TaskType string

const (
	TaskAgentMission          TaskType = "AGENT_MISSION"
	TaskAnalyzeWebPageTaint   TaskType = "ANALYZE_WEB_PAGE_TAINT"
	TaskAnalyzeWebPageProtoPP TaskType = "ANALYZE_WEB_PAGE_PROTOPP"
	TaskTestRaceCondition     TaskType = "TEST_RACE_CONDITION"
	TaskTestAuthATO           TaskType = "TEST_AUTH_ATO"
	TaskTestAuthIDOR          TaskType = "TEST_AUTH_IDOR"
	TaskAnalyzeHeaders        TaskType = "ANALYZE_HEADERS"
	TaskAnalyzeJWT            TaskType = "ANALYZE_JWT"
	TaskAnalyzeJSFile         TaskType = "ANALYZE_JS_FILE"
	TaskHumanoidSequence      TaskType = "HUMANOID_SEQUENCE"
)

// Task represents a unit of work to be executed by the engine.
type Task struct {
	TaskID     string      `json:"task_id"`
	ScanID     string      `json:"scan_id"`
	Type       TaskType    `json:"type"`
	TargetURL  string      `json:"target_url"`
	Parameters interface{} `json:"parameters"`
}

// -- Task Parameter Definitions --

// ATOTaskParams defines parameters for the Account Takeover task.
type ATOTaskParams struct {
	Usernames []string `json:"usernames"`
}

// IDORTaskParams defines parameters for the IDOR task.
type IDORTaskParams struct {
	HTTPMethod  string            `json:"http_method"`
	HTTPBody    string            `json:"http_body"`
	HTTPHeaders map[string]string `json:"http_headers"`
}

// JWTTaskParams defines parameters for the JWT analysis task.
type JWTTaskParams struct {
	Token string `json:"token"`
}

// AgentMissionParams defines parameters for the Agent mission task.
type AgentMissionParams struct {
	MissionBrief string `json:"mission_brief"`
}

// JSFileTaskParams defines parameters for the JavaScript file analysis task.
type JSFileTaskParams struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content,omitempty"`
}

// -- Humanoid Task Parameter Definitions --

// HumanoidActionType defines the specific action for a humanoid step.
type HumanoidActionType string

const (
	HumanoidMove     HumanoidActionType = "MOVE"
	HumanoidClick    HumanoidActionType = "CLICK"
	HumanoidDragDrop HumanoidActionType = "DRAG_DROP"
	HumanoidType     HumanoidActionType = "TYPE"
	HumanoidPause    HumanoidActionType = "PAUSE"
)

// HumanoidForceSource defines an attractor or repulsor in the potential field for trajectory deformation.
// This struct is used for serialization within the task definition.
type HumanoidForceSource struct {
	// PositionX and PositionY define the coordinates of the force source.
	PositionX float64 `json:"position_x"`
	PositionY float64 `json:"position_y"`
	// Strength: Positive for attraction, negative for repulsion.
	Strength float64 `json:"strength"`
	// Falloff: Controls the rate of decay (larger means slower decay/wider influence).
	Falloff float64 `json:"falloff"`
}

// HumanoidInteractionOptions provides configuration for humanoid actions.
type HumanoidInteractionOptions struct {
	// EnsureVisible controls automatic scrolling. If nil, defaults to true.
	EnsureVisible *bool `json:"ensure_visible,omitempty"`
	// FieldSources defines the potential field to influence the mouse trajectory.
	FieldSources []HumanoidForceSource `json:"field_sources,omitempty"`
}

// HumanoidStep defines a single action in a humanoid sequence.
type HumanoidStep struct {
	Action      HumanoidActionType          `json:"action"`
	Selector    string                      `json:"selector,omitempty"`
	EndSelector string                      `json:"end_selector,omitempty"`  // For DragDrop
	Text        string                      `json:"text,omitempty"`          // For Type
	MeanScale   float64                     `json:"mean_scale,omitempty"`    // For Pause
	StdDevScale float64                     `json:"std_dev_scale,omitempty"` // For Pause
	Options     *HumanoidInteractionOptions `json:"options,omitempty"`
}

// HumanoidSequenceParams defines parameters for the HUMANOID_SEQUENCE task.
type HumanoidSequenceParams struct {
	Steps []HumanoidStep `json:"steps"`
	// Persona allows overriding the default browser fingerprint for the sequence (Improvement: Flexibility).
	Persona *Persona `json:"persona,omitempty"`
}
