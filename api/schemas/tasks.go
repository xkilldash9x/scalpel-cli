package schemas

// -- Task Schemas --

// TaskType is an enumeration of the different types of analysis tasks that can
// be performed by the scanning engine.
type TaskType string

const (
	TaskAgentMission          TaskType = "AGENT_MISSION"            // A high-level mission for the autonomous agent.
	TaskAnalyzeWebPageTaint   TaskType = "ANALYZE_WEB_PAGE_TAINT"   // Performs taint analysis on a web page.
	TaskAnalyzeWebPageProtoPP TaskType = "ANALYZE_WEB_PAGE_PROTOPP" // Checks for prototype pollution vulnerabilities.
	TaskTestRaceCondition     TaskType = "TEST_RACE_CONDITION"      // Tests for race conditions in web applications.
	TaskTestAuthATO           TaskType = "TEST_AUTH_ATO"            // Tests for account takeover vulnerabilities.
	TaskTestAuthIDOR          TaskType = "TEST_AUTH_IDOR"           // Tests for Insecure Direct Object References.
	TaskAnalyzeHeaders        TaskType = "ANALYZE_HEADERS"          // Analyzes HTTP security headers.
	TaskAnalyzeJWT            TaskType = "ANALYZE_JWT"              // Analyzes JSON Web Tokens for vulnerabilities.
	TaskAnalyzeJSFile         TaskType = "ANALYZE_JS_FILE"          // Performs static analysis on a JavaScript file.
	TaskHumanoidSequence      TaskType = "HUMANOID_SEQUENCE"        // Executes a sequence of human-like browser interactions.
)

// Task represents a single, self-contained unit of work to be processed by a
// worker in the task engine. It includes a unique ID, the type of task, the
// target, and any specific parameters required for its execution.
type Task struct {
	TaskID     string      `json:"task_id"`    // A unique identifier for this specific task instance.
	ScanID     string      `json:"scan_id"`    // The ID of the parent scan this task belongs to.
	Type       TaskType    `json:"type"`       // The type of the task, which determines which worker will handle it.
	TargetURL  string      `json:"target_url"` // The primary URL or resource target for the task.
	Parameters interface{} `json:"parameters"` // A flexible field for task-specific parameters.
}

// -- Task Parameter Definitions --

// ATOTaskParams provides the specific parameters required for an Account
// Takeover (ATO) analysis task.
type ATOTaskParams struct {
	Usernames []string `json:"usernames"` // A list of usernames to test for vulnerabilities like password spraying.
}

// IDORTaskParams provides the parameters for an Insecure Direct Object Reference
// (IDOR) testing task.
type IDORTaskParams struct {
	HTTPMethod  string            `json:"http_method"`  // The HTTP method to use for the request.
	HTTPBody    string            `json:"http_body"`    // The request body.
	HTTPHeaders map[string]string `json:"http_headers"` // The request headers.
}

// JWTTaskParams provides the parameters for a JSON Web Token analysis task.
type JWTTaskParams struct {
	Token string `json:"token"` // The JWT token to be analyzed.
}

// AgentMissionParams provides the parameters for a high-level agent mission.
type AgentMissionParams struct {
	MissionBrief string `json:"mission_brief"` // The high-level objective for the agent to achieve.
}

// JSFileTaskParams provides the parameters for a JavaScript file analysis task.
type JSFileTaskParams struct {
	FilePath string `json:"file_path"`         // The path or URL of the JavaScript file.
	Content  string `json:"content,omitempty"` // The content of the file, if already available.
}

// RaceConditionParams defines parameters for the Race Condition task.
type RaceConditionParams struct {
	Method  string              `json:"method"`
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}

// -- Humanoid Task Parameter Definitions --

// HumanoidActionType defines the type of a single action within a human-like
// interaction sequence.
type HumanoidActionType string

const (
	HumanoidMove     HumanoidActionType = "MOVE"      // Moves the mouse to a target.
	HumanoidClick    HumanoidActionType = "CLICK"     // Clicks the mouse.
	HumanoidDragDrop HumanoidActionType = "DRAG_DROP" // Drags an element from a start to an end point.
	HumanoidType     HumanoidActionType = "TYPE"      // Types text using the keyboard.
	HumanoidPause    HumanoidActionType = "PAUSE"     // Pauses for a human-like duration.
)

// HumanoidForceSource represents a point of attraction or repulsion in a
// potential field, used to create more realistic, curved mouse movement instead
// of straight lines.
type HumanoidForceSource struct {
	PositionX float64 `json:"position_x"` // The x-coordinate of the force's origin.
	PositionY float64 `json:"position_y"` // The y-coordinate of the force's origin.
	Strength  float64 `json:"strength"`   // The strength of the force (positive for attraction, negative for repulsion).
	Falloff   float64 `json:"falloff"`    // The rate at which the force's influence decays with distance.
}

// HumanoidInteractionOptions provides advanced configuration for a humanoid
// action, such as controlling automatic scrolling or defining a potential field
// to influence mouse trajectories.
type HumanoidInteractionOptions struct {
	// EnsureVisible, if true, will automatically scroll the element into view. Defaults to true.
	EnsureVisible *bool `json:"ensure_visible,omitempty"`
	// FieldSources defines a set of attractors/repulsors to create a potential field for mouse movement.
	FieldSources []HumanoidForceSource `json:"field_sources,omitempty"`
}

// HumanoidStep represents a single, discrete action in a sequence of human-like
// interactions.
type HumanoidStep struct {
	Action      HumanoidActionType          `json:"action"`                  // The type of action to perform.
	Selector    string                      `json:"selector,omitempty"`      // The CSS selector for the target element.
	EndSelector string                      `json:"end_selector,omitempty"`  // For DragDrop actions, the destination selector.
	Text        string                      `json:"text,omitempty"`          // For Type actions, the text to be typed.
	MeanScale   float64                     `json:"mean_scale,omitempty"`    // For Pause actions, scales the mean pause duration.
	StdDevScale float64                     `json:"std_dev_scale,omitempty"` // For Pause actions, scales the standard deviation of the pause duration.
	Options     *HumanoidInteractionOptions `json:"options,omitempty"`       // Advanced options for this specific step.
}

// HumanoidSequenceParams defines the complete set of parameters for a
// HUMANOID_SEQUENCE task, including the steps to execute and an optional custom
// browser persona.
type HumanoidSequenceParams struct {
	Steps []HumanoidStep `json:"steps"`
	// Persona allows overriding the default browser fingerprint for this sequence,
	// enabling more flexible and realistic emulation.
	Persona *Persona `json:"persona,omitempty"`
}
