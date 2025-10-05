package stealth

import (
    "context"
    "encoding/json"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/xkilldash9x/scalpel-cli/api/schemas"
    "go.uber.org/zap"
    "go.uber.org/zap/zaptest/observer"
)

// MockSessionContext to satisfy the interface requirement (minimal implementation).
// We must implement all methods defined in schemas.SessionContext.
type MockSessionContext struct{}

func (m *MockSessionContext) ID() string { return "mock" }
func (m *MockSessionContext) Navigate(ctx context.Context, url string) error { return nil }
func (m *MockSessionContext) Click(ctx context.Context, selector string) error { return nil }
func (m *MockSessionContext) Type(ctx context.Context, selector string, text string) error { return nil }
func (m *MockSessionContext) Submit(ctx context.Context, selector string) error { return nil }
func (m *MockSessionContext) ScrollPage(ctx context.Context, direction string) error { return nil }
func (m *MockSessionContext) WaitForAsync(ctx context.Context, milliseconds int) error { return nil }
func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error { return nil }
func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error { return nil }
func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error { return nil }
func (m *MockSessionContext) Close(ctx context.Context) error { return nil }
func (m *MockSessionContext) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) { return nil, nil }
func (m *MockSessionContext) AddFinding(ctx context.Context, finding schemas.Finding) error { return nil }
func (m *MockSessionContext) Sleep(ctx context.Context, d time.Duration) error { return nil }
func (m *MockSessionContext) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error { return nil }
func (m *MockSessionContext) SendKeys(ctx context.Context, keys string) error { return nil }
func (m *MockSessionContext) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) { return nil, nil }
func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) { return nil, nil }


func TestApplyEvasions(t *testing.T) {
    ctx := context.Background()
    mockSession := &MockSessionContext{}
    persona := schemas.DefaultPersona

    t.Run("Logging with Non-Empty EvasionsJS", func(t *testing.T) {
        // Setup logger observer
        core, observedLogs := observer.New(zap.DebugLevel)
        logger := zap.New(core)

        // Temporarily ensure EvasionsJS is not empty (White-box testing access)
        originalEvasionsJS := EvasionsJS
        EvasionsJS = "some script"
        defer func() { EvasionsJS = originalEvasionsJS }()

        err := ApplyEvasions(ctx, mockSession, persona, logger)
        assert.NoError(t, err)

        // Assert logs
        logs := observedLogs.All()
        require.Len(t, logs, 2)
        assert.Contains(t, logs[0].Message, "Applying stealth configuration (Pure Go mode).")
        assert.Contains(t, logs[1].Message, "Note: EvasionsJS (navigator spoofing) is skipped")
    })

    t.Run("Logging with Empty EvasionsJS", func(t *testing.T) {
        core, observedLogs := observer.New(zap.DebugLevel)
        logger := zap.New(core)

        // Temporarily ensure EvasionsJS is empty
        originalEvasionsJS := EvasionsJS
        EvasionsJS = ""
        defer func() { EvasionsJS = originalEvasionsJS }()

        err := ApplyEvasions(ctx, mockSession, persona, logger)
        assert.NoError(t, err)

        // Assert logs - the skip message should not appear
        logs := observedLogs.All()
        require.Len(t, logs, 1)
        assert.Contains(t, logs[0].Message, "Applying stealth configuration (Pure Go mode).")
    })

    t.Run("Nil Logger", func(t *testing.T) {
        // Ensure it doesn't panic if the logger is nil.
        assert.NotPanics(t, func() {
            err := ApplyEvasions(ctx, mockSession, persona, nil)
            assert.NoError(t, err)
        })
    })
}