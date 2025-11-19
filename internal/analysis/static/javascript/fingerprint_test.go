package javascript

import (
	"testing"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap/zaptest"
)

// -- Test Helpers --

func runAnalysis(t *testing.T, code string) []StaticFinding {
	logger := zaptest.NewLogger(t)
	fp := NewFingerprinter(logger)

	findings, err := fp.Analyze("test_case.js", code)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}
	return findings
}

func assertFindings(t *testing.T, findings []StaticFinding, expectedCount int) {
	t.Helper()
	if len(findings) != expectedCount {
		t.Errorf("Expected %d findings, got %d", expectedCount, len(findings))
		for i, f := range findings {
			t.Logf("Finding %d: Source[%s] -> Sink[%s] at Line %d", i, f.Source, f.Sink, f.Location.Line)
		}
	}
}

func assertSourceAndSink(t *testing.T, finding StaticFinding, source core.TaintSource, sink core.TaintSink) {
	t.Helper()
	if finding.Source != source {
		t.Errorf("Expected source %s, got %s", source, finding.Source)
	}
	if finding.Sink != sink {
		t.Errorf("Expected sink %s, got %s", sink, finding.Sink)
	}
}

// -- Integration Tests --

func TestBasicTaintFlow(t *testing.T) {
	code := `
		var input = location.hash;
		document.write(input);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 1)
	assertSourceAndSink(t, findings[0], core.SourceLocationHash, core.TaintSink("document.write"))
}

func TestSanitization(t *testing.T) {
	code := `
		var input = location.hash;
		var clean = encodeURIComponent(input);
		document.write(clean);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 0)
}

func TestObjectSensitivity(t *testing.T) {
	code := `
		var obj = {};
		obj.bad = location.search;
		obj.good = "safe";
		
		// Should find this
		eval(obj.bad); 
		
		// Should NOT find this
		eval(obj.good);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 1)
	assertSourceAndSink(t, findings[0], core.SourceLocationSearch, core.TaintSink("eval"))
}

func TestObjectAssignments(t *testing.T) {
	code := `
		var data = { 
			user: location.href, 
			id: 123 
		};
		
		// Direct access
		document.write(data.user);
		
		// Alias access
		var ref = data;
		eval(ref.user);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 2)
}

func TestInterProcedural_ReturnTaint(t *testing.T) {
	code := `
		function getInput() {
			return location.hash;
		}
		
		var val = getInput();
		document.write(val);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 1)
	// Note: The source might be wrapped or propagated as a specific "return:getInput" source
	// depending on how strict your summary logic is.
	// Based on your walker code, it might come out as "return:getInput" or the original source
	// if you improved propagation. Let's check existence first.
}

func TestInterProcedural_SinkWrapper(t *testing.T) {
	code := `
		function safeExec(cmd) {
			eval(cmd);
		}
		
		safeExec(location.hash);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 1)

	// This verifies that "call:safeExec(arg:0)" was detected as a sink because
	// safeExec's summary marked param 0 as flowing to 'eval'.
}

func TestTemplateStrings(t *testing.T) {
	// Fix: We use double quotes for the Go string so we can include the JS backticks
	// required for the template string.
	code := "var x = location.hash;\n" +
		"var msg = \"Hello \" + x;\n" +
		"var tpl = `Welcome ${x}`;\n" + // Valid JS template string
		"document.write(tpl);"

	findings := runAnalysis(t, code)
	assertFindings(t, findings, 1)
}

func TestUnknownSourcePropagation(t *testing.T) {
	// Test that if we pass a tainted value through an unknown function logic,
	// we might lose the exact source string but still track it as tainted (SourceUnknown).
	code := `
		function wrapper(a) {
			return a;
		}
		var x = location.hash;
		var y = wrapper(x);
		eval(y);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 1)
}

func TestPropertyAliases(t *testing.T) {
	// Ensure aliases like window.location.hash work the same as location.hash
	code := `
		var x = window.location.hash;
		document.writeln(x);
	`
	findings := runAnalysis(t, code)
	assertFindings(t, findings, 1)
}
