// Filename: javascript/state_test.go
package javascript

import (
	"strings"
	"testing"
)

// -- State Unit Tests --

// TestSimpleTaint_Merge verifies the lattice join operation for SimpleTaint.
func TestSimpleTaint_Merge(t *testing.T) {
	t.Parallel()

	clean := NewSimpleTaint("", 0)
	// Use sources that guarantee a specific sort order for deterministic checks.
	sourceA := TaintSource("source_A") // Sorts first
	sourceB := TaintSource("source_B")
	taintedA := NewSimpleTaint(sourceA, 10)
	taintedB := NewSimpleTaint(sourceB, 20)

	// 1. Clean + Tainted = Tainted (Identity element)
	res1 := clean.Merge(taintedA)
	if !res1.IsTainted() || res1.GetSource() != sourceA {
		t.Errorf("Expected clean merged with tainted A to be %s, got %s", sourceA, res1.GetSource())
	}

	// 2. Tainted + Clean = Tainted (Commutative property check with identity)
	res2 := taintedA.Merge(clean)
	if !res2.IsTainted() || res2.GetSource() != sourceA {
		t.Errorf("Expected tainted A merged with clean to be %s, got %s", sourceA, res2.GetSource())
	}

	// 3. TaintedA + TaintedB = Tainted(A union B)
	// Fix for Failure D: The expectation should be a union of sources (Lattice Join), not preference/overwrite.
	res3 := taintedA.Merge(taintedB)
	if !res3.IsTainted() {
		t.Fatal("Expected merge of two tainted states to be tainted")
	}

	// Verify union of sources. GetSource() returns a sorted, joined string.
	expectedUnion := TaintSource("source_A|source_B")
	if res3.GetSource() != expectedUnion {
		t.Errorf("Expected union of sources %s, got %s", expectedUnion, res3.GetSource())
	}

	// 4. Verify Line Number Approximation (Earliest introduction wins)
	if simpleRes, ok := res3.(SimpleTaint); ok {
		if simpleRes.Line != 10 {
			t.Errorf("Expected earliest line number 10 (from taintedA), got %d", simpleRes.Line)
		}
	}

	// 5. Check commutativity
	res4 := taintedB.Merge(taintedA)
	if res4.GetSource() != expectedUnion {
		t.Errorf("Merge should be commutative. Expected %s, got %s", expectedUnion, res4.GetSource())
	}
}

func TestObjectTaint_PropertyTracking(t *testing.T) {
	t.Parallel()

	obj := NewObjectTaint()
	taintVal := NewSimpleTaint(SourceLocationHash, 1)

	// 1. Set and Get Property
	obj.SetPropertyTaint("dangerous", taintVal)

	if !obj.GetPropertyTaint("dangerous").IsTainted() {
		t.Error("Property 'dangerous' should be tainted")
	}
	if obj.GetPropertyTaint("safe") != nil {
		t.Error("Property 'safe' should be nil")
	}

	// 2. Structure Taint (Loss of precision)
	obj.StructureTainted = true
	if !obj.GetPropertyTaint("random_prop").IsTainted() {
		t.Error("Random property should be tainted if structure is tainted")
	}
}

func TestObjectTaint_Merge(t *testing.T) {
	t.Parallel()

	// Obj1: { a: tainted(Hash) }
	obj1 := NewObjectTaint()
	obj1.SetPropertyTaint("a", NewSimpleTaint(SourceLocationHash, 1))

	// Obj2: { b: tainted(Cookie), a: tainted(Search) }
	obj2 := NewObjectTaint()
	obj2.SetPropertyTaint("b", NewSimpleTaint(SourceDocumentCookie, 2))
	obj2.SetPropertyTaint("a", NewSimpleTaint(SourceLocationSearch, 3))

	// Merge
	mergedState := obj1.Merge(obj2)
	mergedObj, ok := mergedState.(*ObjectTaint)

	if !ok {
		t.Fatal("Result of object merge should be ObjectTaint")
	}

	// Verify Union of properties
	if !mergedObj.GetPropertyTaint("b").IsTainted() {
		t.Error("Merged object lost taint for property 'b'")
	}

	// Verify merge of existing property 'a' (Union of sources for that property)
	taintA := mergedObj.GetPropertyTaint("a")
	if !taintA.IsTainted() {
		t.Fatal("Merged object lost taint for property 'a'")
	}
	sourceA := string(taintA.GetSource())
	if !strings.Contains(sourceA, string(SourceLocationHash)) || !strings.Contains(sourceA, string(SourceLocationSearch)) {
		t.Errorf("Expected union of sources for property 'a', got %s", sourceA)
	}
}

// TestState_TypeMixing verifies the behavior when merging different TaintState types.
func TestState_TypeMixing(t *testing.T) {
	t.Parallel()

	// Fix for Failure C: Update test expectation for Merge operation.
	// Context: This tests the Lattice Join operation, NOT assignment.
	// SimpleTaint is the Least Upper Bound (LUB) over ObjectTaint.
	// Merging ObjectTaint with SimpleTaint results in SimpleTaint containing the union of all sources.
	// (Simulating: if (c) { x = {a: sourceA} } else { x = sourceB })

	// Use sources that guarantee a specific sort order.
	sourceA := TaintSource("source_A")
	sourceB := TaintSource("source_B")

	// Obj: { a: tainted(A) }
	obj := NewObjectTaint()
	obj.SetPropertyTaint("a", NewSimpleTaint(sourceA, 1))

	// Simple: tainted(B)
	simple := NewSimpleTaint(sourceB, 2)

	// Merge: Obj Join Simple
	res := obj.Merge(simple)

	// 1. Result Type Check
	if _, ok := res.(SimpleTaint); !ok {
		t.Error("Merging SimpleTaint and ObjectTaint should result in SimpleTaint (LUB)")
	}

	// 2. Source Check (Union)
	// The resulting SimpleTaint must include sources from the Object and the original SimpleTaint.
	expectedSource := TaintSource("source_A|source_B")
	if res.GetSource() != expectedSource {
		t.Errorf("Result should be the union of sources. Expected %s, got %s", expectedSource, res.GetSource())
	}

	// 3. Commutative Check: Simple Join Obj
	resCommutative := simple.Merge(obj)
	if resCommutative.GetSource() != expectedSource {
		t.Error("Merge operation should be commutative")
	}
}
