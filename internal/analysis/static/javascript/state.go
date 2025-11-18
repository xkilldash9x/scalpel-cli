// Filename: javascript/state.go
// Defines the abstract state model for tracking taint, including object sensitivity (Level 2)
// and function summaries for inter-procedural analysis (Level 3).
package javascript

import (
	"sort"
	"strings"
	"sync"
)

// TaintState represents the abstract taint status of a variable or property.
type TaintState interface {
	IsTainted() bool
	// GetSource returns a representative origin of the taint (for reporting).
	GetSource() TaintSource
	// GetSources returns the set of all taint origins.
	GetSources() map[TaintSource]bool
	// Merge combines this state with another TaintState (the lattice join operation).
	Merge(other TaintState) TaintState
}

// -- Simple Taint (Level 2) with Multi-Source Tracking --

// SimpleTaint represents a tainted primitive value or a value where structure is unknown.
// It is the Least Upper Bound (LUB) of SimpleTaint and ObjectTaint.
type SimpleTaint struct {
	// Sources is a set of origins for the taint.
	Sources map[TaintSource]bool
	// Line tracking represents the location of the earliest introduced source.
	Line int
}

// NewSimpleTaint creates a new SimpleTaint record.
func NewSimpleTaint(source TaintSource, line int) SimpleTaint {
	// If source is explicitly empty, return an untainted record.
	if source == "" {
		return SimpleTaint{}
	}
	return SimpleTaint{
		Sources: map[TaintSource]bool{source: true},
		Line:    line,
	}
}

func (t SimpleTaint) IsTainted() bool {
	return len(t.Sources) > 0
}

// GetSource returns a representative source string for reporting.
func (t SimpleTaint) GetSource() TaintSource {
	if !t.IsTainted() {
		return ""
	}

	// If only one source exists, return it.
	if len(t.Sources) == 1 {
		for s := range t.Sources {
			return s
		}
	}

	// If multiple sources exist, return a deterministic, joined string.
	sources := make([]string, 0, len(t.Sources))
	for s := range t.Sources {
		sources = append(sources, string(s))
	}
	sort.Strings(sources)
	return TaintSource(strings.Join(sources, "|"))
}

func (t SimpleTaint) GetSources() map[TaintSource]bool {
	return t.Sources
}

// Merge combines this state with another TaintState. (Lattice Join Operation)
func (t SimpleTaint) Merge(other TaintState) TaintState {
	if other == nil || !other.IsTainted() {
		return t
	}

	// Fix for Logic Bug: If the current state is NOT tainted, we must adopt the incoming taint.
	if !t.IsTainted() {
		return other
	}

	// Both are tainted. We need to merge the sources.

	// We extract sources from the other state, regardless of its underlying type (Simple or Object).
	otherSources := other.GetSources()
	var otherLine int

	// Try to get the line number if it's a SimpleTaint for better tracking.
	if otherSimple, ok := other.(SimpleTaint); ok {
		otherLine = otherSimple.Line
	}

	// Check if the other state adds new sources or an earlier line number (optimization).
	needsMerge := false
	if otherLine > 0 && (t.Line == 0 || otherLine < t.Line) {
		needsMerge = true
	}
	if !needsMerge {
		for source := range otherSources {
			if !t.Sources[source] {
				needsMerge = true
				break
			}
		}
	}

	if !needsMerge {
		return t
	}

	// Perform the actual merge by creating a new state.
	return t.mergeSources(otherSources, otherLine)
}

// mergeSources creates a new SimpleTaint by merging the provided sources and line number.
func (t SimpleTaint) mergeSources(otherSources map[TaintSource]bool, otherLine int) SimpleTaint {
	merged := t.clone()
	for source := range otherSources {
		merged.Sources[source] = true
	}

	// Approximate the line number (keep the earliest introduction).
	if otherLine > 0 && (merged.Line == 0 || otherLine < merged.Line) {
		merged.Line = otherLine
	}
	return merged
}

// Helper to clone the SimpleTaint (for functional state updates).
func (t SimpleTaint) clone() SimpleTaint {
	newSources := make(map[TaintSource]bool, len(t.Sources))
	for k, v := range t.Sources {
		newSources[k] = v
	}
	return SimpleTaint{Sources: newSources, Line: t.Line}
}

// -- Object Taint (Level 2) --

// ObjectTaint represents an object or array where specific properties/indices might be tainted.
type ObjectTaint struct {
	// Maps property names (strings) to their taint state.
	Properties map[string]TaintState
	// If true, indicates that we lost precision (e.g., computed property assignment),
	// so the entire object should be considered tainted.
	StructureTainted bool
}

// NewObjectTaint initializes an empty ObjectTaint structure.
func NewObjectTaint() *ObjectTaint {
	return &ObjectTaint{
		Properties: make(map[string]TaintState),
	}
}

// IsTainted returns true if any property or the structure itself is tainted.
func (t *ObjectTaint) IsTainted() bool {
	if t.StructureTainted {
		return true
	}
	// We must check the actual taint status of properties.
	for _, state := range t.Properties {
		if state != nil && state.IsTainted() {
			return true
		}
	}
	return false
}

// GetSource returns a generic source marker as an object doesn't have a single origin.
func (t *ObjectTaint) GetSource() TaintSource {
	if t.IsTainted() {
		// For reporting, we can rely on GetSources() if needed, but often SourceUnknown is sufficient for objects.
		return SourceUnknown
	}
	return ""
}

// GetSources returns the union of sources from all properties.
func (t *ObjectTaint) GetSources() map[TaintSource]bool {
	sources := make(map[TaintSource]bool)
	if t.StructureTainted {
		sources[SourceUnknown] = true
	}

	for _, state := range t.Properties {
		if state != nil && state.IsTainted() {
			for s := range state.GetSources() {
				sources[s] = true
			}
		}
	}
	return sources
}

// GetPropertyTaint retrieves the taint state of a specific property.
func (t *ObjectTaint) GetPropertyTaint(propName string) TaintState {
	if state, ok := t.Properties[propName]; ok && state != nil && state.IsTainted() {
		return state
	}
	// If the specific property isn't tracked, but the structure is generally tainted, return a generic taint.
	if t.StructureTainted {
		// Line 0 indicates unknown origin line within the structure.
		return NewSimpleTaint(SourceUnknown, 0)
	}
	return nil
}

// SetPropertyTaint sets the taint state of a specific property.
func (t *ObjectTaint) SetPropertyTaint(propName string, state TaintState) {
	if state == nil || !state.IsTainted() {
		delete(t.Properties, propName)
	} else {
		t.Properties[propName] = state
	}
}

// Merge combines two ObjectTaint states or merges a SimpleTaint into an ObjectTaint.
func (t *ObjectTaint) Merge(other TaintState) TaintState {
	if other == nil || !other.IsTainted() {
		return t
	}

	if otherObj, ok := other.(*ObjectTaint); ok {
		// Merging two objects: combine properties (Union).
		// We create a new object to maintain functional state principles where possible.
		merged := NewObjectTaint()
		merged.StructureTainted = t.StructureTainted || otherObj.StructureTainted

		// Copy current properties
		for k, v := range t.Properties {
			merged.Properties[k] = v
		}

		// Merge other properties
		for k, v := range otherObj.Properties {
			if existing, exists := merged.Properties[k]; exists {
				merged.Properties[k] = existing.Merge(v)
			} else {
				merged.Properties[k] = v
			}
		}
		return merged
	}

	// Merging with SimpleTaint (or other non-ObjectTaint).
	// Since SimpleTaint is the LUB (ObjectTaint <= SimpleTaint), the result is SimpleTaint.
	// We rely on the commutative property: t.Merge(other) == other.Merge(t).
	return other.Merge(t)
}

// -- Function Summary (Level 3) --

// RefID is a unique identifier for function tracking.
type RefID string

// FunctionSummary describes the taint behavior of a function.
type FunctionSummary struct {
	// RefID is the unique identifier for the function declaration.
	RefID RefID

	// TaintsReturn indicates if the function returns tainted data derived from a global source.
	TaintsReturn bool

	// TaintedParams maps the index of a parameter to whether it flows to a sink within the function.
	TaintedParams map[int]bool

	// ParamToReturn maps the index of a parameter to whether it flows to the return value.
	ParamToReturn map[int]bool
}

// NewFunctionSummary initializes a summary for a given function reference.
func NewFunctionSummary(id RefID) *FunctionSummary {
	return &FunctionSummary{
		RefID:         id,
		TaintedParams: make(map[int]bool),
		ParamToReturn: make(map[int]bool),
	}
}

// AnalyzerContext holds the state required across different passes of the analysis (IPA).
type AnalyzerContext struct {
	// Maps function identifiers to their computed summaries.
	Summaries map[RefID]*FunctionSummary

	// Findings discovered during the summarization phase (intra-procedural).
	intraProceduralFindings []StaticFinding

	// Mutex to protect access to shared structures, enabling potential parallelization of analysis.
	mu sync.Mutex
}

// NewAnalyzerContext creates a new context for multi-pass analysis.
func NewAnalyzerContext() *AnalyzerContext {
	return &AnalyzerContext{
		Summaries:               make(map[RefID]*FunctionSummary),
		intraProceduralFindings: []StaticFinding{},
	}
}

// AddIntraProceduralFinding safely adds a finding discovered during the summarization phase.
func (ac *AnalyzerContext) AddIntraProceduralFinding(finding StaticFinding) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.intraProceduralFindings = append(ac.intraProceduralFindings, finding)
}

// GetIntraProceduralFindings returns the findings collected during summarization.
func (ac *AnalyzerContext) GetIntraProceduralFindings() []StaticFinding {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	// Return a copy to prevent modification by the caller after analysis completes.
	findings := make([]StaticFinding, len(ac.intraProceduralFindings))
	copy(findings, ac.intraProceduralFindings)
	return findings
}
