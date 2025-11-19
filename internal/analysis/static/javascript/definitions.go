// Filename: javascript/definitions.go
package javascript

import (
	"strings"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// StaticSinkDefinition maps the core definition to the walker's needs.
// We keep this struct here to maintain the walker's independence and support specific logic like TaintedArgs.
type StaticSinkDefinition struct {
	Name          core.TaintSink
	Type          core.SinkType
	CanonicalType schemas.TaintSink
	TaintedArgs   []int
}

// Global maps used by the Walker (walker.go)
var (
	knownSinkFunctions     = make(map[string]StaticSinkDefinition)
	knownSinkPropertyPaths = make(map[string]StaticSinkDefinition)
)

func init() {
	// Iterate over the centralized sink list from Core
	for _, sink := range core.DefaultSinks() {

		// 1. Map Canonical Type (IAST) to Static Type (SAST)
		sinkType := core.GetSinkType(sink.Type)

		// 2. Construct the base definition
		// Note: We intentionally do not set Name here yet; we set it based on the map key below.
		baseDef := StaticSinkDefinition{
			Type:          sinkType,
			CanonicalType: sink.Type,
			TaintedArgs:   []int{sink.ArgIndex},
		}

		parts := strings.Split(sink.Name, ".")
		staticName := parts[len(parts)-1]

		if sink.Setter {
			// -- Property Sinks (e.g. innerHTML, href) --

			// Map Full Path (Priority): "Element.prototype.innerHTML" -> Name: "Element.prototype.innerHTML"
			fullDef := baseDef
			fullDef.Name = core.TaintSink(sink.Name)
			knownSinkPropertyPaths[sink.Name] = fullDef

			// Map Static Name (Fallback): "innerHTML" -> Name: "innerHTML"
			if sink.Name != staticName {
				fallbackDef := baseDef
				fallbackDef.Name = core.TaintSink(staticName)

				// Only register fallback if it doesn't conflict or we want to merge?
				// For properties, we usually just register it.
				knownSinkPropertyPaths[staticName] = fallbackDef
			}

		} else {
			// -- Function Sinks (e.g. eval, document.write) --

			// 1. Map Full Path (Priority)
			// This Fixes TestBasicTaintFlow: "document.write" maps to Name="document.write"
			fullDef := baseDef
			fullDef.Name = core.TaintSink(sink.Name)

			if existing, exists := knownSinkFunctions[sink.Name]; exists {
				// If entry exists (e.g., multiple definitions for same function), merge args
				knownSinkFunctions[sink.Name] = mergeArgs(existing, sink.ArgIndex)
			} else {
				knownSinkFunctions[sink.Name] = fullDef
			}

			// 2. Map Static Name (Fallback)
			// "write" -> Name="write" (Used when we can't resolve the object "document")
			if sink.Name != staticName {
				fallbackDef := baseDef
				fallbackDef.Name = core.TaintSink(staticName)

				if existing, exists := knownSinkFunctions[staticName]; exists {
					knownSinkFunctions[staticName] = mergeArgs(existing, sink.ArgIndex)
				} else {
					knownSinkFunctions[staticName] = fallbackDef
				}
			}
		}
	}
}

// Helper to merge argument indices without duplicates
func mergeArgs(def StaticSinkDefinition, newArg int) StaticSinkDefinition {
	for _, arg := range def.TaintedArgs {
		if arg == newArg {
			return def
		}
	}
	def.TaintedArgs = append(def.TaintedArgs, newArg)
	return def
}

// -- Lookup Helpers used by Walker --

// CheckIfSinkProperty checks if a property access path leads to a sink.
func CheckIfSinkProperty(path []string) (StaticSinkDefinition, bool) {
	if len(path) == 0 {
		return StaticSinkDefinition{}, false
	}
	pathStr := strings.Join(path, ".")

	// 1. Try Exact Match (High Confidence) e.g., "Element.prototype.innerHTML"
	if def, ok := knownSinkPropertyPaths[pathStr]; ok {
		return def, true
	}

	// 2. Try Static Name Match (Low Confidence) e.g., "innerHTML"
	staticName := path[len(path)-1]
	if def, ok := knownSinkPropertyPaths[staticName]; ok {
		return def, true
	}

	return StaticSinkDefinition{}, false
}

// CheckIfSinkFunction checks if a function call path matches a known sink.
func CheckIfSinkFunction(path []string) (StaticSinkDefinition, bool) {
	if len(path) == 0 {
		return StaticSinkDefinition{}, false
	}
	pathStr := strings.Join(path, ".")

	// 1. Try Exact Match (e.g. "document.write")
	if def, ok := knownSinkFunctions[pathStr]; ok {
		return def, true
	}

	// 2. Try Static Name Match (e.g. "write")
	staticName := path[len(path)-1]
	if def, ok := knownSinkFunctions[staticName]; ok {
		return def, true
	}

	return StaticSinkDefinition{}, false
}
