// Filename: javascript/walker.go
// Core logic for traversing the AST and tracking taint flow with object sensitivity
// and inter-procedural analysis support.
package javascript

import (
	"fmt"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"go.uber.org/zap"

	// Import core definitions (Step 1)
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// WalkerMode defines the operation mode of the AST walker.
type WalkerMode int

const (
	// ModeAnalyze performs the main taint analysis, utilizing summaries.
	ModeAnalyze WalkerMode = iota
	// ModeSummarize analyzes functions to determine their taint behavior.
	ModeSummarize
)

// astWalker implements the logic for flow-sensitive analysis on Tree-sitter nodes.
type astWalker struct {
	// Findings collected during ModeAnalyze.
	analyzeFindings []StaticFinding
	logger          *zap.Logger
	filename        string
	source          []byte
	mode            WalkerMode
	// Shared context for IPA data exchange.
	context *AnalyzerContext

	// Map unique symbol references (RefID) to their current abstract taint state (The Environment/Store).
	symbolTaint map[RefID]TaintState

	// -- Level 3: Inter-procedural state (Used only in ModeSummarize) --
	currentSummary *FunctionSummary
	returnTaint    TaintState
	// Temporary storage for findings derived from parameters during summarization.
	// This is used exclusively to calculate the TaintedParams map in finalizeSummary.
	summaryParamFindings []StaticFinding
}

func newASTWalker(logger *zap.Logger, filename string, source []byte, mode WalkerMode, context *AnalyzerContext) *astWalker {
	return &astWalker{
		analyzeFindings:      []StaticFinding{},
		logger:               logger.Named("js_walker"),
		filename:             filename,
		source:               source,
		mode:                 mode,
		context:              context,
		symbolTaint:          make(map[RefID]TaintState),
		summaryParamFindings: []StaticFinding{},
	}
}

// GetAnalyzeFindings returns the findings collected if the walker was in Analyze mode.
func (w *astWalker) GetAnalyzeFindings() []StaticFinding {
	return w.analyzeFindings
}

// Walk recursively visits nodes.
func (w *astWalker) Walk(node *sitter.Node) {
	if node == nil || node.IsNull() {
		return
	}

	shouldRecurse := true

	switch node.Type() {
	case "function_declaration", "function", "arrow_function", "generator_function", "method_definition":
		shouldRecurse = w.handleFunctionBoundary(node)

	case "variable_declaration", "lexical_declaration":
		w.handleVarDecl(node)
		// Evaluation handled internally.

	case "assignment_expression":
		w.handleAssignment(node)
		// Evaluation handled internally.

	case "call_expression", "new_expression":
		// We call handleCall primarily to check for sinks.
		w.handleCall(node)

	case "return_statement":
		w.handleReturn(node)
	}

	if shouldRecurse {
		// Depth-First Search traversal.
		cursor := sitter.NewTreeCursor(node)
		defer cursor.Close()

		if ok := cursor.GoToFirstChild(); ok {
			for {
				w.Walk(cursor.CurrentNode())
				if ok := cursor.GoToNextSibling(); !ok {
					break
				}
			}
		}
	}
}

// -- Level 3: Function Summarization Logic --

// handleFunctionBoundary determines if we should descend into a function body.
func (w *astWalker) handleFunctionBoundary(_ *sitter.Node) bool {
	// In analysis mode, we rely entirely on summaries and skip the body.
	if w.mode == ModeAnalyze {
		return false
	}

	// In summarization mode, we must ensure we don't descend into nested functions
	// if we are already summarizing the parent function.
	if w.mode == ModeSummarize && w.currentSummary != nil {
		// We are inside the target function body; skip nested declarations.
		return false
	}

	return true
}

// StartSummarizationWalk initiates analysis of a specific function body.
func (w *astWalker) StartSummarizationWalk(ref RefID, fnNode *sitter.Node) {
	if w.mode != ModeSummarize {
		w.logger.Error("StartSummarizationWalk called in wrong mode")
		return
	}

	summary := NewFunctionSummary(ref)
	w.currentSummary = summary
	w.context.Summaries[ref] = summary

	// Initialize parameters with symbolic taint sources.
	w.initializeParameters(fnNode)

	// Walk the function body.
	bodyNode := fnNode.ChildByFieldName("body")
	if bodyNode != nil {
		w.Walk(bodyNode)
	}

	w.finalizeSummary()
}

// initializeParameters handles the initialization of function parameters, adapting to grammar variations.
func (w *astWalker) initializeParameters(fnNode *sitter.Node) {
	// Fix for Failure A: Grammar mismatch for parameter access (parameters vs formal_parameters).

	// Strategy 1: Check common field names for the parameter list (the node containing (...)).
	// Prioritize 'formal_parameters' (standard JS grammar) then fallback to 'parameters'.
	paramsNode := fnNode.ChildByFieldName("formal_parameters")
	if paramsNode == nil {
		paramsNode = fnNode.ChildByFieldName("parameters")
	}

	if paramsNode != nil {
		// Process the parameter list node.
		logicalIndex := 0
		for i := 0; i < int(paramsNode.ChildCount()); i++ {
			param := paramsNode.Child(i)
			// Align index by skipping punctuation.
			switch param.Type() {
			// Include assignment_pattern for default parameters.
			case "identifier", "rest_parameter", "object_pattern", "array_pattern", "assignment_pattern":
				w.initializeParameterTaint(param, logicalIndex)
				logicalIndex++
			case "(", ")", ",":
				// Ignore punctuation
			}
		}
		return
	}

	// Strategy 2: Handle arrow functions with a single, parenthesis-free parameter (e.g., x => x).
	if fnNode.Type() == "arrow_function" {
		// The grammar often names this specific case 'parameter' (singular).
		param := fnNode.ChildByFieldName("parameter")
		if param != nil {
			w.initializeParameterTaint(param, 0)
			return
		}
	}

	// If we reach here, the function has no parameters or the structure is unexpected.
}

// initializeParameterTaint initiates the assignment of symbolic taint sources, handling destructuring with path sensitivity.
func (w *astWalker) initializeParameterTaint(paramNode *sitter.Node, index int) {
	// Create the base symbolic taint source "param:N".
	baseSource := core.TaintSource(fmt.Sprintf("param:%d", index))
	loc := int(paramNode.StartPoint().Row)

	// Use a recursive helper to handle potential destructuring with path sensitivity.
	w.initializeDestructuredParameter(paramNode, baseSource, loc)
}

// initializeDestructuredParameter recursively assigns symbolic taint sources (e.g., param:0.prop) to bindings in a parameter pattern.
func (w *astWalker) initializeDestructuredParameter(pattern *sitter.Node, currentSource core.TaintSource, loc int) {
	if pattern == nil {
		return
	}

	switch pattern.Type() {
	case "identifier", "shorthand_property_identifier_pattern":
		// Base case: Assign the current symbolic source to the identifier.
		state := NewSimpleTaint(currentSource, loc)
		ref := RefID(pattern.Content(w.source))
		w.taintBinding(ref, state)

	case "object_pattern":
		// function ({ a, b: c }) {}
		for i := 0; i < int(pattern.ChildCount()); i++ {
			child := pattern.Child(i)
			switch child.Type() {
			case "shorthand_property_identifier_pattern":
				// { a } -> a gets source.a
				propName := child.Content(w.source)
				nextSource := core.TaintSource(fmt.Sprintf("%s.%s", currentSource, propName))
				w.initializeDestructuredParameter(child, nextSource, loc)

			case "pair_pattern":
				// { key: value_pattern } -> value_pattern gets source.key
				key := child.ChildByFieldName("key")
				valuePattern := child.ChildByFieldName("value")

				propName, staticallyKnown := w.extractStaticKeyName(key)
				var nextSource core.TaintSource
				if staticallyKnown {
					nextSource = core.TaintSource(fmt.Sprintf("%s.%s", currentSource, propName))
				} else {
					// Computed property in parameter destructuring.
					nextSource = currentSource // Approximation: lose path sensitivity
				}
				w.initializeDestructuredParameter(valuePattern, nextSource, loc)

			case "rest_parameter", "assignment_pattern":
				// Approximation: lose path sensitivity for rest/defaults in complex patterns.
				w.initializeDestructuredParameter(child, currentSource, loc)
			}
		}

	case "array_pattern":
		// function ([ a, b ]) {}
		// Approximation: Treat array elements as having the base parameter source.
		// Precise tracking could use source[0], source[1], etc., but we approximate here.
		for i := 0; i < int(pattern.ChildCount()); i++ {
			child := pattern.Child(i)
			if child.Type() == "," || child.Type() == "[" || child.Type() == "]" {
				continue
			}
			w.initializeDestructuredParameter(child, currentSource, loc)
		}

	case "assignment_pattern":
		// function (a = default) {}
		// The parameter is tainted if the argument is provided.
		left := pattern.ChildByFieldName("left")
		w.initializeDestructuredParameter(left, currentSource, loc)
		// Note: We ignore the default value during summarization initialization.

	case "rest_parameter":
		// function (...rest) {}
		// The binding pattern is the child after the '...' (often by field name 'argument' or index 1).
		arg := pattern.ChildByFieldName("argument")
		if arg == nil && pattern.ChildCount() > 1 {
			// Fallback to index if field name is missing (robustness).
			arg = pattern.Child(1)
		}

		if arg != nil {
			w.initializeDestructuredParameter(arg, currentSource, loc)
		}
	}
}

func (w *astWalker) handleReturn(node *sitter.Node) {
	if w.mode != ModeSummarize || w.currentSummary == nil {
		return
	}

	// Find the return value expression.
	// return_statement children: "return", [expression], ";"
	// The expression is often by field name 'argument' or index 1.
	valueNode := node.ChildByFieldName("argument")

	// Fallback for robustness if field name is missing.
	if valueNode == nil && node.ChildCount() > 1 && node.Child(0).Type() == "return" {
		potentialArg := node.Child(1)
		if potentialArg.Type() != ";" {
			valueNode = potentialArg
		}
	}

	if valueNode != nil {
		retTaint := w.evaluateTaint(valueNode)
		if retTaint != nil && retTaint.IsTainted() {
			// Join the taint state with existing return taint (if multiple return paths exist).
			if w.returnTaint == nil {
				w.returnTaint = retTaint
			} else {
				w.returnTaint = w.returnTaint.Merge(retTaint)
			}
		}
	}
}

// finalizeSummary processes the results of the function analysis to produce the final FunctionSummary.
func (w *astWalker) finalizeSummary() {
	summary := w.currentSummary
	if summary == nil {
		return
	}

	// 1. Analyze findings derived from parameters (Sink analysis).
	for _, finding := range w.summaryParamFindings {
		// The finding source string might contain multiple sources (e.g., "param:0|param:1.a").
		sources := strings.Split(string(finding.Source), "|")
		for _, source := range sources {
			if strings.HasPrefix(source, "param:") {
				paramIndex, ok := w.extractParamIndex(core.TaintSource(source))
				if ok {
					summary.TaintedParams[paramIndex] = true
				}
			}
		}
	}

	// 2. Analyze return value taint (Return analysis).
	if w.returnTaint != nil && w.returnTaint.IsTainted() {
		// Use GetSources() for accurate analysis with multi-source tracking.
		sources := w.returnTaint.GetSources()
		hasGlobalSource := false

		for source := range sources {
			if strings.HasPrefix(string(source), "param:") {
				// Taint flows from parameter to return.
				paramIndex, ok := w.extractParamIndex(source)
				if ok {
					summary.ParamToReturn[paramIndex] = true
				}
			} else {
				hasGlobalSource = true
			}
		}

		if hasGlobalSource {
			// Taint flows from global source (or SourceUnknown) to return.
			summary.TaintsReturn = true
		}
	}

	// Clean up temporary state.
	w.currentSummary = nil
	w.returnTaint = nil
	w.summaryParamFindings = nil
}

// extractParamIndex parses the index N from sources like "param:N" or "param:N.prop".
func (w *astWalker) extractParamIndex(source core.TaintSource) (int, bool) {
	s := string(source)
	if !strings.HasPrefix(s, "param:") {
		return 0, false
	}
	s = strings.TrimPrefix(s, "param:")
	// Find the end of the number (either end of string or '.')
	end := len(s)
	if dotIndex := strings.Index(s, "."); dotIndex != -1 {
		end = dotIndex
	}

	// Use strconv.Atoi for robust integer parsing.
	if index, err := strconv.Atoi(s[:end]); err == nil {
		return index, true
	}
	w.logger.Debug("Failed to parse parameter index from symbolic source", zap.String("source", string(source)))
	return 0, false
}

// -- Taint Evaluation (Abstract Interpretation) --

// evaluateTaint recursively analyzes an expression node to determine its abstract taint state.
func (w *astWalker) evaluateTaint(node *sitter.Node) TaintState {
	if node == nil {
		return nil
	}

	switch node.Type() {
	// Handle identifiers, including those used as shorthand properties.
	case "identifier", "shorthand_property_identifier":
		ref := RefID(node.Content(w.source))
		return w.symbolTaint[ref]

	case "member_expression", "subscript_expression":
		return w.evaluatePropertyAccessTaint(node)

	case "call_expression", "new_expression":
		return w.evaluateCallTaint(node)

	case "binary_expression":
		left := node.ChildByFieldName("left")
		right := node.ChildByFieldName("right")
		leftTaint := w.evaluateTaint(left)
		rightTaint := w.evaluateTaint(right)

		// Utilize the corrected Merge logic.
		if leftTaint != nil {
			return leftTaint.Merge(rightTaint)
		}
		return rightTaint

	case "template_string":
		var resultTaint TaintState
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child.Type() == "template_substitution" {
				// ${ expr } -> find the expression inside
				// Fix for Failure B: Robustly handle grammar mismatch for template substitution expression access.

				// Attempt 1: Use the field name if defined by the grammar.
				expr := child.ChildByFieldName("expression")

				// Attempt 2: Access by index if the field name is missing.
				// template_substitution structure is typically: "${" (index 0), expression (index 1), "}" (index 2).
				if expr == nil && child.ChildCount() > 1 {
					// Access the node at index 1.
					potentialExpr := child.Child(1)
					// Ensure it's not the closing brace "}" (handles empty `${}` if grammar allows it).
					if potentialExpr.Type() != "}" {
						expr = potentialExpr
					}
				}

				// Evaluate the extracted expression node.
				partTaint := w.evaluateTaint(expr)
				if partTaint != nil && partTaint.IsTainted() {
					if resultTaint == nil {
						resultTaint = partTaint
					} else {
						resultTaint = resultTaint.Merge(partTaint)
					}
				}
			}
		}
		return resultTaint

	case "object": // Object literal { a: 1 }
		return w.evaluateObjectLiteralTaint(node)

	// Parenthesized expressions
	case "parenthesized_expression":
		// ( expression )
		// The expression is typically the child at index 1, or by field name 'expression'.
		expr := node.ChildByFieldName("expression")
		if expr == nil && node.ChildCount() > 2 {
			expr = node.Child(1)
		}
		return w.evaluateTaint(expr)

	// Literals
	case "string", "number", "true", "false", "null", "undefined", "array":
		return nil

	default:
		// Handle other expression types if necessary (e.g., sequence_expression, await_expression).
		return nil
	}
}

func (w *astWalker) evaluatePropertyAccessTaint(node *sitter.Node) TaintState {
	// 1. Global Source Check
	path := flattenPropertyAccess(node, w.source)
	if path != nil {
		// Use the unified check from core (Step 1)
		if source, isSource := core.CheckIfPropertySource(path); isSource {
			return NewSimpleTaint(source, int(node.StartPoint().Row))
		}
	}

	// 2. Tracked Object Check
	object := node.ChildByFieldName("object")

	// Determine the property name and access type (static vs computed).
	propName, staticallyKnown := w.determinePropertyName(node)

	targetState := w.evaluateTaint(object)
	if targetState == nil {
		return nil
	}

	if objTaint, ok := targetState.(*ObjectTaint); ok {
		if staticallyKnown {
			return objTaint.GetPropertyTaint(propName)
		}
		// Computed access on an object.
		if objTaint.IsTainted() {
			// If any part of the object is tainted, the result of computed access is tainted.
			// We merge the object's taint sources with SourceUnknown to signify approximation.
			return NewSimpleTaint(core.SourceUnknown, int(node.StartPoint().Row)).Merge(objTaint)
		}
	}

	// Approximation: Accessing a property on a tainted non-object (SimpleTaint).
	if targetState.IsTainted() {
		// We propagate the taint but lose precision on the property access itself.
		// We merge SourceUnknown into the existing taint state.
		return targetState.Merge(NewSimpleTaint(core.SourceUnknown, int(node.StartPoint().Row)))
	}

	return nil
}

// determinePropertyName extracts the property name and returns whether it was statically known.
func (w *astWalker) determinePropertyName(node *sitter.Node) (string, bool) {
	var propertyOrIndex *sitter.Node
	isSubscript := node.Type() == "subscript_expression"

	if !isSubscript {
		propertyOrIndex = node.ChildByFieldName("property")
	} else {
		propertyOrIndex = node.ChildByFieldName("index")
	}

	if propertyOrIndex == nil {
		return "", false
	}

	switch propertyOrIndex.Type() {
	case "identifier", "property_identifier":
		propName := propertyOrIndex.Content(w.source)
		// If it's an identifier inside a subscript (obj[i]), it's computed access.
		if isSubscript {
			return propName, false
		}
		return propName, true
	case "string":
		// obj['prop']
		raw := propertyOrIndex.Content(w.source)
		propName := strings.Trim(raw, "\"'`")
		return propName, true
	default:
		// Computed property (e.g., obj[getPropName()] or arr[0])
		return "", false
	}
}

// extractStaticKeyName determines the property name from a key node (in object literals or patterns).
func (w *astWalker) extractStaticKeyName(key *sitter.Node) (string, bool) {
	if key == nil {
		return "", false
	}
	switch key.Type() {
	case "property_identifier", "identifier":
		return key.Content(w.source), true
	case "string":
		raw := key.Content(w.source)
		return strings.Trim(raw, "\"'`"), true
	default:
		// Computed property name or other complex types (e.g. "computed_property_name").
		return "", false
	}
}

// evaluateObjectLiteralTaint handles object creation, including modern syntax like spread and shorthand properties.
func (w *astWalker) evaluateObjectLiteralTaint(node *sitter.Node) TaintState {
	objState := NewObjectTaint()

	// Iterate over object properties, pairs, and spread elements.
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "pair":
			// Standard { key: value }
			key := child.ChildByFieldName("key")
			value := child.ChildByFieldName("value")

			propName, staticallyKnown := w.extractStaticKeyName(key)

			valueTaint := w.evaluateTaint(value)
			if valueTaint != nil && valueTaint.IsTainted() {
				if staticallyKnown {
					objState.SetPropertyTaint(propName, valueTaint)
				} else {
					// Computed property name assignment taints the structure.
					objState.StructureTainted = true
				}
			}

		case "shorthand_property_identifier":
			// Handle shorthand property identifiers: { identifier }
			// The value is the variable itself, so we evaluate the identifier node.
			valueTaint := w.evaluateTaint(child)
			if valueTaint != nil && valueTaint.IsTainted() {
				propName := NodeContent(child, w.source)
				objState.SetPropertyTaint(propName, valueTaint)
			}

		case "spread_element":
			// Handle spread syntax: { ...otherObj }
			// The argument is often at index 1 or by field name 'argument'.
			spreadExpr := child.ChildByFieldName("argument")
			if spreadExpr == nil && child.ChildCount() > 1 {
				spreadExpr = child.Child(1)
			}

			spreadTaint := w.evaluateTaint(spreadExpr)

			if spreadTaint != nil && spreadTaint.IsTainted() {
				// Merge the spread taint into the current object state.
				newState := objState.Merge(spreadTaint)
				// If the result is still an ObjectTaint, update objState.
				if newObj, ok := newState.(*ObjectTaint); ok {
					objState = newObj
				} else {
					// If Merge resulted in a SimpleTaint (because SimpleTaint is the LUB),
					// we adopt the SimpleTaint as the new state, overwriting the object structure.
					return newState
				}
			}
		}
	}

	if objState.IsTainted() {
		return objState
	}
	return nil
}

// Step 4 Implementation: Helper function to identify specific parameter extraction patterns.
// This checks for methods like .get(), .getItem() called on objects derived from known sources.
func (w *astWalker) checkSpecificParameterExtraction(callNode, callee *sitter.Node, path []string, argsNode *sitter.Node) TaintState {
	if len(path) == 0 {
		return nil
	}

	methodName := path[len(path)-1]
	// Check for common extraction methods.
	if methodName == "get" || methodName == "getItem" || methodName == "getAll" {

		// Get the receiver object (the object the method is called on).
		var receiver *sitter.Node
		if callee.Type() == "member_expression" {
			receiver = callee.ChildByFieldName("object")
		}
		// Add support for subscript_expression if needed (e.g. obj['get']('id')).

		if receiver != nil {
			// Evaluate the taint of the receiver (e.g., the URLSearchParams object or localStorage).
			receiverTaint := w.evaluateTaint(receiver)

			if receiverTaint != nil && receiverTaint.IsTainted() {
				// Check if the taint originates from relevant sources (URL params, storage).
				sources := receiverTaint.GetSources()

				// Determine the source prefix for refinement (Step 4 refinement).
				sourcePrefix := ""
				if sources[core.SourceLocationSearch] || sources[core.SourceLocationHref] {
					// Prioritize query if Href is present, as Href includes Search.
					sourcePrefix = "param:query:"
				} else if sources[core.SourceLocationHash] {
					sourcePrefix = "param:hash:"
				} else if sources[core.SourceLocalStorage] || sources[core.SourceSessionStorage] {
					// We can refine storage keys as well.
					sourcePrefix = "param:storage:"
				}

				if sourcePrefix != "" {
					// We found a relevant extraction call. Now extract the argument (parameter/key name).
					args := w.extractArguments(argsNode)
					if len(args) > 0 {
						// We only refine if the first argument is a static string literal.
						arg := args[0]
						if arg.Type() == "string" {
							raw := NodeContent(arg, w.source)
							paramName := strings.Trim(raw, "\"'`") // Unquote the string literal

							specificSource := core.TaintSource(sourcePrefix + paramName)

							// Return the refined taint state.
							return NewSimpleTaint(specificSource, int(callNode.StartPoint().Row))
						}
					}
				}
			}
		}
	}
	return nil
}

func (w *astWalker) evaluateCallTaint(node *sitter.Node) TaintState {
	callee := node.ChildByFieldName("function")
	argsNode := node.ChildByFieldName("arguments")

	path := flattenPropertyAccess(callee, w.source)

	// 1. Check known APIs (Sources, Sanitizers)
	if path != nil {
		// Step 4 Implementation: Check for specific parameter extraction first.
		if refinedTaint := w.checkSpecificParameterExtraction(node, callee, path, argsNode); refinedTaint != nil {
			return refinedTaint
		}

		// Use the unified checks from core (Step 1)
		if source, isSource := core.CheckIfFunctionSource(path); isSource {
			return NewSimpleTaint(source, int(node.StartPoint().Row))
		}
		if core.CheckIfSanitizer(path) {
			return nil
		}
	}

	// 2. Inter-procedural logic (Apply Summaries)
	// We only apply summaries in ModeAnalyze.
	if w.mode == ModeAnalyze && w.context != nil && callee != nil && callee.Type() == "identifier" {
		calleeRef := RefID(callee.Content(w.source))
		if summary, exists := w.context.Summaries[calleeRef]; exists {
			return w.evaluateCallWithSummary(node, argsNode, summary)
		}
	}

	// 3. Fallback Approximation (Unknown functions or ModeSummarize)
	var mergedTaint TaintState
	if argsNode != nil {
		// We use extractArguments to handle potential spread elements in the arguments list.
		args := w.extractArguments(argsNode)
		for _, arg := range args {
			var argTaint TaintState
			if arg.Type() == "spread_element" {
				// Evaluate the expression inside the spread.
				spreadExpr := arg.ChildByFieldName("argument")
				if spreadExpr == nil && arg.ChildCount() > 1 {
					spreadExpr = arg.Child(1)
				}
				argTaint = w.evaluateTaint(spreadExpr)
			} else {
				argTaint = w.evaluateTaint(arg)
			}

			if argTaint != nil && argTaint.IsTainted() {
				if mergedTaint == nil {
					mergedTaint = argTaint
				} else {
					mergedTaint = mergedTaint.Merge(argTaint)
				}
			}
		}
	}

	// Approximation: Method call side effects obj.method(tainted) -> taint obj
	if mergedTaint != nil && mergedTaint.IsTainted() && callee != nil && callee.Type() == "member_expression" {
		obj := callee.ChildByFieldName("object")
		w.updateTaintTarget(obj, NewSimpleTaint(core.SourceUnknown, int(node.StartPoint().Row)))
	}

	// Approximation: Return value inherits argument taint for unknown functions.
	if mergedTaint != nil {
		// We merge the existing taint with SourceUnknown to signify approximation.
		return mergedTaint.Merge(NewSimpleTaint(core.SourceUnknown, int(node.StartPoint().Row)))
	}

	return nil
}

func (w *astWalker) evaluateCallWithSummary(callNode, argsNode *sitter.Node, summary *FunctionSummary) TaintState {
	// Case 1: Function inherently returns taint (from global source).
	if summary.TaintsReturn {
		funcName := string(summary.RefID)
		// Propagate the specific return source marker.
		source := core.TaintSource(fmt.Sprintf("return:%s", funcName))
		return NewSimpleTaint(source, int(callNode.StartPoint().Row))
	}

	// Case 2: Return value depends on arguments (Param -> Return).
	var mergedTaint TaintState
	args := w.extractArguments(argsNode)

	for i, arg := range args {
		paramIndex := i // Approximation: assumes argument index matches parameter index.

		flowsToReturn := summary.ParamToReturn[paramIndex]

		// Handle spread approximation.
		if arg.Type() == "spread_element" {
			// If *any* parameter flows to return, we assume the spread argument might contribute.
			flowsToReturn = false
			for _, flows := range summary.ParamToReturn {
				if flows {
					flowsToReturn = true
					break
				}
			}
		}

		if flowsToReturn {
			var argTaint TaintState
			if arg.Type() == "spread_element" {
				spreadExpr := arg.ChildByFieldName("argument")
				if spreadExpr == nil && arg.ChildCount() > 1 {
					spreadExpr = arg.Child(1)
				}
				argTaint = w.evaluateTaint(spreadExpr)
			} else {
				argTaint = w.evaluateTaint(arg)
			}

			if argTaint != nil && argTaint.IsTainted() {
				if mergedTaint == nil {
					mergedTaint = argTaint
				} else {
					mergedTaint = mergedTaint.Merge(argTaint)
				}
			}
		}
	}
	return mergedTaint
}

// -- Propagation Handlers (State Updates) --

func (w *astWalker) handleVarDecl(node *sitter.Node) {
	// variable_declaration or lexical_declaration can have multiple declarators
	for i := 0; i < int(node.ChildCount()); i++ {
		declarator := node.Child(i)
		if declarator.Type() == "variable_declarator" {
			nameNode := declarator.ChildByFieldName("name")
			valueNode := declarator.ChildByFieldName("value")

			// A declarator might not have a value (e.g. `let x;`)
			if nameNode != nil && valueNode != nil {
				rhsTaint := w.evaluateTaint(valueNode)
				w.handleDestructuring(nameNode, rhsTaint)
			}
		}
	}
}

func (w *astWalker) handleAssignment(node *sitter.Node) {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")

	if left != nil && right != nil {
		rhsTaint := w.evaluateTaint(right)
		w.updateTaintTarget(left, rhsTaint)
		w.checkAssignmentSink(left, rhsTaint, node)
	}
}

func (w *astWalker) handleDestructuring(pattern *sitter.Node, state TaintState) {
	if pattern == nil {
		return
	}

	switch pattern.Type() {
	case "identifier", "shorthand_property_identifier":
		ref := RefID(pattern.Content(w.source))
		w.taintBinding(ref, state)

	case "object_pattern":
		w.handleObjectDestructuring(pattern, state)

	case "array_pattern":
		w.handleArrayDestructuring(pattern, state)
	}
}

func (w *astWalker) handleObjectDestructuring(pattern *sitter.Node, state TaintState) {
	objTaint, isObject := state.(*ObjectTaint)

	for i := 0; i < int(pattern.ChildCount()); i++ {
		child := pattern.Child(i)
		switch child.Type() {
		case "pair_pattern": // { key: value }
			keyNode := child.ChildByFieldName("key")
			valuePattern := child.ChildByFieldName("value")
			propName, staticallyKnown := w.extractStaticKeyName(keyNode)

			var propTaint TaintState
			if isObject && staticallyKnown {
				propTaint = objTaint.GetPropertyTaint(propName)
			} else if state != nil && state.IsTainted() {
				// If the source is not an object or property is computed, approximate.
				propTaint = NewSimpleTaint(core.SourceUnknown, int(child.StartPoint().Row))
			}
			w.handleDestructuring(valuePattern, propTaint)

		case "shorthand_property_identifier_pattern": // { prop }
			propName := NodeContent(child, w.source)
			var propTaint TaintState
			if isObject {
				propTaint = objTaint.GetPropertyTaint(propName)
			} else if state != nil && state.IsTainted() {
				propTaint = NewSimpleTaint(core.SourceUnknown, int(child.StartPoint().Row))
			}
			w.handleDestructuring(child, propTaint)
		}
	}
}

func (w *astWalker) handleArrayDestructuring(pattern *sitter.Node, state TaintState) {
	// Approximation: If the array is tainted, all destructured elements are tainted.
	var elemTaint TaintState
	if state != nil && state.IsTainted() {
		elemTaint = NewSimpleTaint(core.SourceUnknown, int(pattern.StartPoint().Row))
	}

	for i := 0; i < int(pattern.ChildCount()); i++ {
		child := pattern.Child(i)
		// Skip punctuation
		if child.Type() != "[" && child.Type() != "]" && child.Type() != "," {
			w.handleDestructuring(child, elemTaint)
		}
	}
}

func (w *astWalker) taintBinding(ref RefID, state TaintState) {
	if state != nil && state.IsTainted() {
		w.symbolTaint[ref] = state
	} else {
		// If the new state is not tainted, remove the old taint.
		delete(w.symbolTaint, ref)
	}
}

func (w *astWalker) updateTaintTarget(target *sitter.Node, state TaintState) {
	if target == nil {
		return
	}

	switch target.Type() {
	case "identifier":
		ref := RefID(target.Content(w.source))
		w.taintBinding(ref, state)
	case "member_expression", "subscript_expression":
		w.updatePropertyTaint(target, state)
	case "object_pattern", "array_pattern":
		// This is destructuring assignment
		w.handleDestructuring(target, state)
	}
}

func (w *astWalker) updatePropertyTaint(target *sitter.Node, state TaintState) {
	objectNode := target.ChildByFieldName("object")
	if objectNode == nil {
		return
	}

	propName, staticallyKnown := w.determinePropertyName(target)

	// Get the existing taint state of the object.
	existingTaint := w.evaluateTaint(objectNode)

	if !staticallyKnown {
		// Computed property assignment: Taint the whole object structure.
		var newTaint TaintState
		if existingTaint != nil {
			newTaint = existingTaint.Merge(state)
		} else {
			newTaint = state
		}
		// Mark the structure as tainted if it's an object.
		if objTaint, ok := newTaint.(*ObjectTaint); ok {
			objTaint.StructureTainted = true
		}
		w.updateTaintTarget(objectNode, newTaint)
		return
	}

	// Static property assignment.
	var objTaint *ObjectTaint
	if ot, ok := existingTaint.(*ObjectTaint); ok {
		objTaint = ot
	} else {
		objTaint = NewObjectTaint()
		// If there was existing simple taint, merge it into the structure.
		if existingTaint != nil && existingTaint.IsTainted() {
			objTaint.StructureTainted = true
		}
	}

	objTaint.SetPropertyTaint(propName, state)
	w.updateTaintTarget(objectNode, objTaint)
}

// -- Sink Detection --

// checkAssignmentSink uses StaticSinkDefinition
func (w *astWalker) checkAssignmentSink(target *sitter.Node, rhsState TaintState, fullNode *sitter.Node) {
	if target == nil {
		return
	}
	// Defense in depth: Ensure target type is valid for property access flattening.
	if target.Type() != "identifier" && target.Type() != "member_expression" && target.Type() != "subscript_expression" {
		return
	}

	path := flattenPropertyAccess(target, w.source)
	if path == nil {
		return
	}

	// CheckIfSinkProperty returns StaticSinkDefinition
	if sinkDef, isSink := CheckIfSinkProperty(path); isSink {
		w.reportFinding(rhsState.GetSource(), sinkDef, fullNode)
	}
}

func (w *astWalker) handleCall(node *sitter.Node) {
	callee := node.ChildByFieldName("function")
	argsNode := node.ChildByFieldName("arguments")
	w.checkCallForSinks(callee, argsNode, node)
}

// extractArguments parses the arguments node into a list of expression nodes, handling spread syntax.
func (w *astWalker) extractArguments(argsNode *sitter.Node) []*sitter.Node {
	var args []*sitter.Node
	if argsNode == nil {
		return args
	}

	// Tree-sitter structures arguments within parenthesis.
	for i := 0; i < int(argsNode.ChildCount()); i++ {
		child := argsNode.Child(i)
		if child.Type() != "(" && child.Type() != ")" && child.Type() != "," {
			// Includes standard expressions and spread_element.
			args = append(args, child)
		}
	}
	return args
}

func (w *astWalker) checkCallForSinks(callee *sitter.Node, argsNode *sitter.Node, fullNode *sitter.Node) {
	if callee == nil {
		return
	}

	// 1. Check known sink functions.
	path := flattenPropertyAccess(callee, w.source)
	if path != nil {
		// CheckIfSinkFunction returns StaticSinkDefinition
		if sinkDef, isSink := CheckIfSinkFunction(path); isSink {
			w.checkArgsAgainstSink(sinkDef, argsNode, fullNode)
			return
		}
	}

	// 2. User defined summary check (IPA).
	if w.mode == ModeAnalyze && w.context != nil && callee.Type() == "identifier" {
		ref := RefID(callee.Content(w.source))
		if summary, exists := w.context.Summaries[ref]; exists {
			w.checkCallWithSummary(argsNode, fullNode, summary)
		}
	}
}

// checkArgsAgainstSink uses StaticSinkDefinition
func (w *astWalker) checkArgsAgainstSink(sinkDef StaticSinkDefinition, argsNode *sitter.Node, fullNode *sitter.Node) {
	args := w.extractArguments(argsNode)

	for _, argIndex := range sinkDef.TaintedArgs {
		if argIndex >= 0 && argIndex < len(args) {
			argNode := args[argIndex]
			var argTaint TaintState

			// Handle spread arguments in sink calls.
			if argNode.Type() == "spread_element" {
				// Approximation: check the taint of the spread expression itself.
				spreadExpr := argNode.ChildByFieldName("argument")
				if spreadExpr == nil && argNode.ChildCount() > 1 {
					spreadExpr = argNode.Child(1)
				}
				argTaint = w.evaluateTaint(spreadExpr)
			} else {
				// Standard argument evaluation.
				argTaint = w.evaluateTaint(argNode)
			}

			if argTaint != nil && argTaint.IsTainted() {
				// Report based on the representative source.
				w.reportFinding(argTaint.GetSource(), sinkDef, fullNode)
				// We stop after the first tainted argument hits the sink definition.
				return
			}
		}
	}
}

func (w *astWalker) checkCallWithSummary(argsNode *sitter.Node, fullNode *sitter.Node, summary *FunctionSummary) {
	args := w.extractArguments(argsNode)

	// We iterate through the actual arguments provided.
	for i, arg := range args {
		paramIndex := i // Approximation: assumes argument index matches parameter index.

		flowsToSink := summary.TaintedParams[paramIndex]

		// Handle spread approximation.
		if arg.Type() == "spread_element" {
			// If *any* parameter flows to a sink, we assume the spread argument might contribute.
			flowsToSink = false
			for _, flows := range summary.TaintedParams {
				if flows {
					flowsToSink = true
					break
				}
			}
		}

		if flowsToSink {
			// Evaluate the argument (handling spread element internally if needed).
			var argTaint TaintState
			if arg.Type() == "spread_element" {
				spreadExpr := arg.ChildByFieldName("argument")
				if spreadExpr == nil && arg.ChildCount() > 1 {
					spreadExpr = arg.Child(1)
				}
				argTaint = w.evaluateTaint(spreadExpr)
			} else {
				argTaint = w.evaluateTaint(arg)
			}

			if argTaint != nil && argTaint.IsTainted() {
				// Found inter-procedural sink
				funcName := string(summary.RefID)
				// Create a StaticSinkDefinition for reporting
				sinkDef := StaticSinkDefinition{
					// We report the argument index i.
					Name: core.TaintSink(fmt.Sprintf("call:%s(arg:%d)", funcName, i)),
					// Approximation: We assume the worst-case sink type if not tracked in summary.
					Type: core.SinkTypeExecution,
					// CanonicalType is unknown here for summarized functions.
				}
				w.reportFinding(argTaint.GetSource(), sinkDef, fullNode)
				return
			}
		}
	}
}

// reportFinding records a detected taint flow.
// Uses core.TaintSource and StaticSinkDefinition
func (w *astWalker) reportFinding(source core.TaintSource, sinkDef StaticSinkDefinition, node *sitter.Node) {
	// source here is the representative source string (potentially joined by "|").

	if source == "" {
		source = core.SourceUnknown
	}

	location := FormatLocation(w.filename, node, w.source)

	// Logging includes the mode for easier debugging of the multi-pass architecture.
	w.logger.Warn("Taint flow detected",
		zap.String("source", string(source)),
		zap.String("sink", string(sinkDef.Name)),
		zap.Int("mode", int(w.mode)),
		zap.String("location", location.String()),
	)

	confidence := "High"
	// If the source is ambiguous (contains SourceUnknown), derived from an unknown function return,
	// or the sink is inter-procedural (call:...), reduce confidence.
	if strings.Contains(string(source), string(core.SourceUnknown)) ||
		strings.HasPrefix(string(sinkDef.Name), "call:") {
		confidence = "Medium"
	}

	// If the source is a specific parameter identified for Hybrid IAST (Step 4), we can note this.
	if strings.HasPrefix(string(source), "param:query:") || strings.HasPrefix(string(source), "param:hash:") || strings.HasPrefix(string(source), "param:storage:") {
		// This indicates a refined source from Step 4.
	}

	finding := StaticFinding{
		Source:   source,
		Sink:     sinkDef.Name,
		SinkType: sinkDef.Type,
		// Ensure CanonicalType is set for correlation (Step 5)
		CanonicalType: sinkDef.CanonicalType,
		Location:      location,
		Confidence:    confidence,
	}

	// --- Data Flow Logic for IPA ---

	if w.mode == ModeAnalyze {
		// Standard analysis phase: store the finding locally.
		w.analyzeFindings = append(w.analyzeFindings, finding)
	} else if w.mode == ModeSummarize {
		// Summarization phase: determine where the finding belongs.

		isParamSourced := false
		isGlobalSourced := false

		// Analyze the representative source string for contributing factors.
		sources := strings.Split(string(source), "|")
		for _, src := range sources {
			if strings.HasPrefix(src, "param:") {
				isParamSourced = true
			} else {
				isGlobalSourced = true
			}
		}

		if isParamSourced {
			// Case 1: Flow from Parameter to Sink. Used to calculate FunctionSummary.
			// Store it temporarily for finalizeSummary to process.
			w.summaryParamFindings = append(w.summaryParamFindings, finding)
		}

		if isGlobalSourced {
			// Case 2: Flow from Global Source to Sink (Intra-Procedural Vulnerability).
			// It MUST be reported immediately to the shared AnalyzerContext.
			// Note: A finding might be added here AND to summaryParamFindings if it involves both global and parameter sources.
			w.context.AddIntraProceduralFinding(finding)
		}
	}
}
