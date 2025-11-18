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
	baseSource := TaintSource(fmt.Sprintf("param:%d", index))
	loc := int(paramNode.StartPoint().Row)

	// Use a recursive helper to handle potential destructuring with path sensitivity.
	w.initializeDestructuredParameter(paramNode, baseSource, loc)
}

// initializeDestructuredParameter recursively assigns symbolic taint sources (e.g., param:0.prop) to bindings in a parameter pattern.
func (w *astWalker) initializeDestructuredParameter(pattern *sitter.Node, currentSource TaintSource, loc int) {
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
				nextSource := TaintSource(fmt.Sprintf("%s.%s", currentSource, propName))
				w.initializeDestructuredParameter(child, nextSource, loc)

			case "pair_pattern":
				// { key: value_pattern } -> value_pattern gets source.key
				key := child.ChildByFieldName("key")
				valuePattern := child.ChildByFieldName("value")

				propName, staticallyKnown := w.extractStaticKeyName(key)
				var nextSource TaintSource
				if staticallyKnown {
					nextSource = TaintSource(fmt.Sprintf("%s.%s", currentSource, propName))
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
				paramIndex, ok := w.extractParamIndex(TaintSource(source))
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
func (w *astWalker) extractParamIndex(source TaintSource) (int, bool) {
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
		if source, isSource := CheckIfPropertySource(path); isSource {
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
			return NewSimpleTaint(SourceUnknown, int(node.StartPoint().Row)).Merge(objTaint)
		}
	}

	// Approximation: Accessing a property on a tainted non-object (SimpleTaint).
	if targetState.IsTainted() {
		// We propagate the taint but lose precision on the property access itself.
		// We merge SourceUnknown into the existing taint state.
		return targetState.Merge(NewSimpleTaint(SourceUnknown, int(node.StartPoint().Row)))
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

func (w *astWalker) evaluateCallTaint(node *sitter.Node) TaintState {
	callee := node.ChildByFieldName("function")
	argsNode := node.ChildByFieldName("arguments")

	path := flattenPropertyAccess(callee, w.source)

	// 1. Check known APIs (Sources, Sanitizers)
	if path != nil {
		if source, isSource := CheckIfFunctionSource(path); isSource {
			return NewSimpleTaint(source, int(node.StartPoint().Row))
		}
		if CheckIfSanitizer(path) {
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
		w.updateTaintTarget(obj, NewSimpleTaint(SourceUnknown, int(node.StartPoint().Row)))
	}

	// Approximation: Return value inherits argument taint for unknown functions.
	if mergedTaint != nil {
		// We merge the existing taint with SourceUnknown to signify approximation.
		return mergedTaint.Merge(NewSimpleTaint(SourceUnknown, int(node.StartPoint().Row)))
	}

	return nil
}

func (w *astWalker) evaluateCallWithSummary(callNode, argsNode *sitter.Node, summary *FunctionSummary) TaintState {
	// Case 1: Function inherently returns taint (from global source).
	if summary.TaintsReturn {
		funcName := string(summary.RefID)
		// Propagate the specific return source marker.
		source := TaintSource(fmt.Sprintf("return:%s", funcName))
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

// handleVarDecl processes variable declarations, now supporting destructuring.
func (w *astWalker) handleVarDecl(node *sitter.Node) {
	// Iterate over variable_declarator children.
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "variable_declarator" {
			// 'namePattern' can be identifier, object_pattern, or array_pattern.
			namePattern := child.ChildByFieldName("name")
			value := child.ChildByFieldName("value")

			if value != nil {
				taintState := w.evaluateTaint(value)
				// Use the general destructuring handler for all pattern types.
				w.handleDestructuring(namePattern, taintState)
			} else {
				// Declaration without initialization (e.g., var x;). Ensure state is cleared (untainted).
				w.handleDestructuring(namePattern, nil)
			}
		}
	}
}

// handleDestructuring recursively propagates taint from a source state to bindings defined in a pattern.
func (w *astWalker) handleDestructuring(pattern *sitter.Node, sourceState TaintState) {
	if pattern == nil {
		return
	}

	switch pattern.Type() {
	case "identifier", "shorthand_property_identifier_pattern":
		// Base case: Bind the source state directly to the identifier.
		ref := RefID(pattern.Content(w.source))
		w.taintBinding(ref, sourceState)

	case "object_pattern":
		// { a, b: c } = sourceState
		w.handleObjectDestructuring(pattern, sourceState)

	case "array_pattern":
		// [ a, b ] = sourceState
		w.handleArrayDestructuring(pattern, sourceState)

	case "assignment_pattern":
		// { a = defaultValue } = sourceState or (a = defaultValue)
		left := pattern.ChildByFieldName("left")
		// Approximation: If sourceState is tainted, it overrides the default.
		if sourceState != nil && sourceState.IsTainted() {
			w.handleDestructuring(left, sourceState)
		} else {
			// If sourceState is untainted (or nil/missing), the default value is used.
			right := pattern.ChildByFieldName("right")
			defaultValueTaint := w.evaluateTaint(right)
			w.handleDestructuring(left, defaultValueTaint)
		}

	case "rest_parameter":
		// { ...rest } = sourceState or [...rest] or function(...rest)
		// The argument is often at index 1 or by field name 'argument'.
		arg := pattern.ChildByFieldName("argument")
		if arg == nil && pattern.ChildCount() > 1 {
			arg = pattern.Child(1)
		}
		// Approximation: 'rest' inherits the overall taint status of the source.
		w.handleDestructuring(arg, sourceState)

	}
}

// handleObjectDestructuring processes object patterns { key: binding, shorthand }.
func (w *astWalker) handleObjectDestructuring(pattern *sitter.Node, sourceState TaintState) {
	// If the source is not tainted, clear all bindings in the pattern.
	if sourceState == nil || !sourceState.IsTainted() {
		// Recurse with nil state to clear bindings.
		// We must iterate children explicitly here to handle nested patterns correctly.
		for i := 0; i < int(pattern.ChildCount()); i++ {
			child := pattern.Child(i)
			switch child.Type() {
			case "pair_pattern":
				w.handleDestructuring(child.ChildByFieldName("value"), nil)
			case "shorthand_property_identifier_pattern", "rest_parameter", "assignment_pattern":
				w.handleDestructuring(child, nil)
			}
		}
		return
	}

	objTaint, isObject := sourceState.(*ObjectTaint)

	// Helper function to determine the taint for a binding.
	getBindingTaint := func(propName string, staticallyKnown bool) TaintState {
		if isObject {
			if staticallyKnown {
				return objTaint.GetPropertyTaint(propName)
			}
			// Computed access or structure tainted.
			if objTaint.IsTainted() {
				// Propagate the object's taint sources approximately.
				return NewSimpleTaint(SourceUnknown, int(pattern.StartPoint().Row)).Merge(objTaint)
			}
			return nil
		}
		// Destructuring a SimpleTaint value. Propagate the exact source state.
		return sourceState
	}

	for i := 0; i < int(pattern.ChildCount()); i++ {
		child := pattern.Child(i)
		switch child.Type() {
		case "pair_pattern":
			// { key: binding_pattern }
			key := child.ChildByFieldName("key")
			value := child.ChildByFieldName("value") // The binding pattern

			propName, staticallyKnown := w.extractStaticKeyName(key)
			bindingTaint := getBindingTaint(propName, staticallyKnown)

			w.handleDestructuring(value, bindingTaint)

		case "shorthand_property_identifier_pattern":
			// { shorthand }
			propName := NodeContent(child, w.source)
			bindingTaint := getBindingTaint(propName, true)

			// The child node IS the binding target.
			w.handleDestructuring(child, bindingTaint)

		case "rest_parameter", "assignment_pattern":
			// Handled in the generic handleDestructuring switch.
			// For rest, we approximate with the full source state.
			// For assignment, handleDestructuring manages the default value logic.
			w.handleDestructuring(child, sourceState)
		}
	}
}

// handleArrayDestructuring processes array patterns [a, , b].
func (w *astWalker) handleArrayDestructuring(pattern *sitter.Node, sourceState TaintState) {
	if sourceState == nil || !sourceState.IsTainted() {
		// Clear bindings
		for i := 0; i < int(pattern.ChildCount()); i++ {
			child := pattern.Child(i)
			if child.Type() != "[" && child.Type() != "]" && child.Type() != "," {
				w.handleDestructuring(child, nil)
			}
		}
		return
	}

	// If the source is tainted, propagate that taint to all elements.
	// We lose precision on specific indices for array destructuring in this model.

	// We use the sourceState directly if it's SimpleTaint.
	taintToPropagate := sourceState

	// If it's an ObjectTaint (representing an Array), we treat array access as generally tainted.
	if obj, ok := sourceState.(*ObjectTaint); ok && obj.IsTainted() {
		// Approximation for array elements when structure is known but indices are not tracked.
		taintToPropagate = NewSimpleTaint(SourceUnknown, int(pattern.StartPoint().Row)).Merge(obj)
	}

	for i := 0; i < int(pattern.ChildCount()); i++ {
		child := pattern.Child(i)
		switch child.Type() {
		case "[", "]", ",":
			continue
		default:
			// identifier, rest_parameter, or nested pattern (e.g., assignment_pattern)
			w.handleDestructuring(child, taintToPropagate)
		}
	}
}

func (w *astWalker) handleAssignment(node *sitter.Node) {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	// Operator detection robustness: use field name or traversal.
	operatorNode := node.ChildByFieldName("operator")

	// 1. Evaluate RHS.
	rhsTaint := w.evaluateTaint(right)
	isTainted := rhsTaint != nil && rhsTaint.IsTainted()

	// 2. Determine operator.
	var op string
	if operatorNode != nil {
		op = operatorNode.Content(w.source)
	} else {
		// Fallback logic if named field is missing (e.g., simple '=' might be anonymous).
		// We traverse children to find the token between LHS and RHS.
		if left != nil && right != nil {
			cursor := sitter.NewTreeCursor(node)
			defer cursor.Close()
			if cursor.GoToFirstChild() {
				foundLeft := false
				for {
					current := cursor.CurrentNode()
					if current == left {
						foundLeft = true
					} else if current == right {
						break // Reached RHS
					} else if foundLeft {
						// This node is between LHS and RHS, it must be the operator.
						op = current.Content(w.source)
						break
					}
					if !cursor.GoToNextSibling() {
						break
					}
				}
			}
		}
	}

	// Final fallback if detection fails (e.g. complex destructuring might lack explicit operator node).
	if op == "" {
		op = "="
	}

	// 3. Check for Sinks.
	// We only check sinks for standard assignments, not destructuring patterns (patterns on LHS).
	isPattern := left != nil && (left.Type() == "object_pattern" || left.Type() == "array_pattern")
	if op == "=" && isTainted && !isPattern {
		w.checkAssignmentSink(left, rhsTaint, node)
	}

	// 4. Update State (Propagation).
	if op == "=" {
		// Strong update (overwrite).
		w.updateTaintTarget(left, rhsTaint)
	} else {
		// Compound assignment (+=) - Weak update (merge).
		lhsTaint := w.evaluateTaint(left)

		var finalState TaintState
		if lhsTaint != nil {
			finalState = lhsTaint.Merge(rhsTaint)
		} else {
			finalState = rhsTaint
		}

		// We update the target even if the final state is untainted (e.g., "safe" += "").
		w.updateTaintTarget(left, finalState)
	}
}

func (w *astWalker) taintBinding(ref RefID, state TaintState) {
	if state == nil || !state.IsTainted() {
		delete(w.symbolTaint, ref)
	} else {
		w.symbolTaint[ref] = state
	}
}

// updateTaintTarget updates the state of a variable, property, or destructuring pattern.
func (w *astWalker) updateTaintTarget(target *sitter.Node, state TaintState) {
	if target == nil {
		return
	}

	// handleDestructuring handles all identifier, pattern, and assignment types.
	if target.Type() == "member_expression" || target.Type() == "subscript_expression" {
		w.updatePropertyTaint(target, state)
	} else {
		// This covers identifiers and destructuring patterns (object_pattern, array_pattern).
		w.handleDestructuring(target, state)
	}
}

func (w *astWalker) updatePropertyTaint(target *sitter.Node, state TaintState) {
	object := target.ChildByFieldName("object")

	// Simplified tracking: only track properties on simple identifiers (variables) or 'this'.
	if object == nil || (object.Type() != "identifier" && object.Type() != "this") {
		// Complex base (e.g. getObj().prop = x). We skip precise tracking for this assignment.
		return
	}

	ref := RefID(object.Content(w.source))
	baseState := w.symbolTaint[ref]

	// If the base state is SimpleTaint, assignment to a property overwrites it with an ObjectTaint.
	// This correctly models JavaScript behavior where types can change dynamically (e.g. x=taint; x.p=1;).
	objTaint, ok := baseState.(*ObjectTaint)
	if !ok {
		// Initialize a new object structure, overwriting previous state.
		objTaint = NewObjectTaint()
	}

	// Determine the property name.
	propName, staticallyKnown := w.determinePropertyName(target)

	updated := false
	if staticallyKnown {
		// Strong update: overwrite the property state.
		objTaint.SetPropertyTaint(propName, state)
		updated = true
	} else if state != nil && state.IsTainted() {
		// Weak update (Computed access assignment): loss of precision.
		objTaint.StructureTainted = true
		updated = true
	}

	// Update the symbol table if the object state changed or was newly created.
	if updated {
		// We update the symbol table if the object has properties or is structure tainted.
		if objTaint.IsTainted() || len(objTaint.Properties) > 0 {
			w.symbolTaint[ref] = objTaint
		} else {
			// Clean up if the object is now empty and untainted.
			delete(w.symbolTaint, ref)
		}
	}
}

// -- Sink Detection --

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

func (w *astWalker) checkArgsAgainstSink(sinkDef SinkDefinition, argsNode *sitter.Node, fullNode *sitter.Node) {
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
				sinkDef := SinkDefinition{
					// We report the argument index i.
					Name: TaintSink(fmt.Sprintf("call:%s(arg:%d)", funcName, i)),
					// Approximation: We assume the worst-case sink type if not tracked in summary.
					Type: SinkTypeExecution,
				}
				w.reportFinding(argTaint.GetSource(), sinkDef, fullNode)
				return
			}
		}
	}
}

// reportFinding records a detected taint flow.
func (w *astWalker) reportFinding(source TaintSource, sinkDef SinkDefinition, node *sitter.Node) {
	// source here is the representative source string (potentially joined by "|").

	if source == "" {
		source = SourceUnknown
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
	if strings.Contains(string(source), string(SourceUnknown)) ||
		strings.HasPrefix(string(sinkDef.Name), "call:") {
		confidence = "Medium"
	}

	finding := StaticFinding{
		Source:     source,
		Sink:       sinkDef.Name,
		SinkType:   sinkDef.Type,
		Location:   location,
		Confidence: confidence,
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
