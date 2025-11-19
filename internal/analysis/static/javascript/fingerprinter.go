// Filename: javascript/fingerprinter.go
// This module implements a flow-sensitive static taint analysis engine
// featuring object sensitivity (Level 2) and inter-procedural analysis (Level 3).
package javascript

import (
	"context"
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"go.uber.org/zap"

	// Import core definitions and schemas (Step 1 and Step 5)
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// StaticFinding represents a potential vulnerability found via static analysis.
type StaticFinding struct {
	Source     core.TaintSource
	Sink       core.TaintSink // The specific sink name identified statically
	SinkType   core.SinkType  // The impact category
	Location   LocationInfo
	Confidence string // High, Medium, Low

	// CanonicalType is crucial for correlation with dynamic findings (Step 5).
	CanonicalType schemas.TaintSink
}

// Fingerprinter analyzes JavaScript source code to find potential taint flows.
type Fingerprinter struct {
	logger *zap.Logger
}

// NewFingerprinter creates a new static analyzer.
func NewFingerprinter(logger *zap.Logger) *Fingerprinter {
	return &Fingerprinter{
		logger: logger.Named("js_fingerprinter"),
	}
}

// Analyze parses and analyzes the AST of a JavaScript file using a multi-pass approach.
func (f *Fingerprinter) Analyze(filename, content string) ([]StaticFinding, error) {
	if content == "" {
		return []StaticFinding{}, nil
	}

	f.logger.Debug("Starting analysis of JavaScript file", zap.String("filename", filename), zap.Int("size_bytes", len(content)))

	// 1. Parsing Phase
	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())

	sourceBytes := []byte(content)
	tree, err := parser.ParseCtx(context.Background(), nil, sourceBytes)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter failed to parse %s: %w", filename, err)
	}
	defer tree.Close()

	rootNode := tree.RootNode()
	if rootNode.HasError() {
		f.logger.Warn("Tree-sitter detected syntax errors; analysis may be incomplete", zap.String("file", filename))
	}

	// Initialize the context for inter-procedural analysis.
	ctx := NewAnalyzerContext()

	// 2. Pass 1: Summarization (Level 3)
	f.logger.Debug("Starting Pass 1: Summarization", zap.String("file", filename))
	// Pass the filename for accurate location reporting during summarization.
	f.summarizeFunctions(filename, rootNode, sourceBytes, ctx)

	// 3. Pass 2: Analysis
	f.logger.Debug("Starting Pass 2: Taint Analysis", zap.String("file", filename), zap.Int("summaries_count", len(ctx.Summaries)))

	// Initialize the main walker in Analysis mode.
	walker := newASTWalker(f.logger, filename, sourceBytes, ModeAnalyze, ctx)

	// Perform the analysis on the global scope (Walk the root).
	walker.Walk(rootNode)

	// 4. Result Aggregation (Fix for Failure 2)
	// Combine findings from the Analysis phase (Pass 2) and the Summarization phase (Pass 1).
	analysisFindings := walker.GetAnalyzeFindings()
	intraProcFindings := ctx.GetIntraProceduralFindings()

	finalFindings := append(intraProcFindings, analysisFindings...)

	if len(finalFindings) > 0 {
		f.logger.Info("Analysis completed with findings",
			zap.String("filename", filename),
			zap.Int("total_findings_count", len(finalFindings)),
			zap.Int("intra_procedural_count", len(intraProcFindings)),
			zap.Int("analysis_count", len(analysisFindings)),
		)
	}

	return finalFindings, nil
}

// summarizeFunctions iterates over the AST to find function declarations and summarizes their taint behavior.
func (f *Fingerprinter) summarizeFunctions(filename string, root *sitter.Node, source []byte, ctx *AnalyzerContext) {
	// Use a dedicated visitor to find function nodes.
	finder := &functionFinder{
		logger:   f.logger,
		source:   source,
		context:  ctx,
		filename: filename, // Propagate filename context.
	}
	finder.Walk(root)
}

// functionFinder is a visitor dedicated to finding and initiating summarization for functions.
type functionFinder struct {
	logger   *zap.Logger
	source   []byte
	context  *AnalyzerContext
	filename string
}

// Walk traverses the tree looking for function definitions.
func (ff *functionFinder) Walk(node *sitter.Node) {
	if node == nil {
		return
	}

	// Check current node type
	switch node.Type() {
	case "function_declaration", "generator_function_declaration":
		// function myFunction() {...}
		nameNode := node.ChildByFieldName("name")
		if nameNode != nil {
			ref := RefID(nameNode.Content(ff.source))
			ff.summarize(ref, node)
		}

	case "lexical_declaration", "variable_declaration":
		// const x = ...
		ff.findFunctionsInVarDecl(node)

	case "assignment_expression":
		// x = function() {}
		ff.findFunctionInAssignment(node)
	}

	// Recurse children
	for i := 0; i < int(node.ChildCount()); i++ {
		ff.Walk(node.Child(i))
	}
}

func (ff *functionFinder) findFunctionsInVarDecl(node *sitter.Node) {
	// Iterate variable declarators
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "variable_declarator" {
			nameNode := child.ChildByFieldName("name")
			valueNode := child.ChildByFieldName("value")

			if nameNode != nil && valueNode != nil {
				// Only handle simple identifier bindings for now
				if nameNode.Type() == "identifier" {
					ref := RefID(nameNode.Content(ff.source))
					if isFunctionNode(valueNode) {
						ff.summarize(ref, valueNode)
					}
				}
			}
		}
	}
}

func (ff *functionFinder) findFunctionInAssignment(node *sitter.Node) {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")

	if left != nil && right != nil {
		if left.Type() == "identifier" {
			ref := RefID(left.Content(ff.source))
			if isFunctionNode(right) {
				ff.summarize(ref, right)
			}
		}
	}
}

func isFunctionNode(node *sitter.Node) bool {
	if node == nil {
		return false
	}
	t := node.Type()
	return t == "function" || t == "arrow_function" || t == "function_declaration"
}

// summarize runs the walker in ModeSummarize for a specific function.
func (ff *functionFinder) summarize(ref RefID, funcNode *sitter.Node) {
	if _, exists := ff.context.Summaries[ref]; exists {
		return
	}

	// Create a dedicated walker instance for this function in Summarize mode.
	// CRITICAL: Use the actual filename (ff.filename) for accurate location reporting.
	walker := newASTWalker(ff.logger, ff.filename, ff.source, ModeSummarize, ff.context)
	walker.StartSummarizationWalk(ref, funcNode)
}
