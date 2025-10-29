// internal/agent/codebase_executor.go
package agent

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"

	"go.uber.org/zap"
	"golang.org/x/tools/go/packages"
)

const (
	// -- Headers used for separating sections in the final output --
	moduleSourceCodeHeaderFmt = "## Source Code for Module: %s ##"
	dependenciesHeader        = "## Discovered External Dependencies ##"
	fileHeaderFmt             = "-- File: %s --"
	definitionHeaderFmt       = "-- Definition for: %s (from %s) --"
)

// Definition holds the location and source offsets for a symbol's declaration.
type Definition struct {
	FilePath    string
	StartOffset int
	EndOffset   int
}

// Execute handles the GATHER_CODEBASE_CONTEXT action by performing deep static analysis.
func (e *CodebaseExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	if action.Type != ActionGatherCodebaseContext {
		return nil, fmt.Errorf("codebase executor cannot handle action type: %s", action.Type)
	}

	// The module_path is now interpreted as a package pattern (e.g., "./...").
	packagePattern, ok := action.Metadata["module_path"].(string)
	if !ok || packagePattern == "" {
		packagePattern = "./..." // Default to analyzing the entire project.
	}

	e.logger.Info("Executing deep codebase analysis", zap.String("pattern", packagePattern))

	// -- Main analysis logic integrated from contextor --
	analysisResult, err := e.analyzeCodebase(packagePattern)
	if err != nil {
		e.logger.Error("Failed to perform codebase analysis", zap.Error(err))
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedCodebaseContext,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": err.Error()},
		}, nil
	}

	// The result payload contains the full analysis output.
	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedCodebaseContext,
		Data:            analysisResult,
	}, nil
}

// analyzeCodebase orchestrates the full static analysis workflow.
func (e *CodebaseExecutor) analyzeCodebase(pattern string) (string, error) {
	// 1. Load, parse, and type check the packages.
	// FIX: Removed os.Chdir(). (Guide 1.2)
	// os.Chdir() modifies the working directory for the entire process, which is unsafe
	// in a concurrent environment. The packages.Load configuration (specifically cfg.Dir
	// in loadPackages) already correctly handles the project root context.

	pkgs, err := e.loadPackages([]string{pattern})
	if err != nil {
		return "", fmt.Errorf("error loading packages: %w", err)
	}
	if len(pkgs) == 0 {
		// Improve error message clarity.
		return "", fmt.Errorf("no packages were loaded for pattern '%s' in root '%s'", pattern, e.projectRoot)
	}

	// 2. Identify the packages belonging to the main module.
	mainModule, localPkgs, localFiles := determineLocalPackages(pkgs)
	if mainModule != nil {
		e.logger.Info("Analyzing module", zap.String("path", mainModule.Path))
	}

	// 3. Build a comprehensive symbol table for all loaded code.
	symbolTable := buildSymbolTable(pkgs)

	// 4. Find all identifiers that resolve to an external dependency.
	depsToExtract := findExternalDependencies(pkgs, localPkgs, symbolTable)

	// 5. Generate the final output string.
	output, err := e.generateOutput(mainModule, localFiles, depsToExtract, symbolTable)
	if err != nil {
		return "", fmt.Errorf("failed to generate analysis output: %w", err)
	}

	return output, nil
}

// -- Helper methods integrated from contextor --

// loadPackages configures and runs the Go packages loader.
func (e *CodebaseExecutor) loadPackages(patterns []string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedModule,
		Tests: true, // Also include test files.
		Dir:   e.projectRoot,
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}

	if packages.PrintErrors(pkgs) > 0 {
		e.logger.Warn("Errors were found while loading packages, attempting to continue.")
	}

	var hasGoFiles bool
	for _, p := range pkgs {
		if len(p.GoFiles) > 0 {
			hasGoFiles = true
			break
		}
	}
	if !hasGoFiles {
		return nil, nil // Return nil slice to signal no packages were loaded.
	}

	return pkgs, nil
}

// determineLocalPackages identifies the main module and collects all packages and source files that belong to it.
func determineLocalPackages(pkgs []*packages.Package) (*packages.Module, map[string]bool, []string) {
	var mainModule *packages.Module
	for _, pkg := range pkgs {
		if pkg.Module != nil && pkg.Module.Main {
			mainModule = pkg.Module
			break
		}
	}
	if mainModule == nil && len(pkgs) > 0 && pkgs[0].Module != nil {
		mainModule = pkgs[0].Module
	}

	localPkgs := make(map[string]bool)
	var localFiles []string

	if mainModule != nil {
		for _, pkg := range pkgs {
			if pkg.Module != nil && pkg.Module.Path == mainModule.Path {
				localPkgs[pkg.PkgPath] = true
				localFiles = append(localFiles, pkg.GoFiles...)
			}
		}
	} else {
		for _, pkg := range pkgs {
			localPkgs[pkg.PkgPath] = true
			localFiles = append(localFiles, pkg.GoFiles...)
		}
	}

	sort.Strings(localFiles)
	uniqueFiles := make([]string, 0, len(localFiles))
	if len(localFiles) > 0 {
		uniqueFiles = append(uniqueFiles, localFiles[0])
		for i := 1; i < len(localFiles); i++ {
			if localFiles[i] != localFiles[i-1] {
				uniqueFiles = append(uniqueFiles, localFiles[i])
			}
		}
	}

	return mainModule, localPkgs, uniqueFiles
}

// buildSymbolTable creates a map of type objects to their definition sites.
func buildSymbolTable(pkgs []*packages.Package) map[types.Object]Definition {
	symbolTable := make(map[types.Object]Definition)
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, obj := range pkg.TypesInfo.Defs {
			if obj == nil || obj.Pkg() == nil || !obj.Pos().IsValid() {
				continue
			}
			_, node, _ := findEnclosingDeclaration(pkg, obj.Pos())
			if node == nil {
				continue
			}
			tokenFile := pkg.Fset.File(obj.Pos())
			if tokenFile == nil {
				continue
			}
			symbolTable[obj] = Definition{
				FilePath:    tokenFile.Name(),
				StartOffset: tokenFile.Offset(node.Pos()),
				EndOffset:   tokenFile.Offset(node.End()),
			}
		}
	}
	return symbolTable
}

// findExternalDependencies inspects the AST of local packages to find usages of external symbols.
func findExternalDependencies(pkgs []*packages.Package, localPkgs map[string]bool, symbolTable map[types.Object]Definition) map[types.Object]bool {
	depsToExtract := make(map[types.Object]bool)
	for _, pkg := range pkgs {
		if !localPkgs[pkg.PkgPath] {
			continue
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				ident, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if obj, ok := pkg.TypesInfo.Uses[ident]; ok && obj != nil && obj.Pkg() != nil {
					if !localPkgs[obj.Pkg().Path()] {
						if _, exists := symbolTable[obj]; exists {
							depsToExtract[obj] = true
						}
					}
				}
				return true
			})
		}
	}
	return depsToExtract
}

// generateOutput constructs the final text output.
func (e *CodebaseExecutor) generateOutput(mainModule *packages.Module, localFiles []string, deps map[types.Object]bool, symbolTable map[types.Object]Definition) (string, error) {
	var out bytes.Buffer
	fileCache := make(map[string][]byte)

	// -- Part 1: Output local source files --
	if mainModule != nil {
		out.WriteString(fmt.Sprintf(moduleSourceCodeHeaderFmt, mainModule.Path))
	}
	out.WriteString("\n\n")

	for _, path := range localFiles {
		// a little heuristic to make file paths relative to the project root
		relPath, err := filepath.Rel(e.projectRoot, path)
		if err != nil {
			relPath = path
		}
		content, err := os.ReadFile(path)
		if err != nil {
			e.logger.Warn("Failed to read source file", zap.String("path", path), zap.Error(err))
			continue
		}
		fileCache[path] = content
		out.WriteString(fmt.Sprintf(fileHeaderFmt, relPath))
		out.WriteString("\n")
		out.Write(content)
		out.WriteString("\n\n")
	}

	// -- Part 2: Output external dependency definitions --
	out.WriteString(dependenciesHeader)
	out.WriteString("\n\n")

	sortedDeps := make([]types.Object, 0, len(deps))
	for depObj := range deps {
		sortedDeps = append(sortedDeps, depObj)
	}
	sort.Slice(sortedDeps, func(i, j int) bool {
		return sortedDeps[i].String() < sortedDeps[j].String()
	})

	for _, depObj := range sortedDeps {
		def, ok := symbolTable[depObj]
		if !ok {
			continue
		}
		content, inCache := fileCache[def.FilePath]
		if !inCache {
			var readErr error
			content, readErr = os.ReadFile(def.FilePath)
			if readErr != nil {
				e.logger.Warn("Failed to read dependency file", zap.String("path", def.FilePath), zap.Error(readErr))
				continue
			}
			fileCache[def.FilePath] = content
		}
		if def.StartOffset >= 0 && def.EndOffset <= len(content) && def.StartOffset < def.EndOffset {
			out.WriteString(fmt.Sprintf(definitionHeaderFmt, depObj.String(), def.FilePath))
			out.WriteString("\n")
			out.Write(content[def.StartOffset:def.EndOffset])
			out.WriteString("\n\n")
		}
	}

	return out.String(), nil
}

// findEnclosingDeclaration locates the top-level declaration containing a given position.
func findEnclosingDeclaration(pkg *packages.Package, pos token.Pos) (*ast.File, ast.Node, error) {
	for _, file := range pkg.Syntax {
		if file.Pos() <= pos && pos < file.End() {
			for _, decl := range file.Decls {
				if decl.Pos() <= pos && pos < decl.End() {
					return file, decl, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("declaration not found for position %d", pos)
}
