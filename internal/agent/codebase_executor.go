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
	analysisResult, err := e.analyzeCodebase(ctx, packagePattern)
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
func (e *CodebaseExecutor) analyzeCodebase(ctx context.Context, pattern string) (string, error) {
	// FIX: To extract source definitions for dependencies (like stdlib), we must ensure their syntax trees (ASTs) are loaded.
	// By default, packages.Load only loads syntax for the packages matching the input patterns (e.g., "./...").
	// We use a two-step loading process to achieve this.

	// Step 1.1: Load metadata to discover the dependency graph. (loadSyntax=false)
	// This step is fast as it avoids parsing syntax and full type checking for dependencies.
	initialPkgs, err := e.loadPackages(ctx, []string{pattern}, false)
	if err != nil {
		return "", fmt.Errorf("error loading packages initially: %w", err)
	}
	if len(initialPkgs) == 0 {
		return "", fmt.Errorf("no packages were loaded for pattern '%s' in root '%s'", pattern, e.projectRoot)
	}

	// Step 1.2: Identify local packages and all external dependencies.
	// We determine what is "local" based on the initial load.
	mainModule, localPkgs, _ := determineLocalPackages(initialPkgs)
	if mainModule != nil {
		e.logger.Info("Analyzing module", zap.String("path", mainModule.Path))
	}

	// Flatten the graph to find all packages (including transitive dependencies).
	allInitialPkgs := flattenPackages(initialPkgs)
	var externalPatterns []string
	externalPatternsSet := make(map[string]bool)

	for _, pkg := range allInitialPkgs {
		// Identify external packages (including stdlib).
		if !localPkgs[pkg.PkgPath] {
			if _, added := externalPatternsSet[pkg.PkgPath]; !added {
				externalPatterns = append(externalPatterns, pkg.PkgPath)
				externalPatternsSet[pkg.PkgPath] = true
			}
		}
	}

	// Step 1.3: Full load: Load syntax and type info for the main module AND all dependencies.
	// By explicitly including dependencies in the patterns list, they are treated as "root" packages,
	// which forces packages.Load to parse their syntax (loadSyntax=true).
	allPatterns := []string{pattern}
	if len(externalPatterns) > 0 {
		allPatterns = append(allPatterns, externalPatterns...)
		e.logger.Info("Starting full load with syntax", zap.Int("dependencies_count", len(externalPatterns)))
	}

	pkgs, err := e.loadPackages(ctx, allPatterns, true)
	if err != nil {
		e.logger.Error("Failed during full package load", zap.Error(err))
		return "", fmt.Errorf("error during full package load: %w", err)
	}
	if len(pkgs) == 0 {
		// Should be impossible if the initial load succeeded, but checked for safety.
		return "", fmt.Errorf("no packages were loaded during full analysis")
	}

	// 2. Final analysis preparation using the fully loaded data.
	// Flatten the graph again from the new results.
	allPkgs := flattenPackages(pkgs)

	// We must collect the list of `localFiles` from the newly loaded packages that belong to the main module.
	// We call determineLocalPackages again on the full results (which include dependencies as roots)
	// to correctly filter only the files belonging to the main module.
	_, _, localFiles := determineLocalPackages(pkgs)

	// 3. Build a comprehensive symbol table. This now works because syntax is loaded for all packages.
	symbolTable := buildSymbolTable(allPkgs)

	// 4. Find all identifiers used locally that resolve to an external dependency.
	// We use the 'localPkgs' map determined during the initial load to distinguish local vs external usages.
	depsToExtract := findExternalDependencies(allPkgs, localPkgs, symbolTable)

	// 5. Generate the final output string.
	output, err := e.generateOutput(mainModule, localFiles, depsToExtract, symbolTable)
	if err != nil {
		return "", fmt.Errorf("failed to generate analysis output: %w", err)
	}

	return output, nil
}

// flattenPackages takes the initial list of packages from packages.Load and
// recursively walks the Imports map to return a flat, unique list of all packages
// in the dependency graph.
func flattenPackages(initialPkgs []*packages.Package) []*packages.Package {
	allPkgsMap := make(map[string]*packages.Package)
	var queue []*packages.Package
	queue = append(queue, initialPkgs...)

	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]

		// Safety check for nil package pointers
		if pkg == nil {
			continue
		}

		if _, visited := allPkgsMap[pkg.ID]; !visited {
			allPkgsMap[pkg.ID] = pkg
			for _, imp := range pkg.Imports {
				queue = append(queue, imp)
			}
		}
	}

	// Convert map back to slice for consistent return type.
	result := make([]*packages.Package, 0, len(allPkgsMap))
	for _, pkg := range allPkgsMap {
		result = append(result, pkg)
	}
	return result
}

// -- Helper methods integrated from contextor --

// loadPackages configures and runs the Go packages loader.
// If loadSyntax is true, it requests syntax trees and full type information (for deep analysis).
// If false, it only loads metadata required to understand the dependency graph (faster).
func (e *CodebaseExecutor) loadPackages(ctx context.Context, patterns []string, loadSyntax bool) ([]*packages.Package, error) {
	// Define the base required modes for metadata loading.
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedModule

	// Add modes required for deep analysis (syntax, types) if requested.
	if loadSyntax {
		mode |= packages.NeedTypes | packages.NeedTypesSizes |
			packages.NeedSyntax | packages.NeedTypesInfo
	}

	cfg := &packages.Config{
		Context: ctx, // Pass the context to handle cancellation.
		Mode:    mode,
		Tests:   true, // Also include test files.
		Dir:     e.projectRoot,
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
	// Try to find the module explicitly marked as "Main".
	for _, pkg := range pkgs {
		if pkg.Module != nil && pkg.Module.Main {
			mainModule = pkg.Module
			break
		}
	}
	// Fallback if no package is explicitly marked as Main; assume the first one defines the module context if available.
	if mainModule == nil && len(pkgs) > 0 && pkgs[0].Module != nil {
		mainModule = pkgs[0].Module
	}

	localPkgs := make(map[string]bool)
	var localFiles []string

	if mainModule != nil {
		for _, pkg := range pkgs {
			// Check if the package belongs to the main module based on the module path.
			if pkg.Module != nil && pkg.Module.Path == mainModule.Path {
				localPkgs[pkg.PkgPath] = true
				localFiles = append(localFiles, pkg.GoFiles...)
			}
		}
	} else {
		// Fallback if no module information is available (e.g., GOPATH mode or analyzing loose files).
		// Treat all initially loaded packages as local.
		for _, pkg := range pkgs {
			localPkgs[pkg.PkgPath] = true
			localFiles = append(localFiles, pkg.GoFiles...)
		}
	}

	// Sort and deduplicate files for deterministic output.
	sort.Strings(localFiles)
	uniqueFiles := make([]string, 0, len(localFiles))
	seenFiles := make(map[string]bool)
	for _, file := range localFiles {
		if !seenFiles[file] {
			uniqueFiles = append(uniqueFiles, file)
			seenFiles[file] = true
		}
	}

	return mainModule, localPkgs, uniqueFiles
}

// buildSymbolTable creates a map of type objects to their definition sites.
func buildSymbolTable(pkgs []*packages.Package) map[types.Object]Definition {
	symbolTable := make(map[types.Object]Definition)
	for _, pkg := range pkgs {
		// We rely on the two-step loading process to ensure TypesInfo and Syntax are available.
		if pkg.TypesInfo == nil || len(pkg.Syntax) == 0 {
			continue
		}
		// Iterate over all definitions in the package.
		for _, obj := range pkg.TypesInfo.Defs {
			if obj == nil || obj.Pkg() == nil || !obj.Pos().IsValid() {
				continue
			}
			// Find the AST node corresponding to the declaration.
			_, node, _ := findEnclosingDeclaration(pkg, obj.Pos())
			if node == nil {
				continue
			}
			// Get file information and calculate offsets.
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
		// Only inspect packages identified as local.
		if !localPkgs[pkg.PkgPath] {
			continue
		}
		// Walk the AST of each file in the local package.
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				ident, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				// Check if the identifier is a usage of a symbol.
				if obj, ok := pkg.TypesInfo.Uses[ident]; ok && obj != nil && obj.Pkg() != nil {
					// Check if the symbol belongs to an external package.
					if !localPkgs[obj.Pkg().Path()] {
						// Check if we successfully located the definition for this external symbol.
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
	// Cache file content to avoid repeated I/O.
	fileCache := make(map[string][]byte)

	// -- Part 1: Output local source files --
	moduleName := "Project (Unknown Module)"
	if mainModule != nil {
		moduleName = mainModule.Path
	}
	out.WriteString(fmt.Sprintf(moduleSourceCodeHeaderFmt, moduleName))
	out.WriteString("\n\n")

	for _, path := range localFiles {
		// Correctly make file paths relative to the project root.
		relPath, err := filepath.Rel(e.projectRoot, path)
		if err != nil {
			// Fallback to absolute path if relative path cannot be determined.
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

	// Sort dependencies alphabetically for deterministic output.
	sortedDeps := make([]types.Object, 0, len(deps))
	for depObj := range deps {
		sortedDeps = append(sortedDeps, depObj)
	}
	sort.Slice(sortedDeps, func(i, j int) bool {
		// Sort by the full string representation (e.g., "func fmt.Println...")
		return sortedDeps[i].String() < sortedDeps[j].String()
	})

	for _, depObj := range sortedDeps {
		def, ok := symbolTable[depObj]
		if !ok {
			continue
		}

		// Load the dependency source file (if not already cached).
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

		// Extract the specific definition using the stored offsets.
		if def.StartOffset >= 0 && def.EndOffset <= len(content) && def.StartOffset < def.EndOffset {
			out.WriteString(fmt.Sprintf(definitionHeaderFmt, depObj.String(), def.FilePath))
			out.WriteString("\n")
			out.Write(content[def.StartOffset:def.EndOffset])
			out.WriteString("\n\n")
		} else {
			e.logger.Error("Invalid definition offsets calculated during analysis",
				zap.String("symbol", depObj.String()),
				zap.String("file", def.FilePath),
				zap.Int("start", def.StartOffset),
				zap.Int("end", def.EndOffset))
		}
	}

	return out.String(), nil
}

// findEnclosingDeclaration locates the top-level declaration containing a given position.
func findEnclosingDeclaration(pkg *packages.Package, pos token.Pos) (*ast.File, ast.Node, error) {
	// Iterate through the syntax trees (files) of the package.
	for _, file := range pkg.Syntax {
		if file.Pos() <= pos && pos < file.End() {
			// Found the file. Now find the top-level declaration (GenDecl, FuncDecl).
			for _, decl := range file.Decls {
				if decl.Pos() <= pos && pos < decl.End() {
					return file, decl, nil
				}
			}
		}
	}
	// This requires pkg.Syntax to be available for the package where the definition resides.
	return nil, nil, fmt.Errorf("declaration not found for position %d in package %s", pos, pkg.PkgPath)
}
