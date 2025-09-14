// internal/agent/codebase_executor.go
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	// "go/ast" // Removed unused import
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/mod/modfile"
	// schemas import removed as we use internal models
)

// CodebaseExecutor is responsible for executing actions related to static code analysis.
type CodebaseExecutor struct {
	logger      *zap.Logger
	projectRoot string
}

// Ensure CodebaseExecutor implements the agent.ActionExecutor interface.
var _ ActionExecutor = (*CodebaseExecutor)(nil)

// NewCodebaseExecutor creates a new instance of the executor.
func NewCodebaseExecutor(logger *zap.Logger, projectRoot string) *CodebaseExecutor {
	return &CodebaseExecutor{
		logger:      logger.Named("codebase_executor"),
		projectRoot: projectRoot,
	}
}

// Execute handles the GATHER_CODEBASE_CONTEXT action.
func (e *CodebaseExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	if action.Type != ActionGatherCodebaseContext {
		return nil, fmt.Errorf("codebase executor cannot handle action type: %s", action.Type)
	}

	modulePath, ok := action.Metadata["module_path"].(string)
	if !ok || modulePath == "" {
		return nil, fmt.Errorf("GATHER_CODEBASE_CONTEXT action requires a 'module_path' string in metadata")
	}

	e.logger.Info("Executing codebase analysis", zap.String("module_path", modulePath))

	// Rerun the dependency mapping logic for the specified module.
	deps, err := buildDependencyMap(e.projectRoot)
	if err != nil {
		e.logger.Error("Failed to build dependency map", zap.Error(err))
		return &ExecutionResult{
			Status:          "failed",
			Error:           err.Error(),
			ObservationType: ObservedCodebaseContext,
		}, err
	}

	depsJSON, err := json.Marshal(deps)
	if err != nil {
		e.logger.Error("Failed to marshal dependencies to JSON", zap.Error(err))
		return &ExecutionResult{
			Status:          "failed",
			Error:           err.Error(),
			ObservationType: ObservedCodebaseContext,
		}, err
	}

	// The result payload contains the dependency graph as a JSON string.
	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedCodebaseContext,
		Data:            string(depsJSON),
	}, nil
}

// buildDependencyMap (Implementation remains unchanged from the prompt)
func buildDependencyMap(projectDir string) (map[string][]string, error) {
	deps := make(map[string][]string)
	fset := token.NewFileSet()

	goModuleName, err := getGoModuleName(projectDir)
	if err != nil {
		return nil, err
	}

	err = filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".go") {
			relPath, err := filepath.Rel(projectDir, path)
			if err != nil {
				return err
			}

			fileDependencies := make(map[string]struct{})
			node, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not parse Go file %s: %v\n", relPath, err)
				return nil
			}

			for _, importSpec := range node.Imports {
				importPath := strings.Trim(importSpec.Path.Value, `"`)
				if !strings.HasPrefix(importPath, goModuleName) && !strings.HasPrefix(importPath, ".") && !strings.HasPrefix(importPath, "..") {
					continue
				}

				var resolvedPath string
				if strings.HasPrefix(importPath, goModuleName) {
					resolvedPath = filepath.Join(projectDir, strings.TrimPrefix(importPath, goModuleName+"/"))
				} else {
					resolvedPath = filepath.Join(filepath.Dir(path), importPath)
				}

				resolvedPath = filepath.Clean(resolvedPath)
				dirInfo, err := os.Stat(resolvedPath)
				if err == nil && dirInfo.IsDir() {
					files, err := os.ReadDir(resolvedPath)
					if err == nil {
						for _, file := range files {
							if !file.IsDir() && strings.HasSuffix(file.Name(), ".go") {
								fullFile := filepath.Join(resolvedPath, file.Name())
								relFile, _ := filepath.Rel(projectDir, fullFile)
								fileDependencies[relFile] = struct{}{}
							}
						}
					}
				}
			}

			if len(fileDependencies) > 0 {
				var dependencies []string
				for dep := range fileDependencies {
					dependencies = append(dependencies, dep)
				}
				deps[relPath] = dependencies
			}
		}
		return nil
	})

	return deps, err
}

// getGoModuleName (Implementation remains unchanged from the prompt)
func getGoModuleName(projectDir string) (string, error) {
	modPath := filepath.Join(projectDir, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		return "", fmt.Errorf("could not read go.mod file at %s: %w", modPath, err)
	}

	modFile, err := modfile.Parse(modPath, data, nil)
	if err != nil {
		return "", fmt.Errorf("could not parse go.mod file: %w", err)
	}

	return modFile.Module.Mod.Path, nil
}