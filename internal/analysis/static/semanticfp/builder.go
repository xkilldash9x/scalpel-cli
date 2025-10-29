package semanticfp

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// BuildSSAFromPackages constructs the SSA representation for the given loaded packages.
// It assumes the packages have been loaded with at least packages.LoadAllSyntax mode
// and that the caller has checked for critical errors in the packages.
func BuildSSAFromPackages(initialPkgs []*packages.Package) (*ssa.Program, *ssa.Package, error) {
	if len(initialPkgs) == 0 {
		// This function should only be called with non-empty input by the fingerprinter.
		return nil, nil, fmt.Errorf("input packages list is empty")
	}

	// Although the caller should check errors, we perform a secondary check
	// to ensure SSA construction doesn't proceed on broken packages.
	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			// Filter out minor errors if necessary, but typically any error prevents SSA build.
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	if errorMessages.Len() > 0 {
		// This case indicates errors occurred during loading (e.g., syntax/type errors).
		return nil, nil, fmt.Errorf("packages contain errors (cannot build SSA): \n%s", errorMessages.String())
	}

	// 1. SSA Generation.
	// Use ssautil.AllPackages to build SSA for the initial packages and their dependencies.
	prog, pkgs := ssautil.AllPackages(initialPkgs, ssa.BuilderMode(0))
	if prog == nil {
		return nil, nil, fmt.Errorf("failed to initialize SSA program builder")
	}

	// Build the SSA program.
	prog.Build()

	// 2. Find the specific ssa.Package corresponding to the first initial package.
	// We assume the primary package of interest (the one we are fingerprinting) is the first one.
	mainPkg := initialPkgs[0]
	var ssaPkg *ssa.Package

	// The 'pkgs' slice corresponds element-wise to 'initialPkgs'.
	for i, p := range initialPkgs {
		if p == mainPkg && i < len(pkgs) && pkgs[i] != nil {
			ssaPkg = pkgs[i]
			break
		}
	}

	// Fallback mechanism if the direct mapping fails (less common).
	if ssaPkg == nil && mainPkg.Types != nil {
		ssaPkg = prog.Package(mainPkg.Types)
	}

	if ssaPkg == nil {
		return nil, nil, fmt.Errorf("could not find main SSA package corresponding to %s in the program", mainPkg.ID)
	}

	return prog, ssaPkg, nil
}
