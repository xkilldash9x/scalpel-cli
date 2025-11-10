package semanticfp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/token"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// FingerprintResult encapsulates the output of the semantic fingerprinting
// process for a single function. It includes the function's name, its semantic
// fingerprint (a hash), the canonical intermediate representation (IR) from
// which the hash was derived, and the function's position in the source code.
type FingerprintResult struct {
	FunctionName string
	Fingerprint  string
	CanonicalIR  string
	Pos          token.Pos // The position of the 'func' keyword, for precise AST matching.
}

// normalizeControlFlow modifies a function's SSA form to create a canonical
// control flow structure. It normalizes conditional branches (e.g., rewriting
// `a >= b` to `a < b` and swapping the successor blocks) to ensure that
// semantically identical logic produces a consistent graph structure.
func normalizeControlFlow(fn *ssa.Function) {
	for _, block := range fn.Blocks {
		if len(block.Instrs) == 0 {
			continue
		}
		// The last instruction is the control flow instruction.
		if ifInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If); ok {
			// Check if the condition is a BinOp we want to normalize.
			if binOp, ok := ifInstr.Cond.(*ssa.BinOp); ok {
				switch binOp.Op {
				case token.GEQ: // >=
					// Normalize >= to <
					binOp.Op = token.LSS
					// Swap the successors. Succs[0] is True, Succs[1] is False.
					block.Succs[0], block.Succs[1] = block.Succs[1], block.Succs[0]
				case token.GTR: // >
					// Normalize > to <=
					binOp.Op = token.LEQ
					block.Succs[0], block.Succs[1] = block.Succs[1], block.Succs[0]
				}
			}
		}
	}
	// Note: We do not need to recompute the dominator tree as we rely on DFS traversal.
}

// GenerateFingerprint is the core function that computes the semantic
// fingerprint for a single SSA function. It first normalizes the function's
// control flow, then generates a canonical string representation of its IR, and
// finally hashes this string to produce the fingerprint.
func GenerateFingerprint(fn *ssa.Function, policy LiteralPolicy, strictMode bool) FingerprintResult {
	// 1.5. Control Flow Normalization
	normalizeControlFlow(fn)

	// 2. IR Canonicalization
	canonicalizer := NewCanonicalizer(policy)
	canonicalizer.StrictMode = strictMode
	canonicalIR := canonicalizer.CanonicalizeFunction(fn)

	// 3. Fingerprint Generation (Hashing)
	hash := sha256.Sum256([]byte(canonicalIR))
	fingerprint := hex.EncodeToString(hash[:])

	return FingerprintResult{
		FunctionName: fn.Name(),
		Fingerprint:  fingerprint,
		CanonicalIR:  canonicalIR,
		// Pos will be set by the caller (processFunctionAndAnons).
	}
}

// loadPackagesFromSource handles the internal loading logic when starting from a source string.
// This is used by FingerprintSource when analyzing temporary snippets (like patch hunks).
func loadPackagesFromSource(filename string, src string) ([]*packages.Package, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("input source code is empty")
	}

	// Determine the context directory for dependency resolution.
	sourceDir := filepath.Dir(filename)
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		// If Abs fails (e.g., dummy filename like "hunk_old_version.go"), use the filename as is.
		absFilename = filename
	}

	fset := token.NewFileSet()

	// Configure the 'packages' loader.
	cfg := &packages.Config{
		// Dir is important for resolving dependencies relative to the project context.
		Dir:  sourceDir,
		Mode: packages.LoadAllSyntax,
		Fset: fset,
		// The Overlay allows analyzing in-memory content.
		Overlay: map[string][]byte{
			absFilename: []byte(src),
		},
		Tests: false,
	}

	// Load the package.
	loadPattern := "file=" + absFilename
	initialPkgs, err := packages.Load(cfg, loadPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to execute loader: %w", err)
	}
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("no packages loaded for %s in context %s", absFilename, sourceDir)
	}

	// Check for errors during loading (parsing, type-checking).
	var errorMessages strings.Builder
	packages.Visit(initialPkgs, nil, func(pkg *packages.Package) {
		for _, e := range pkg.Errors {
			errorMessages.WriteString(e.Error() + "\n")
		}
	})

	if errorMessages.Len() > 0 {
		return nil, fmt.Errorf("packages contain errors: \n%s", errorMessages.String())
	}

	return initialPkgs, nil
}

// FingerprintSource is a high-level entry point for fingerprinting a single Go
// source file provided as a string. It handles the parsing, type-checking, and
// SSA construction before generating fingerprints for all functions within the
// source. It is best suited for analyzing isolated snippets, such as diff hunks.
func FingerprintSource(filename string, src string, policy LiteralPolicy) ([]FingerprintResult, error) {
	return FingerprintSourceAdvanced(filename, src, policy, false)
}

// FingerprintSourceAdvanced is an extended version of `FingerprintSource` that
// provides additional control over the fingerprinting process, such as enabling
// a strict mode that will panic on unhandled SSA instructions.
func FingerprintSourceAdvanced(filename string, src string, policy LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	// Load packages from the source string.
	initialPkgs, err := loadPackagesFromSource(filename, src)
	if err != nil {
		return nil, err
	}

	// Use the centralized function to process the loaded packages.
	return FingerprintPackages(initialPkgs, policy, strictMode)
}

// FingerprintPackages is the most efficient entry point for fingerprinting when
// the Go packages have already been loaded by the calling application. It takes
// the loaded packages, builds their SSA representation, and generates
// fingerprints for all non-synthetic functions.
func FingerprintPackages(initialPkgs []*packages.Package, policy LiteralPolicy, strictMode bool) ([]FingerprintResult, error) {
	if len(initialPkgs) == 0 {
		return nil, fmt.Errorf("input packages list is empty")
	}

	// Build SSA from the loaded packages.
	// We primarily care about the first package provided (the target source file).
	_, ssaPkg, err := BuildSSAFromPackages(initialPkgs)
	if err != nil {
		return nil, fmt.Errorf("failed to build SSA from packages: %w", err)
	}

	var results []FingerprintResult
	// Iterate over members of the target package.
	for _, member := range ssaPkg.Members {
		if fn, ok := member.(*ssa.Function); ok {
			// Process the function and any anonymous functions defined within it.
			processFunctionAndAnons(fn, policy, strictMode, &results)
		}
	}

	// Sort results alphabetically for deterministic output.
	sort.Slice(results, func(i, j int) bool {
		return results[i].FunctionName < results[j].FunctionName
	})

	return results, nil
}

// Helper function to recursively process a function and any anonymous functions defined within it.
func processFunctionAndAnons(fn *ssa.Function, policy LiteralPolicy, strictMode bool, results *[]FingerprintResult) {
	// Strictly skip synthetic functions. User-defined init functions are NOT marked synthetic.
	if fn.Synthetic == "" {
		// Generate the fingerprint if it has implementation (Blocks > 0).
		if len(fn.Blocks) > 0 {
			result := GenerateFingerprint(fn, policy, strictMode)
			// Set the position information from the SSA function metadata.
			result.Pos = fn.Pos()
			*results = append(*results, result)
		}
	}

	// Recurse into anonymous functions (closures).
	for _, anon := range fn.AnonFuncs {
		processFunctionAndAnons(anon, policy, strictMode, results)
	}
}
