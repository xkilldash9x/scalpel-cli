package semanticfp

import (
	"go/constant"
	"go/token"
	"math"

	"golang.org/x/tools/go/ssa"
)

// LiteralPolicy defines a configurable strategy for determining which literal
// values (e.g., numbers, strings) should be abstracted into placeholders during
// the canonicalization of SSA form. This allows fingerprinting to focus on
// program structure and logic rather than specific data values.
type LiteralPolicy struct {
	AbstractControlFlowComparisons bool   // If true, abstracts literals used in `if` conditions.
	KeepSmallIntegerIndices        bool   // If true, preserves small integers used as array/slice indices.
	KeepReturnStatusValues         bool   // If true, preserves small integers used in `return` statements.
	SmallIntMin                    int64  // The minimum value for an integer to be considered "small".
	SmallIntMax                    int64  // The maximum value for an integer to be considered "small".
	AbstractOtherTypes             bool   // If true, abstracts non-integer literals like strings and floats.
}

// DefaultLiteralPolicy is the standard policy for fingerprinting. It abstracts
// most literals, including strings and large numbers, but preserves small
// integers used in common contexts like array indexing and return codes, making
// the fingerprint resilient to minor refactoring while retaining key semantics.
var DefaultLiteralPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: true,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	SmallIntMin:                    -16,
	SmallIntMax:                    16,
	AbstractOtherTypes:             true, // Abstract strings, floats by default
}

// KeepAllLiteralsPolicy is a policy designed for testing or exact matching. It
// disables most abstractions, causing the canonical form to retain almost all
// literal values. This results in a fingerprint that is highly sensitive to any
// change in constants.
var KeepAllLiteralsPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: false,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	SmallIntMin:                    math.MinInt64,
	SmallIntMax:                    math.MaxInt64,
	AbstractOtherTypes:             false, // Keep strings, floats
}

// isConst is a helper function that checks if an `ssa.Value` is a constant
// equal to a given `constant.Value`.
func isConst(v ssa.Value, target constant.Value) bool {
	if c, ok := v.(*ssa.Const); ok {
		if c.Value == nil || target == nil {
			return c.Value == target
		}
		return constant.Compare(c.Value, token.EQL, target)
	}
	return false
}

// ShouldAbstract is the core logic of the policy. It decides whether a given
// constant (`ssa.Const`) should be abstracted into a placeholder based on its
// type, value, and the instruction in which it is used (`usageContext`).
func (p *LiteralPolicy) ShouldAbstract(c *ssa.Const, usageContext ssa.Instruction) bool {
	if c.Value == nil {
		return false // Keep nil
	}

	// Check if it's an integer we can analyze based on size.
	isInteger := c.Value.Kind() == constant.Int
	isSmall := false
	if isInteger {
		isSmall = p.isSmallInt(c.Value)
	}

	// --- Contextual Analysis (Primarily affects integers) ---
	// Refactored logic: Explicitly handle policy flags within context checks to prevent incorrect fallthrough behavior.
	if usageContext != nil {
		switch instr := usageContext.(type) {
		case *ssa.Return:
			if isInteger {
				// Keep it ONLY IF the policy allows keeping small status values AND it is small.
				if p.KeepReturnStatusValues && isSmall {
					return false
				}
				// Otherwise, abstract it (it's large, or the policy forbids keeping small status values).
				return true
			}
			// Non-integer returns fall through to default behavior.

		case *ssa.BinOp:
			// Is it a Comparison for Control Flow?
			if isComparisonOp(instr.Op) {
				isControlFlow := false
				if refs := instr.Referrers(); refs != nil {
					for _, ref := range *refs {
						if _, ok := ref.(*ssa.If); ok {
							isControlFlow = true
							break
						}
					}
				}

				if isControlFlow {
					if p.AbstractControlFlowComparisons {
						// Prioritize keeping small indices even in control flow comparisons (e.g., bounds checks).
						// Keep ONLY IF the policy allows keeping small indices AND it is small.
						if isInteger && p.KeepSmallIntegerIndices && isSmall {
							return false
						}
						return true
					}
					// If AbstractControlFlowComparisons is false, fallthrough to default behavior.
				}
			}

		case *ssa.IndexAddr, *ssa.Index:
			var index ssa.Value
			if ia, ok := instr.(*ssa.IndexAddr); ok {
				index = ia.Index
			} else if id, ok := instr.(*ssa.Index); ok {
				index = id.Index
			}

			if index != nil && isConst(index, c.Value) {
				if isInteger {
					// Keep it ONLY IF the policy allows keeping small indices AND it is small.
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					// Otherwise, abstract it (it's large, or the policy forbids keeping small indices).
					return true
				}
				// Non-integer indices fall through to default behavior.
			}

		case *ssa.Slice:
			isIndex := (instr.Low != nil && isConst(instr.Low, c.Value)) ||
				(instr.High != nil && isConst(instr.High, c.Value)) ||
				(instr.Max != nil && isConst(instr.Max, c.Value))

			if isIndex {
				if isInteger {
					// Keep it ONLY IF the policy allows keeping small indices AND it is small.
					if p.KeepSmallIntegerIndices && isSmall {
						return false
					}
					// Otherwise, abstract it.
					return true
				}
				// Non-integer indices fall through to default behavior.
			}

		case *ssa.Alloc:
			// Context used by Alloc handler for array lengths (which are integers).
			// Abstract if it's a large integer.
			if isInteger && !isSmall {
				return true
			}
			// Keep small array lengths by default (fallthrough).
		}
	}

	// --- Default Behavior based on Type ---

	// Default for Integers (e.g. arithmetic operands): Abstract if not small.
	if isInteger {
		return !isSmall
	}

	// Default for other types (Strings, Floats, etc.).
	return p.AbstractOtherTypes
}

// isSmallInt checks if a constant value is an integer within the policy's defined small range.
func (p *LiteralPolicy) isSmallInt(c constant.Value) bool {
	if c.Kind() != constant.Int {
		return false
	}
	if val, ok := constant.Int64Val(c); ok {
		return val >= p.SmallIntMin && val <= p.SmallIntMax
	}
	// Could be a big.Int, treat as not small for simplicity.
	return false
}

// isComparisonOp checks if a token represents a comparison operator.
func isComparisonOp(op token.Token) bool {
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	default:
		return false
	}
}
