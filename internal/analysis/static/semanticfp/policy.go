package semanticfp

import (
	"go/constant"
	"go/token"
	"math"

	"golang.org/x/tools/go/ssa"
)

// LiteralPolicy defines the strategy for abstracting literals during canonicalization.
type LiteralPolicy struct {
	AbstractControlFlowComparisons bool
	KeepSmallIntegerIndices        bool
	KeepReturnStatusValues         bool
	SmallIntMin                    int64
	SmallIntMax                    int64
	// AbstractOtherTypes controls whether non-integer literals (strings, floats, etc.) are abstracted.
	AbstractOtherTypes bool
}

// DefaultLiteralPolicy provides a configuration based on the requirements.
var DefaultLiteralPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: true,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	SmallIntMin:                    -16,
	SmallIntMax:                    16,
	AbstractOtherTypes:             true, // Abstract strings, floats by default
}

// KeepAllLiteralsPolicy keeps most literals (useful for robust testing).
var KeepAllLiteralsPolicy = LiteralPolicy{
	AbstractControlFlowComparisons: false,
	KeepSmallIntegerIndices:        true,
	KeepReturnStatusValues:         true,
	SmallIntMin:                    math.MinInt64,
	SmallIntMax:                    math.MaxInt64,
	AbstractOtherTypes:             false, // Keep strings, floats
}

// isConst checks if an ssa.Value is a constant and if its value matches the target constant.Value.
func isConst(v ssa.Value, target constant.Value) bool {
	if c, ok := v.(*ssa.Const); ok {
		if c.Value == nil || target == nil {
			return c.Value == target
		}
		return constant.Compare(c.Value, token.EQL, target)
	}
	return false
}

// ShouldAbstract determines whether a constant should be abstracted based on its context.
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
