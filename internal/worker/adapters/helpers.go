// internal/worker/adapters/helpers.go
package adapters

import (
	"encoding/json"
	"fmt"
)

// remarshalParams is a utility function to convert the generic interface{} parameters
// into a specific struct type.
func remarshalParams(params interface{}, v interface{}) error {
	if params == nil {
		return nil
	}
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal parameters: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal parameters into target struct (%T): %w", v, err)
	}
	return nil
}
