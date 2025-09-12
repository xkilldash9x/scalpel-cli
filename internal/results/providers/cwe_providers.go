// internal/results/providers/cwe_provider.go
package providers

import (
	"fmt"
)

// CWEEntry holds details about a specific CWE.
type CWEEntry struct {
	ID          string
	Name        string
	Description string
	// Add more fields as needed (e.g., LikelihoodOfExploit, RelatedAttackPatterns)
}

// CWEProvider defines the interface for retrieving CWE information.
type CWEProvider interface {
	GetCWE(id string) (*CWEEntry, error)
}

// InMemoryCWEProvider provides a basic in-memory implementation of CWEProvider.
type InMemoryCWEProvider struct {
	data map[string]CWEEntry
}

// NewInMemoryCWEProvider creates a new InMemoryCWEProvider with preloaded data.
func NewInMemoryCWEProvider() *InMemoryCWEProvider {
	// In a real implementation, this data would be loaded from an external source (e.g., XML/JSON file from MITRE).
	// For now, we hardcode a few common ones based on the analyzers.
	data := map[string]CWEEntry{
		"CWE-79":   {ID: "CWE-79", Name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", Description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users."},
		"CWE-89":   {ID: "CWE-89", Name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", Description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component."},
		"CWE-200":  {ID: "CWE-200", Name: "Exposure of Sensitive Information to an Unauthorized Actor", Description: "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information."},
		"CWE-319":  {ID: "CWE-319", Name: "Cleartext Transmission of Sensitive Information", Description: "The information is sent in cleartext and can be observed by unauthorized parties."},
		"CWE-521":  {ID: "CWE-521", Name: "Weak Password Requirements", Description: "The product does not require that users select passwords that are sufficiently strong."},
		"CWE-639":  {ID: "CWE-639", Name: "Authorization Bypass Through User-Controlled Key", Description: "The web application uses a key to access a resource, but the key is exposed to the user, allowing the user to access unauthorized resources."},
		"CWE-693":  {ID: "CWE-693", Name: "Protection Mechanism Failure", Description: "The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks."},
		"CWE-1021": {ID: "CWE-1021", Name: "Improper Restriction of Rendered UI Layers or Frames", Description: "The product renders a UI in a frame or layer that can be made transparent or opaque, allowing an attacker to overlay a deceptive UI."},
		"CWE-116":  {ID: "CWE-116", Name: "Improper Encoding or Escaping of Output", Description: "The software prepares a structured message for communication with another component, but it does not use or incorrectly uses an encoding or escaping scheme that is compliant with the syntax of the intended destination."},
	}
	return &InMemoryCWEProvider{data: data}
}

// GetCWE retrieves CWE details by ID.
func (p *InMemoryCWEProvider) GetCWE(id string) (*CWEEntry, error) {
	entry, exists := p.data[id]
	if !exists {
		// Return a generic entry instead of an error if not found, to avoid failing the enrichment process.
		return &CWEEntry{ID: id, Name: fmt.Sprintf("%s (Details Not Found)", id), Description: "Details for this CWE ID are not available in the local database."}, nil
	}
	return &entry, nil
}