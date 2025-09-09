// File: internal/interfaces/interfaces.go
// Description: This file now serves as a compatibility layer, providing type aliases
// to the canonical interface definitions in the top-level `api/schemas` package.
// This approach was taken to resolve a circular dependency issue and establish a clean
// architectural boundary. All new code should depend directly on the interfaces in `api/schemas`.

package interfaces

import (
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// NOTE: This file is now primarily a wrapper around the schemas for clarity.
// The actual interface definitions have been moved to `api/schemas/schemas.go`
// to prevent import cycles and establish a clear contract at the API level.

type TaskEngine = schemas.TaskEngine
type Store = schemas.Store
type Executor = schemas.Executor
type KnowledgeGraph = schemas.KnowledgeGraph
type DiscoveryEngine = schemas.DiscoveryEngine
type LLMClient = schemas.LLMClient
type Mind = schemas.Mind
type BrowserManager = schemas.BrowserManager
type Page = schemas.Page
type Analyzer = schemas.Analyzer
type Reporter = schemas.Reporter

