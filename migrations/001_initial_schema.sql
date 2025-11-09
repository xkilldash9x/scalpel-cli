-- migrations/001_initial_schema.sql
-- This migration sets up the initial tables for storing findings and knowledge graph data.

-- Production Ready: Wrap the entire migration in a transaction to ensure atomicity.
BEGIN;

--------------------------------------------------------------------------------
-- Setup, Extensions, and Types
--------------------------------------------------------------------------------

-- Production Ready: Enable pgcrypto and pg_trgm.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Define an ENUM type for finding severity.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'finding_severity') THEN
        -- Standardized, lowercase severity levels matching Go constants.
        CREATE TYPE finding_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
    END IF;
END
$$;

-- Define an ENUM type for KG Node Status.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'kg_node_status') THEN
        -- Matching Go constants in schemas/knowledge_graph.go
        CREATE TYPE kg_node_status AS ENUM ('new', 'processing', 'analyzed', 'error', 'success', 'failure');
    END IF;
END
$$;


-- Function to automatically update the 'updated_at' timestamp column.
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  -- CURRENT_TIMESTAMP provides the time at the start of the transaction.
	 NEW.updated_at = CURRENT_TIMESTAMP;
	 RETURN NEW;
END;
$$ LANGUAGE plpgsql;

--------------------------------------------------------------------------------
-- Findings Table
-- Synchronized with schemas/findings.go
--------------------------------------------------------------------------------

-- We drop the table definitions to ensure the schema is cleanly synchronized for the initial migration.
-- In a live environment, subsequent changes should use ALTER TABLE.
DROP TABLE IF EXISTS findings CASCADE;

CREATE TABLE findings (
    -- Using native UUID. We assume the application provides the ID if it's known, otherwise default.
	 	 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	 	 scan_id UUID NOT NULL,
	 	 task_id UUID NOT NULL,

    -- Core Data
	 	 target TEXT NOT NULL CHECK (target <> ''),
	 	 module VARCHAR(255) NOT NULL CHECK (module <> ''),

    -- Flattened vulnerability structure matching the updated Go Finding struct.
	 	 vulnerability_name VARCHAR(255) NOT NULL CHECK (vulnerability_name <> ''),

    -- Using the defined ENUM type.
	 	 severity finding_severity NOT NULL,
	 	 description TEXT,
    -- JSONB for structured evidence.
	 	 evidence JSONB,
	 	 recommendation TEXT,
    -- Changed to TEXT[] to support multiple CWEs.
	 	 cwe TEXT[],

    -- Timestamps
    -- observed_at: when the scan found it (application provided).
	 	 observed_at TIMESTAMPTZ NOT NULL,
    -- created_at/updated_at: database record tracking (DB managed).
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexing Strategy for Findings
CREATE INDEX idx_findings_scan_id ON findings (scan_id);
CREATE INDEX idx_findings_task_id ON findings (task_id);
CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_vulnerability_name ON findings (vulnerability_name);
CREATE INDEX idx_findings_module ON findings (module);
CREATE INDEX idx_findings_observed_at ON findings (observed_at DESC);
CREATE INDEX idx_findings_scan_severity ON findings (scan_id, severity);

-- Trigram index for the 'target' TEXT column (speeds up LIKE queries).
CREATE INDEX idx_findings_target_trgm ON findings USING GIN (target gin_trgm_ops);

-- GIN index for the CWE array column (efficiently query specific CWEs).
CREATE INDEX idx_findings_cwe ON findings USING GIN (cwe);


-- Apply the updated_at trigger to the findings table.
CREATE TRIGGER set_timestamp_findings
BEFORE UPDATE ON findings
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();


--------------------------------------------------------------------------------
-- Knowledge Graph (KG) Nodes Table
-- Aligned with schemas/knowledge_graph.go Node struct and postgres_kg.go implementation.
--------------------------------------------------------------------------------

DROP TABLE IF EXISTS kg_nodes CASCADE;

CREATE TABLE kg_nodes (
	 	 -- ID is TEXT as it often represents natural keys (e.g., URLs, FQDNs).
	 	 id TEXT PRIMARY KEY CHECK (id <> ''),
	 	 type VARCHAR(255) NOT NULL CHECK (type <> ''),
     label TEXT NOT NULL CHECK (label <> ''),
     -- Using the ENUM type for status.
     status kg_node_status NOT NULL,
     -- Ensuring Properties is never NULL.
	 	 properties JSONB NOT NULL DEFAULT '{}',

    -- Timestamps
    -- created_at: When the node was first created (application provided).
	 	 created_at TIMESTAMPTZ NOT NULL,
    -- last_seen: When the entity represented by the node was last observed (application managed via UPSERT).
     last_seen TIMESTAMPTZ NOT NULL,
    -- updated_at: When the database record was last modified (DB managed).
	 	 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexing Strategy for KG Nodes
CREATE INDEX idx_kg_nodes_type ON kg_nodes (type);
CREATE INDEX idx_kg_nodes_status ON kg_nodes (status);
CREATE INDEX idx_kg_nodes_last_seen ON kg_nodes (last_seen DESC);
-- GIN index on the properties column for fast JSONB lookups.
CREATE INDEX idx_kg_nodes_properties ON kg_nodes USING GIN (properties);

-- Production Ready: Index for QueryImprovementHistory optimization.
-- This specific partial index drastically speeds up lookups for past attempts based on the objective and sorted by time.
-- Note: The WHERE clause uses the constant 'IMPROVEMENT_ATTEMPT' matching the Go NodeType.
CREATE INDEX idx_kg_nodes_improvement_history ON kg_nodes (
    (properties->>'goal_objective'),
    created_at DESC
) WHERE type = 'IMPROVEMENT_ATTEMPT';


-- Apply the updated_at trigger to the kg_nodes table.
CREATE TRIGGER set_timestamp_kg_nodes
BEFORE UPDATE ON kg_nodes
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();


--------------------------------------------------------------------------------
-- Knowledge Graph (KG) Edges Table
-- Aligned with schemas/knowledge_graph.go Edge struct and postgres_kg.go implementation.
--------------------------------------------------------------------------------

DROP TABLE IF EXISTS kg_edges CASCADE;

CREATE TABLE kg_edges (
    -- Application-provided ID for the edge instance.
    id TEXT NOT NULL CHECK (id <> ''),

    -- Standardized column names matching postgres_kg.go
	 	 from_node TEXT NOT NULL,
	 	 to_node TEXT NOT NULL,
	 	 type VARCHAR(255) NOT NULL CHECK (type <> ''),
     label TEXT NOT NULL CHECK (label <> ''),
	 	 properties JSONB NOT NULL DEFAULT '{}',

    -- Timestamps
	 	 created_at TIMESTAMPTZ NOT NULL,
     last_seen TIMESTAMPTZ NOT NULL,
     updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

     -- The Primary Key is the relationship tuple, ensuring normalization and uniqueness.
     -- This is required for the ON CONFLICT clause in postgres_kg.go.
     PRIMARY KEY (from_node, to_node, type),

     -- Ensure the application ID is also unique across all edges.
     CONSTRAINT uq_edge_id UNIQUE (id),

	 	 -- Foreign key constraints ensure data integrity.
	 	 CONSTRAINT fk_edge_from
	 	 	 	 FOREIGN KEY(from_node)
	 	 	 	 REFERENCES kg_nodes(id)
	 	 	 	 ON DELETE CASCADE,
	 	 CONSTRAINT fk_edge_to
	 	 	 	 FOREIGN KEY(to_node)
	 	 	 	 REFERENCES kg_nodes(id)
	 	 	 	 ON DELETE CASCADE
);

-- Indexing Strategy for KG Edges

-- Index for incoming edges (reverse lookups).
CREATE INDEX idx_kg_edges_to_node ON kg_edges (to_node);
-- Index on relationship type.
CREATE INDEX idx_kg_edges_type ON kg_edges (type);
-- Note: The PK (from_node, to_node, type) already covers outgoing edge lookups starting with from_node (used by GetEdges, GetNeighbors).


-- Apply the updated_at trigger to the kg_edges table.
CREATE TRIGGER set_timestamp_kg_edges
BEFORE UPDATE ON kg_edges
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

COMMIT;