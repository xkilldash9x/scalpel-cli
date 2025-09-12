-- migrations/001_initial_schema.sql

-- This migration sets up the initial tables for storing findings and knowledge graph data.

--------------------------------------------------------------------------------
-- Setup and Extensions
--------------------------------------------------------------------------------

-- Enable UUID extension for efficient generation and storage of UUIDs.
-- We use "uuid-ossp" for uuid_generate_v4(). Alternatively, modern Postgres prefers pgcrypto for gen_random_uuid().
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Function to automatically update the 'updated_at' timestamp column.
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

--------------------------------------------------------------------------------
-- Findings Table
-- Stores all vulnerabilities and informational findings discovered during scans.
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    -- Production Ready: Using native UUID type for better performance and storage efficiency.
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL,
    task_id UUID NOT NULL,
    -- Ensure timestamp is always set.
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    target TEXT NOT NULL,
    module VARCHAR(255) NOT NULL,
    vulnerability VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL, -- Consider ENUM or CHECK constraint if standardized vocabulary is used.
    description TEXT,
    evidence JSONB, -- Using JSONB for structured evidence
    recommendation TEXT,
    cwe VARCHAR(50)
);

-- Create indexes for faster lookups on commonly queried columns.
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_vulnerability ON findings (vulnerability);
-- Production Ready: Added indexes for optimizing filtering by analyzer and target.
CREATE INDEX IF NOT EXISTS idx_findings_module ON findings (module);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings (target);


--------------------------------------------------------------------------------
-- Knowledge Graph (KG) Nodes Table
-- Stores entities (vertices) like URLs, domains, technologies, API endpoints.
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kg_nodes (
    -- ID is TEXT as it often represents natural keys (e.g., URLs, FQDNs).
    id TEXT PRIMARY KEY,
    type VARCHAR(255) NOT NULL,
    properties JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create a GIN index on the properties column for fast JSONB lookups.
CREATE INDEX IF NOT EXISTS idx_kg_nodes_properties ON kg_nodes USING GIN (properties);
CREATE INDEX IF NOT EXISTS idx_kg_nodes_type ON kg_nodes (type);

-- Production Ready: Idempotent trigger creation for kg_nodes updated_at.
-- Ensures the migration won't fail if the trigger already exists.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger
        WHERE tgname = 'set_timestamp_kg_nodes'
        AND tgrelid = 'kg_nodes'::regclass
    ) THEN
        CREATE TRIGGER set_timestamp_kg_nodes
        BEFORE UPDATE ON kg_nodes
        FOR EACH ROW
        EXECUTE PROCEDURE trigger_set_timestamp();
    END IF;
END
$$;


--------------------------------------------------------------------------------
-- Knowledge Graph (KG) Edges Table
-- Stores the relationships (connections) between nodes.
--------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kg_edges (
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relationship VARCHAR(255) NOT NULL,
    properties JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Composite primary key ensures uniqueness of a relationship type between two nodes.
    PRIMARY KEY (source_id, target_id, relationship),

    -- Production Ready: Foreign key constraints ensure data integrity.
    -- ON DELETE CASCADE ensures that if a node is deleted, associated edges are also removed.
    CONSTRAINT fk_edge_source
        FOREIGN KEY(source_id)
        REFERENCES kg_nodes(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_edge_target
        FOREIGN KEY(target_id)
        REFERENCES kg_nodes(id)
        ON DELETE CASCADE
);

-- Create indexes on edge columns for traversing the graph.
CREATE INDEX IF NOT EXISTS idx_kg_edges_source_id ON kg_edges (source_id);
CREATE INDEX IF NOT EXISTS idx_kg_edges_target_id ON kg_edges (target_id);
-- Production Ready: Added index on relationship type for efficient querying of specific relationships.
CREATE INDEX IF NOT EXISTS idx_kg_edges_relationship ON kg_edges (relationship);

