-- migrations/001_initial_schema.sql

-- This migration sets up the initial tables for storing findings and knowledge graph data.

-- Findings table stores all the vulnerabilities and informational findings discovered.
CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL, -- CRITICAL FIX: Added to associate findings with a specific scan run.
    task_id VARCHAR(36) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    target TEXT NOT NULL,
    module VARCHAR(255) NOT NULL,
    vulnerability VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    description TEXT,
    evidence JSONB, -- Using JSONB for structured evidence
    recommendation TEXT,
    cwe VARCHAR(50)
);

-- Create indexes for faster lookups on commonly queried columns.
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_vulnerability ON findings (vulnerability);


-- Knowledge Graph (KG) tables for persistent storage.

-- kg_nodes stores entities like URLs, domains, technologies, etc.
CREATE TABLE IF NOT EXISTS kg_nodes (
    id TEXT PRIMARY KEY,
    type VARCHAR(255) NOT NULL,
    properties JSONB, -- FEATURE COMPLETE: Use JSONB for efficient querying.
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create a GIN index on the properties column for fast JSONB lookups.
CREATE INDEX IF NOT EXISTS idx_kg_nodes_properties ON kg_nodes USING GIN (properties);
CREATE INDEX IF NOT EXISTS idx_kg_nodes_type ON kg_nodes (type);


-- kg_edges stores the relationships between nodes.
CREATE TABLE IF NOT EXISTS kg_edges (
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relationship VARCHAR(255) NOT NULL,
    properties JSONB, -- FEATURE COMPLETE: Use JSONB for efficient querying.
    timestamp TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_id, target_id, relationship)
);

-- Create indexes on edge columns for traversing the graph.
CREATE INDEX IF NOT EXISTS idx_kg_edges_source_id ON kg_edges (source_id);
CREATE INDEX IF NOT EXISTS idx_kg_edges_target_id ON kg_edges (target_id);
