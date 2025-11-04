# Scalpel Agent System

The Scalpel Agent System is an advanced, intelligent component designed to augment the core scanning capabilities of `scalpel-cli`. It leverages a Large Language Model (LLM) and a persistent Knowledge Graph to provide deeper insights, contextual analysis, and a foundation for future automated remediation tasks.

## Table of Contents

- Core Concepts
- Components
  - LLM Integration
  - Knowledge Graph
- Configuration
  - Enabling the Agent
  - Configuring LLM Models
- How to Interact

## Core Concepts

The agent system is built on two primary ideas:

1.  **Intelligence**: By integrating with powerful LLMs (like Google's Gemini series), the agent can understand the context of vulnerabilities, analyze code, and reason about the structure of a target application in ways that traditional scanners cannot.
2.  **Persistence**: The Knowledge Graph stores structured data about the target application across multiple scans. This allows the agent to "learn" over time, correlating findings and building a comprehensive model of the application's components and their relationships.

This combination enables features beyond simple vulnerability detection, such as providing detailed, context-aware remediation advice and powering the `autofix` module.

## Components

### LLM Integration

The agent uses LLMs to perform complex analytical tasks. The system is configured to use different models for tasks of varying complexity, optimizing for both speed and power.

- **Fast Model**: Used for high-volume, low-complexity tasks (e.g., classifying endpoints, summarizing simple findings).
- **Powerful Model**: Reserved for complex, low-volume tasks (e.g., analyzing vulnerability chains, generating code for patches).

The default models are specified in `config.yaml`:

```yaml
agent:
  llm:
    default_fast_model: "gemini-2.5-flash"
    default_powerful_model: "gemini-2.5-pro"
    models: {}
```

### Knowledge Graph

The Knowledge Graph (KG) is the agent's memory. It is a persistent database (currently PostgreSQL) that stores information about the target application, including:

- Endpoints and their parameters.
- Discovered assets (JavaScript files, etc.).
- Relationships between different parts of the application.
- Findings from past and present scans.

By storing this data, the KG allows the agent to build a rich, interconnected understanding of the target, which improves the quality of its analysis with each subsequent scan.

## Configuration

### Enabling the Agent

The agent's features are primarily leveraged by other modules (like `autofix` or specialized analyzers). To use them, you must configure the necessary credentials for the LLM providers.

### Configuring LLM Models

API keys for LLM providers are configured via environment variables. The variable name is constructed based on the model name defined in `config.yaml`.

The format is `SCALPEL_AGENT_LLM_MODELS_<MODEL_NAME>_API_KEY`, where `<MODEL_NAME>` is the model identifier, converted to uppercase, with dots and dashes replaced by underscores.

**Example:**

To configure the API key for the default `gemini-2.5-pro` model, you would set the following environment variable:

```bash
export SCALPEL_AGENT_LLM_MODELS_GEMINI_2_5_PRO_API_KEY="your-google-ai-api-key"
```

## How to Interact

Direct interaction with the agent is currently implicit. When you run a scan with modules that use the agent (like `autofix`), `scalpel-cli` will automatically invoke the agent's capabilities. Ensure your LLM API keys are correctly configured in your environment for these features to work. Future versions may include direct `agent` subcommands for querying the Knowledge Graph or interacting with the LLM.