<div align="center">

# Scalpel CLI: Autonomous Security Analysis Agent

Scalpel CLI is an advanced, LLM-driven autonomous agent designed for comprehensive security analysis of web applications. It operates on an Observe-Orient-Decide-Act (OODA) loop, intelligently exploring targets, identifying vulnerabilities, and even possessing the capability for self-improvement.

**An AI-Augmented Dynamic Application Security Testing (DAST) Scanner**
</div>

## Key Features

-   **Interactive Web UI**: A modern React-based frontend provides a rich, real-time interactive user interface for monitoring missions, visualizing the Knowledge Graph, and interacting with the agent via WebSockets.
-   **LLM-Driven Autonomy**: At its core, Scalpel CLI uses a Large Language Model (LLM) as its "Mind" to make intelligent decisions, plan actions, and reason about the security posture of a target.
-   **OODA Loop Architecture**: The agent continuously observes its environment, orientates itself with gathered context, decides on the next best action, and then acts upon it.
-   **Modular Executor System**: A highly modular `ExecutorRegistry` dispatches actions to specialized executors (Browser, Humanoid, Analysis, Codebase), promoting clear separation of concerns and extensibility.
-   **Knowledge Graph (KG)**: A persistent, contextual memory store that records observations, actions, findings, and relationships between various entities (e.g., URLs, UI elements, code files). This allows the agent to build a rich understanding of the target and its own progress.
-   **Comprehensive Vulnerability Scanning**: A suite of active and passive scanners to detect a wide range of vulnerabilities.

## Architecture Overview

Scalpel CLI's architecture is modular and highly decoupled, centered around the LLM-driven Mind:

1.  **The Mind (`LLMMind`)**: The central intelligence, powered by an LLM.
2.  **Knowledge Graph (`GraphStore`)**: A graph database that serves as the agent's memory.
3.  **Mission Control Platform (MCP)**: A standalone server that hosts the agent, serves the web UI, and provides a REST API and WebSocket endpoint for interaction.
4.  **Executors**: Specialized modules that perform actions (e.g., browsing, analysis).

## Getting Started

The recommended way to run Scalpel CLI is with Docker Compose. This will set up the MCP server, the PostgreSQL database, and the web UI.

### Prerequisites

*   Docker and Docker Compose

### Quick Start

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/xkilldash9x/scalpel-cli.git
    cd scalpel-cli
    ```

2.  **Configure your environment**:
    Copy the `.env.example` file to `.env` and add your LLM API keys.
    ```bash
    cp .env.example .env
    # Open .env and add your API keys
    ```

3.  **Start the application**:
    ```bash
    docker-compose up --build
    ```

4.  **Access the Web UI**:
    Open your browser and navigate to `http://localhost:5173`.

## How to Interact

Once the MCP server is running, you can interact with Scalpel in two ways:

1.  **Web UI**:
    The web UI provides an interactive interface for starting scans, viewing results, and interacting with the agent in real-time.

2.  **REST API**:
    The MCP server exposes a REST API for programmatic interaction. For example, you can start a new mission with a `POST` request:
    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"url": "https://example.com"}' http://localhost:8080/api/v1/missions
    ```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) to get started.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
