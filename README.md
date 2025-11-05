<div align="center">
<!--
  This README.md is generated based on an analysis of the `scalpel-cli` project's Go source code.
  It aims to provide a comprehensive overview of the project's architecture, features, and capabilities.
-->

<!-- TODO: Add a project logo -->
<!-- <img src="path/to/logo.png" alt="Scalpel Logo" width="200"/> -->
# Scalpel CLI: Autonomous Security Analysis Agent

Scalpel CLI is an advanced, LLM-driven autonomous agent designed for comprehensive security analysis of web applications. It operates on an Observe-Orient-Decide-Act (OODA) loop, intelligently exploring targets, identifying vulnerabilities, and even possessing the capability for self-improvement.

**An AI-Augmented Dynamic Application Security Testing (DAST) Scanner**
##  Key Features

</div>
-   **LLM-Driven Autonomy**: At its core, Scalpel CLI uses a Large Language Model (LLM) as its "Mind" to make intelligent decisions, plan actions, and reason about the security posture of a target.
-   **OODA Loop Architecture**: The agent continuously observes its environment, orients itself with gathered context, decides on the next best action, and then acts upon it.
-   **Knowledge Graph (KG)**: A persistent, contextual memory store that records observations, actions, findings, and relationships between various entities (e.g., URLs, UI elements, code files). This allows the agent to build a rich understanding of the target and its own progress.
-   **Cognitive Bus**: A central communication hub facilitating seamless interaction between the agent's Mind, Executors, and Analysis Modules.
-   **Comprehensive Vulnerability Scanning**:
    -   **Passive Analysis**:
        -   **Security Headers**: Analyzes HTTP response headers (e.g., HSTS, CSP, X-Frame-Options, Referrer-Policy) for misconfigurations and missing best practices.
        -   **Information Disclosure**: Detects headers revealing sensitive technology stack information (e.g., `Server`, `X-Powered-By`).
    -   **Active Analysis**:
        -   **Prototype Pollution**: Actively probes web pages for client-side JavaScript prototype pollution vulnerabilities.
        -   **TOCTOU (Time-of-Check to Time-of-Use) / Timeslip**: Detects race conditions in web applications by observing timing anomalies and differential responses under high concurrency.
        -   **Taint Analysis / XSS**: (Implied by `ANALYZE_TAINT` action) Identifies potential Cross-Site Scripting (XSS) vulnerabilities through data flow analysis.
-   **Autonomous Web Interaction**: The agent can interact with web applications like a human, performing actions such as:
    -   Navigation (`NAVIGATE`)
    -   Clicking elements (`CLICK`)
    -   Inputting text (`INPUT_TEXT`)
    -   Submitting forms (`SUBMIT_FORM`)
    -   Scrolling (`SCROLL`)
    -   Complex UI interactions (e.g., `HUMANOID_DRAG_AND_DROP`)
-   **Proactive Self-Improvement (`EVOLVE_CODEBASE`)**: A groundbreaking feature that allows the agent to identify limitations or bugs in its own codebase and propose/initiate modifications to improve its capabilities (configurable).
-   **Long-Term Memory (LTM)**: Provides heuristic flagging and learning capabilities to enhance the agent's understanding of observations.
-   **Structured Error Handling**: The agent is designed to interpret and react to various execution errors (e.g., `ELEMENT_NOT_FOUND`, `TIMEOUT_ERROR`), adjusting its strategy accordingly.

<div align="center">
##  Architecture Overview

[![Go Version](https://img.shields.io/github/go-mod/go-version/xkilldash9x/scalpel-cli)](https://go.dev/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/xkilldash9x/scalpel-cli/go.yml?branch=main)](https://github.com/xkilldash9x/scalpel-cli/actions)
[![License](https://img.shields.io/github/license/xkilldash9x/scalpel-cli)](./LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](./CONTRIBUTING.md)
Scalpel CLI's architecture is modular and highly decoupled, centered around the LLM-driven Mind:

</div>
1.  **The Mind (`LLMMind`)**: The central intelligence, powered by an LLM. It receives observations, queries the Knowledge Graph for context, decides the next action, and posts it to the Cognitive Bus.
2.  **Knowledge Graph (`GraphStore`)**: A graph database that serves as the agent's memory. It stores nodes (missions, actions, observations, findings, files) and edges (relationships between them), providing a rich, queryable context for the Mind.
3.  **Cognitive Bus**: An in-memory message bus that facilitates communication between different components. Actions are published, and observations/results are subscribed to.
4.  **Executors (Implicit)**: Components that subscribe to `ACTION` messages from the Cognitive Bus and translate them into concrete operations. This includes:
    -   **Browser Executor**: Controls a headless browser (e.g., via Humanoid) to perform web interactions.
    -   **Analysis Adapters**: Bridge the generic worker framework to specific analysis modules.
5.  **Analysis Modules**: Specialized components that perform security checks. These can be passive (e.g., `HeadersAnalyzer`) or active (e.g., `ProtoPollution Analyzer`, `Timeslip Analyzer`). They report findings and observations back to the Cognitive Bus.
6.  **Long-Term Memory (`LTM`)**: A component that processes observations, applies heuristics, and flags them for the Mind, contributing to the agent's learning and adaptation.

---
## How It Works (Simplified Flow)

**Scalpel** is not just another web scanner. It's a next-generation security tool that fuses traditional, battle-tested DAST techniques with a powerful **AI Agent System**. By leveraging Large Language Models (LLMs) and a persistent Knowledge Graph, Scalpel goes beyond simple vulnerability detection to build a deep, contextual understanding of your application.
1.  **Mission Assignment**: The agent is given a `Mission` (e.g., "Find vulnerabilities in example.com").
2.  **Observation**: The agent's executors interact with the target, and various sensors (browser, network, analysis modules) generate `Observations` (e.g., "Page loaded", "HTTP headers observed", "Prototype pollution detected").
3.  **Knowledge Graph Update**: Observations are recorded in the Knowledge Graph, enriching the agent's understanding of the target and its own actions.
4.  **Orientation**: The Mind queries the Knowledge Graph to gather relevant context (e.g., recent actions, findings, current page state).
5.  **Decision**: The LLM-powered Mind, using the gathered context and its system prompts, decides the `Action` to take next (e.g., "Click login button", "Analyze headers", "Run prototype pollution scan").
6.  **Action**: The chosen action is published to the Cognitive Bus, and an appropriate Executor performs the action. 
7.  **Loop**: The cycle repeats, allowing the agent to autonomously explore, analyze, and adapt until the mission objective is achieved or deemed impossible.

This allows for more accurate findings, intelligent analysis, and paves the way for features like automated patch generation (`autofix`).
##  Configuration
*   **AI Powered Agent System**: Utilizes LLMs (like Google's Gemini) and a Knowledge Graph for deep contextual analysis. See AGENTS.md for details.
*   **Comprehensive Discovery**: High-speed, concurrent crawling and passive subdomain enumeration (`crt.sh`, etc.) to build a complete map of the target.
*   **Modern Web App Support**: Full headless browser interaction for scanning Single Page Applications (SPAs) built with frameworks like React, Vue, and Angular.
*   **Advanced Active Scanners**:
    *   **`timeslip`**: Detects time of check to time of use (TOCTOU) race conditions.
    *   **`protopollution`**: Identifies client-side and server-side prototype pollution vulnerabilities.
    *   **`auth`**: Tests for account takeover (ATO) vulnerabilities and insecure direct object references (IDOR).
*   **Passive Analysis**: Scans for exposed JWT secrets, insecure headers, and other low-hanging fruit without sending intrusive traffic.
*   **Automated Patching (Experimental)**: The `autofix` module uses the Agent System to propose and generate code patches for certain vulnerability classes.
*   **Flexible Reporting**: Generates reports in multiple formats, including industry-standard **SARIF** for easy integration with CI/CD pipelines and security dashboards.

## Demo

## Installation

### Prerequisites

*   **Go 1.25+**: Required to build the project from source.
*   **Docker**: The easiest way to run the required PostgreSQL database.

### From Source

Use this method to ensure you are working with the latest version.
```bash
# Clone the repository
git clone https://github.com/xkilldash9x/scalpel-cli.git
cd scalpel-cli

# Build the binary
go build -o scalpel-cli ./cmd/scalpel
```

### Using `go install`
## Contributing

```bash
go install github.com/xkilldash9x/scalpel-cli/cmd/scalpel@latest
```
*(Placeholder: Information on how to contribute to the project, including development setup, testing, and code style guidelines.)*

## Quick Start

Scalpel requires a PostgreSQL database to store findings and power the Knowledge Graph. The easiest way to get started is with Docker.

**1. Start the Database**

```bash
# This will start a PostgreSQL container named 'scalpel-db'
docker run --name scalpel-db -e POSTGRES_PASSWORD=mysecretpassword -e POSTGRES_USER=scalpel -p 5432:5432 -d postgres
```

**2. Configure the Database URL**

Set the environment variable that Scalpel uses to find the database. For convenience, you can add this to an `.envrc` file and use `direnv`.

```bash
export SCALPEL_DATABASE_URL="postgres://scalpel:mysecretpassword@localhost:5432/postgres?sslmode=disable"
```

**3. Run a Scan**

Execute a scan against your target. The `--output` flag will automatically generate a report when the scan is complete.

```bash
./scalpel-cli scan https://your-target-app.com --output report.sarif
```

**4. Generate a Report Later**

If you didn't use the `--output` flag, you can generate a report at any time using the Scan ID.

```bash
./scalpel-cli report --scan-id <your-scan-id> --output report.sarif
```

##  Configuration

Scalpel is highly configurable. Settings are applied with the following priority:

1.  **Command-line Flags**: (e.g., `--depth 10`)
2.  **Environment Variables**: (e.g., `SCALPEL_DATABASE_URL`)
3.  **Configuration File**: (`config.yaml`)
4.  **Default Values**

A default `config.yaml` is provided in the repository. You can copy it to `config.local.yaml` to make local overrides that are ignored by git.

##  Contributing

Contributions are welcome! We are actively looking for developers to help build the future of application security testing. Please read our Contributing Guide to get started.

##  License

This project is licensed under the **MIT License**. See the LICENSE file for details.
*(Placeholder: License information, e.g., MIT, Apache 2.0.)*
