<div align="center">

<svg width="300" height="100" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 100">
  <style>
    /* Base styles for the logo */
    .title { font: bold 60px monospace; }
    .blade { stroke-width: 1; }

    /* Default (Dark Theme) */
    :root {
      --bg-color: #1e1e1e;
      --title-color: #e0e0e0;
      --blade-fill: #a0a0a0;
      --blade-stroke: #ffffff;
    }

    /* Light Theme Adaptation */
    @media (prefers-color-scheme: light) {
      :root {
        --bg-color: #ffffff;
        --title-color: #1e1e1e;
        --blade-fill: #cccccc;
        --blade-stroke: #333333;
      }
    }
    
    .title { fill: var(--title-color); }
    .blade { fill: var(--blade-fill); stroke: var(--blade-stroke); }
  </style>
  
  <defs>
    <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#ff4136;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0074d9;stop-opacity:1" />
    </linearGradient>
  </defs>
  
  <path d="M10 50 Q 30 40, 50 50 Q 70 60, 50 70 L 30 60 Z" class="blade"/>
  <line x1="50" y1="50" x2="80" y2="30" stroke="url(#grad1)" stroke-width="4"/>

  <text x="90" y="65" class="title">SCALPEL</text>
</svg>
![Project Status](https://img.shields.io/badge/status-in_development-black)
![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue?logo=go&logoColor=green)
![License](https://img.shields.io/badge/license-MIT-purple)

Scalpel is an AI-native, autonomous security scanner designed for modern web applications. It combines a modular analysis engine with an LLM-powered agent to discover and analyze complex vulnerabilities through realistic, human-like browser interaction.

## Disclaimer 

This tool is intended for educational purposes and for use in authorized security assessments only. **Do not** use this tool on any system or network without explicit permission from the owner, as it is unethical and illegal. The creator of this software is **not** responsible for any misuse or damage caused by this framework. **Use at your own risk.**

--

## Table of Contents

- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [License](#license)
--

## Key Features 

* **AI-Powered Agent:** Utilizes a Large Language Model for autonomous, objective-driven security missions.
* **Knowledge Graph Core:** Builds a real-time graph of all discovered assets, relationships, and findings for contextual analysis.
* **Advanced Dynamic Analysis (IAST):** Employs a sophisticated JavaScript shim for client-side taint analysis to detect flows from sources (URL parameters, storage) to dangerous sinks (e.g., `innerHTML`, `eval`).
* **Humanoid Browser Interaction:** Leverages an advanced "humanoid" engine for stealthy browser automation, simulating realistic mouse trajectories, typing patterns, and scrolling behavior to evade bot detection.
* **Active Scanners:** Includes dedicated modules for detecting:
    * Race Conditions (`TimeSlip`)
    * Account Takeover (ATO) vulnerabilities
    * Insecure Direct Object References (IDOR)
* **Passive & Static Analysis:** Passively checks for security header misconfigurations and performs static analysis on artifacts like JSON Web Tokens (JWTs).
* **Persistent & Extensible:** Uses a PostgreSQL backend for storing all findings and knowledge graph data, with a modular worker/adapter architecture that makes it easy to add new analysis capabilities.
* **Professional Reporting:** Generates reports in standard formats like SARIF.

--
## Architecture Overview 

Scalpel is built on a modular, event-driven architecture that separates concerns for scalability and maintainability.

```mermaid
graph TD
    subgraph "CLI (cmd)"
        A[scan command]
    end

    subgraph "Core Services (pkg)"
        B[Orchestrator]
        C[Task Engine]
        D[Knowledge Graph]
        E[Browser Manager]
    end
    
    subgraph "Analysis Modules (pkg/analysis)"
        F[Adapters]
        G[Active Scanners]
        H[Passive Scanners]
        I[Static Scanners]
        J[AI Agent]
    end

    A --> B
    B --> C
    B --> E
    B --> D
    C --> F
    F --> G & H & I & J
    J --> E
    G --> E
    D <--> F
```

1. **Orchestrator:** The top-level component that initializes all services and manages the scan lifecycle.
2.  **Task Engine:** A worker pool that processes analysis tasks concurrently.
3.  **Knowledge Graph:** A central PostgreSQL-backed graph that stores all discovered assets and their relationships.
4.  **Browser Manager:** Manages a pool of headless browser instances, applying stealth and instrumentation.
5.  **Analyzers (Adapters):** Modular components that perform specific security checks (Taint, IDOR, ATO, etc.).
6.  **AI Agent:** An autonomous component with its own cognitive loop (OODA) that receives high-level missions and uses an LLM to decide on actions.
--

## Technology Stack 

* **Go 1.22+**: For the core application logic and CLI.
* **PostgreSQL**: Serves as the persistent backend for the knowledge graph and scan findings.
* **Rod**: Used for browser automation and management.
* **Mermaid**: For rendering diagrams in documentation.
* **Gemini / OpenAI**: Pluggable LLM providers for the AI Agent.

--

## Getting Started 

Follow these steps to get the `scalpel-cli` scanner up and running.

### Prerequisites

* **Go:** Version 1.22 or later.
* **PostgreSQL:** A running instance for storing findings and the knowledge graph.
* **Google Chrome / Chromium:** Required for headless browser operations.
### 1. Installation

Clone the repository and build the binary:


# Clone the repository
```bash
git clone [https://github.com/xkilldash9x/scalpel-cli.git](https://github.com/xkilldash9x/scalpel-cli.git)
cd scalpel-cli
# Tidy dependencies and build the executable
go mod tidy
go build -o scalpel-cli ./cmd/main.go
```
--
### 2. Configuration

`scalpel-cli` is configured using a `config.yaml` file and environment variables.

1.  Copy the existing `config.yaml` to `config.local.yaml`. This file is in the `.gitignore` and is safe for local secrets.

2.  Update `config.local.yaml` with your settings, especially the PostgreSQL connection string:

    ```yaml
    # in config.local.yaml
    
    postgres:
      # Replace with your actual database URL
      url: "postgres://user:password@localhost:5432/scalpeldb?sslmode=disable"
    
    # If using the AI Agent, provide your LLM API Key
    agent:
      enabled: true
      llm:
        provider: "gemini"
        model: "gemini-1.5-flash" # Or another preferred model
        api_key: "YOUR_GEMINI_API_KEY" # Set this here or via environment variable
    ```

3.  **Environment Variables:** You can override any configuration setting with an environment variable prefixed with `SCALPEL_`. For example, to set the database URL:

    ```bash
    export SCALPEL_POSTGRES_URL="postgres://user:password@host:5432/scalpeldb"
    ```
--

## Usage 

The primary command is `scan`, which runs the full discovery and analysis pipeline against one or more targets.

### Command Syntax

```sh
./scalpel-cli scan [target...] [flags]
```
**Flags**
```
* `-c, --config`: Path to a custom config file (e.g., `config.local.yaml`).
* `-o, --output`: File to write the final report to (default: `stdout`).
* `-f, --format`: Output format (`sarif`, `json`, `text`).
* `-d, --depth`: Maximum depth for the crawler.
* `--scope`: Scope of the scan (`root`, `subdomain`, `strict`).
``` 
### Example

Run a scan against a target, limit the crawl depth to 2, and save the results to a SARIF file.

```sh
./scalpel-cli scan [https://example.com](https://example.com) -c config.local.yaml -d 2 -o report.sarif -f sarif
```
--

## License 

This project is licensed under the MIT License - see the `LICENSE.md` file for details.
