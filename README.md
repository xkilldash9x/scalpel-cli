# Scalpel CLI

[![Go Test](https://github.com/xkilldash9x/scalpel-cli/actions/workflows/go-test.yaml/badge.svg)](https://github.com/xkilldash9x/scalpel-cli/actions/workflows/go-test.yaml)

Scalpel CLI is an AI-powered security auditing tool designed to analyze codebases, identify vulnerabilities, and provide automated fixes. It leverages Large Language Models (LLMs) to bring a new level of intelligence to application security testing, moving beyond simple pattern matching to understand the context and logic of your code.

## Overview

Scalpel is not just another static analysis tool. It acts as an AI agent that deeply understands your code. It combines static analysis, dynamic analysis orchestration, and a knowledge graph to build a comprehensive model of your application. This allows it to uncover complex vulnerabilities and, in many cases, automatically generate the code patches to fix them.

## Architecture

The Scalpel CLI is a Go application built with a modular architecture to support extensibility and maintainability. The key components are:

*   **`cmd`**: Contains the main entry point for the CLI, using the [Cobra](https://github.com/spf13/cobra) library to manage commands and flags (`scan`, `report`, etc.).
*   **`internal/config`**: Manages application configuration, loading settings from `config.yaml` and environment variables using [Viper](https://github.com/spf13/viper).
*   **`internal/agent`**: The core AI agent logic resides here. It orchestrates the analysis process, interacts with the knowledge graph, and uses an LLM-powered "evolution" loop to reason about security vulnerabilities.
*   **`internal/analysis`**: Contains the individual security scanners, categorized into:
    *   `passive`: Analyzers that inspect network traffic without sending new requests (e.g., header analysis).
    *   `static`: Analyzers that inspect code and configuration files (e.g., JWT secret scanning).
    *   `active`: Analyzers that actively probe the application for vulnerabilities (e.g., taint analysis, prototype pollution).
*   **`internal/browser`**: A sophisticated browser automation layer built on top of [chromedp](https://github.com/chromedp/chromedp). It includes a `humanoid` sub-package to simulate realistic user interactions, evading bot detection.
*   **`internal/network`**: A custom, low-level HTTP client stack that provides fine-grained control over HTTP/1.1 and HTTP/2 connections, request pipelining, and transparent decompression.
*   **`api/schemas`**: Defines the data structures used throughout the application, including HAR files, findings, and analysis tasks.

## Key Features

*   **AI-Driven Analysis:** Utilizes LLMs (like Google's Gemini) to identify a wide range of security vulnerabilities with high accuracy.
*   **Automated Code Repair (Self-Heal):** Automatically generates patches for identified vulnerabilities, helping you fix issues faster.
*   **Knowledge Graph:** Builds a graph representation of your codebase to uncover deep, inter-procedural vulnerabilities.
*   **Dynamic Analysis:** Interacts with running applications through browser automation to find vulnerabilities that only manifest at runtime.
*   **SARIF Reporting:** Generates industry-standard SARIF reports for easy integration with other security tools and platforms.
*   **Extensible Analyzer Framework:** Supports a variety of analysis techniques, including static, passive, and active analysis.

## Getting Started

Follow these instructions to get Scalpel CLI set up and ready to run your first scan.

### Prerequisites

*   [Go](https://go.dev/doc/install) (version 1.21 or later)
*   [Docker](https://docs.docker.com/get-docker/)
*   An API key for your chosen LLM provider (e.g., Google AI Studio, OpenAI).

### 1. Set Up the PostgreSQL Database

Scalpel uses a PostgreSQL database to store its knowledge graph and analysis results. The easiest way to get this running is with Docker.

**a. Launch PostgreSQL using Docker:**

Run the following command to start a PostgreSQL container. This will create a database named `scalpel_db` with a user `scalpel` and password `secret`.

```bash
docker run --name scalpel-db -e POSTGRES_USER=scalpel -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=scalpel_db -p 5432:5432 -d postgres:15
```

**b. Apply the Database Schema:**

Next, apply the initial database schema using the provided migration file.

```bash
docker exec -i scalpel-db psql -U scalpel -d scalpel_db < ./migrations/001_initial_schema.sql
```

This command executes the `001_initial_schema.sql` script inside your running container to set up the necessary tables.

### 2. Configure the Application

**a. Install Dependencies:**

```bash
go mod tidy
```

**b. Create and Configure `config.yaml`:**

Create a `config.yaml` file in the root of the project. You can use `config.yaml.example` as a starting point. At a minimum, you need to configure the database connection and your LLM provider.

```yaml
# Example config.yaml
database:
  url: "postgres://scalpel:secret@localhost:5432/scalpel_db?sslmode=disable"

agent:
  llm:
    default_fast_model: "gemini-1.5-flash"
    default_powerful_model: "gemini-1.5-pro"
    models:
      # Configure your chosen LLM provider
      gemini-1.5-flash:
        provider: "gemini"
        model: "gemini-1.5-flash-latest"
        # API key should be set via environment variable: SCALPEL_GEMINI_API_KEY
      gemini-1.5-pro:
        provider: "gemini"
        model: "gemini-1.5-pro-latest"
```
**Important:** It is strongly recommended to manage API keys and other secrets using environment variables. For example, set your Gemini API key with:
`export SCALPEL_GEMINI_API_KEY="YOUR_API_KEY"`

### 3. Build the CLI

Compile the `scalpel` binary:

```bash
go build -o scalpel ./cmd/scalpel
```

## Usage

Once built, you can run scans using the `scalpel` executable.

### Basic Scan

To run a scan on a target codebase or URL:

```bash
./scalpel scan --target /path/to/your/project
```

To see all available commands and flags:

```bash
./scalpel --help
```

### Commands

*   `scalpel scan`: The primary command to initiate a security scan on a target.
    *   `--target`: (Required) The file path or URL of the target to scan.
    *   `--output`: The file path to write the output report. Defaults to `results.sarif`.
    *   `--format`: The output format. Currently supports `sarif`.
    *   `--concurrency`: The number of concurrent analysis workers.
    *   `--depth`: The maximum depth for web crawling and interaction.

*   `scalpel report`: Generates a report from a completed scan. (Further details to be added).

*   `scalpel self-heal`: (Experimental) Attempts to automatically patch vulnerabilities found in a previous scan.

*   `scalpel evolution`: (Experimental) Runs the AI agent's self-improvement loop.

## Configuration

Scalpel is configured via a `config.yaml` file. The application looks for this file in the current directory by default. A detailed example with all available options can be found in `config.yaml.example`.

### Key Configuration Sections:

*   **`logger`**: Configures the logging level, format (console or JSON), and file output.
*   **`database`**: Specifies the connection details for the PostgreSQL knowledge graph.
*   **`agent`**: Contains settings for the AI agent, including the LLM router, knowledge graph, and long-term memory.
    *   **`llm`**: Configure different LLM providers (Gemini, OpenAI, etc.), API keys, and model names for "fast" and "powerful" tasks.
*   **`browser`**: Controls the behavior of the headless browser, including whether it runs in headless mode, viewport size, and `humanoid` settings for emulating human-like interaction.
*   **`network`**: Configures the underlying network client, including timeouts, custom headers, and proxy settings.
*   **`scanners`**: Provides fine-grained control to enable or disable specific security analyzers (e.g., `jwt`, `idor`, `taint`).

## Development

This section provides guidance for developers who want to contribute to the Scalpel CLI.

### Running Tests

The project has a comprehensive suite of unit and integration tests. To run all tests, use the standard Go command:

```bash
go test ./...
```

Some tests, particularly in the `internal/browser` package, require a running browser instance and may be slower. To run tests for a specific package:

```bash
# Example: Run tests only for the agent package
go test ./internal/agent/...
```

### Code Style and Conventions

Please follow the standard Go coding conventions (`gofmt`). We also encourage the use of `golangci-lint` to ensure code quality and consistency.

## Contributing

Contributions are welcome and greatly appreciated! We are always looking for improvements to Scalpel CLI.

There are many ways to contribute:

*   **Reporting Bugs:** If you find a bug, please open an issue on our GitHub repository. Be sure to include a clear title, a description of the issue, and steps to reproduce it.
*   **Suggesting Enhancements:** Have an idea for a new feature or an improvement to an existing one? Open an issue to discuss it.
*   **Pull Requests:** If you have a fix or a new feature you'd like to implement, we welcome pull requests.

When contributing, please follow the existing code style and conventions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

<details>
<summary>MIT License Text</summary>

```
MIT License

Copyright (c) 2025 Scalpel CLI Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
</details>
