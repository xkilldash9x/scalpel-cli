# Scalpel CLI

[![Go Test](https://github.com/your-org/scalpel-cli/actions/workflows/go-test.yaml/badge.svg)](https://github.com/your-org/scalpel-cli/actions/workflows/go-test.yaml)

Scalpel CLI is an AI-powered security auditing tool designed to analyze codebases, identify vulnerabilities, and provide automated fixes. It leverages Large Language Models (LLMs) to bring a new level of intelligence to application security testing, moving beyond simple pattern matching to understand the context and logic of your code.

## Overview

Scalpel is not just another static analysis tool. It acts as an AI agent that deeply understands your code. It combines static analysis, dynamic analysis orchestration, and a knowledge graph to build a comprehensive model of your application. This allows it to uncover complex vulnerabilities and, in many cases, automatically generate the code patches to fix them.

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
*   A configured LLM API key (e.g., Google AI Studio API Key)

### 1. Set Up the PostgreSQL Database

Scalpel uses a PostgreSQL database to store its knowledge graph and analysis results. The easiest way to get this running is with Docker.

**a. Launch PostgreSQL using Docker:**

Run the following command to start a PostgreSQL container. This will create a database named `scalpel_db` with a user `scalpel`.

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

**b. Configure `config.yaml`:**

Copy the `config.yaml.example` to `config.yaml` if it exists, or ensure your `config.yaml` is updated with your database and LLM provider credentials.

```yaml
# Example config.yaml
database:
  host: "localhost"
  port: 5432
  user: "scalpel"
  password: "secret" # Use environment variables or a secret management tool in production
  dbname: "scalpel_db"
  sslmode: "disable"

llm:
  # Your LLM provider configuration
  # e.g., for Gemini
  gemini:
    apiKey: "YOUR_GEMINI_API_KEY" # Use environment variables
```

### 3. Build the CLI

Compile the `scalpel` binary:

```bash
go build -o scalpel ./cmd/scalpel
```

## Usage

Once configured, you can run a scan on a target codebase.

```bash
./scalpel scan --target /path/to/your/project
```

To see all available commands and flags:

```bash
./scalpel --help
```

## Running Specific Analyzers

By default, Scalpel runs a broad set of analyzers. You can control which analyzers to run by editing the `analyzers` section in your `config.yaml` file.

To run only specific analyzers, you can disable the categories (e.g., `static`, `passive`) and enable individual analyzers by name.

**Example `config.yaml` for running only `jwt` and `idor`:**

```yaml
# Example config.yaml with specific analyzers enabled
database:
  # ... (database config)
llm:
  # ... (llm config)

analyzers:
  # Disable broad categories
  static: false
  passive: false
  active: false
  auth: false

  # Enable specific analyzers by name
  jwt: true
  idor: true
```

This configuration will ensure that only the "JWT" and "IDOR" analyzers are executed during the scan.

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
