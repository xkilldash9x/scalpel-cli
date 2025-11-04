<div align="center">

<!-- TODO: Add a project logo -->
<!-- <img src="path/to/logo.png" alt="Scalpel Logo" width="200"/> -->

# Scalpel CLI

**An AI-Augmented Dynamic Application Security Testing (DAST) Scanner**

</div>

<div align="center">

[![Go Version](https://img.shields.io/github/go-mod/go-version/xkilldash9x/scalpel-cli)](https://go.dev/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/xkilldash9x/scalpel-cli/go.yml?branch=main)](https://github.com/xkilldash9x/scalpel-cli/actions)
[![License](https://img.shields.io/github/license/xkilldash9x/scalpel-cli)](./LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](./CONTRIBUTING.md)

</div>

---

**Scalpel** is not just another web scanner. It's a next-generation security tool that fuses traditional, battle-tested DAST techniques with a powerful **AI Agent System**. By leveraging Large Language Models (LLMs) and a persistent Knowledge Graph, Scalpel goes beyond simple vulnerability detection to build a deep, contextual understanding of your application.

This allows for more accurate findings, intelligent analysis, and paves the way for features like automated patch generation (`autofix`).

## Key Features

*   **AI-Powered Agent System**: Utilizes LLMs (like Google's Gemini) and a Knowledge Graph for deep contextual analysis. See AGENTS.md for details.
*   **Comprehensive Discovery**: High-speed, concurrent crawling and passive subdomain enumeration (`crt.sh`, etc.) to build a complete map of the target.
*   **Modern Web App Support**: Full headless browser interaction for scanning Single Page Applications (SPAs) built with frameworks like React, Vue, and Angular.
*   **Advanced Active Scanners**:
    *   **`timeslip`**: Detects time-of-check-to-time-of-use (TOCTOU) race conditions.
    *   **`protopollution`**: Identifies client-side and server-side prototype pollution vulnerabilities.
    *   **`auth`**: Tests for account takeover (ATO) vulnerabilities and insecure direct object references (IDOR).
*   **Passive Analysis**: Scans for exposed JWT secrets, insecure headers, and other low-hanging fruit without sending intrusive traffic.
*   **Automated Patching (Experimental)**: The `autofix` module uses the Agent System to propose and generate code patches for certain vulnerability classes.
*   **Flexible Reporting**: Generates reports in multiple formats, including industry-standard **SARIF** for easy integration with CI/CD pipelines and security dashboards.

## Demo


```
./scalpel-cli scan https://example.com --output report.sarif

2025-11-04T10:20:00.123-0800  INFO  scalpel-cli  Starting new scan...
...
2025-11-04T10:21:30.456-0800  INFO  worker       [timeslip] Potential race condition found on POST /api/vouchers
...
2025-11-04T10:22:00.789-0800  INFO  scalpel-cli  Scan execution completed successfully.
2025-11-04T10:22:01.123-0800  INFO  scalpel-cli  Report generated successfully.

Scan Complete. Scan ID: 018f5c49-ab12-c345-de67-fabc89012345
```

## Installation

### From Source 

Ensure you have Go 1.25+ installed.

```bash
# Clone the repository
git clone https://github.com/xkilldash9x/scalpel-cli.git
cd scalpel-cli

# Build the binary
go build -o scalpel-cli ./cmd/scalpel
```

### Using `go install`

```bash
go install github.com/xkilldash9x/scalpel-cli/cmd/scalpel@latest
```

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
