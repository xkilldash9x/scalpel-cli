# Contributing to Scalpel CLI

We welcome contributions from the community! Please read this guide to learn how you can help improve Scalpel CLI.

## How to Contribute

-   **Report bugs:** If you find a bug, please open an issue on our GitHub repository.
-   **Suggest features:** If you have an idea for a new feature, please open an issue to discuss it.
-   **Write code:** If you want to contribute code, please fork the repository and submit a pull request.

## Development Setup

To get started with development, you will need:

-   Go 1.25+
-   Node.js and npm
-   Docker and Docker Compose

1.  Clone the repository.
2.  Run `docker-compose up` to start the database.
3.  Run `go run ./cmd/scalpel mcp` to start the backend server.
4.  Run `npm install` and `npm run dev` in the `frontend` directory to start the frontend development server.
