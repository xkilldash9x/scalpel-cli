# -- Stage 1: Build the binary --
# Use the official Go image matching the go.mod version (1.25).
FROM golang:1.25-alpine AS builder

# Define UID/GID for the non-root user for consistency.
ARG UID=10001
ARG GID=10001

# Install CA certificates (required for HTTPS calls) and git (often needed for dependencies).
RUN apk add --no-cache ca-certificates git

# Create a non-root user and group.
RUN addgroup -g $GID -S appgroup && adduser -u $UID -S appuser -G appgroup

# Define a build argument for the version.
ARG VERSION=development

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum first for caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code.
COPY . .

# Create the logs directory and set permissions using numeric ID.
# This is required for the non-root user to write logs later.
RUN mkdir -p logs && chown $UID:$GID logs

# Build the Go application into a single, statically linked binary.
# CGO_ENABLED=0: static binary without C dependencies.
# -trimpath: remove file system paths for reproducibility and security.
# -ldflags (-s -w): strip debug information for smaller size.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X 'github.com/xkilldash9x/scalpel-cli/cmd.Version=$VERSION'" \
    -a -o /out/scalpel-cli ./cmd/scalpel/main.go

# -- Stage 2: Create the final, minimal image --
# Start from a scratch image for a minimal footprint.
FROM scratch

# Import the UID defined in the builder stage
ARG UID=10001

# Copy essential CA certificates and user/group definitions (required for non-root in scratch)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy the compiled binary.
COPY --from=builder /out/scalpel-cli /usr/local/bin/scalpel-cli

# Set the working directory in the final image
WORKDIR /app

# Copy the default configuration file and necessary runtime assets (IAST shims).
# We must preserve the directory structure expected by the relative paths in config.yaml.
COPY --from=builder /app/config.yaml /app/config.yaml
COPY --from=builder /app/internal/browser/shim /app/internal/browser/shim

# Copy the pre-created logs directory. Ownership metadata is preserved from the builder stage.
COPY --from=builder /app/logs /app/logs

# Switch to the non-root user using the numeric UID.
USER $UID

# Define the command to run when the container starts.
ENTRYPOINT ["/usr/local/bin/scalpel-cli"]