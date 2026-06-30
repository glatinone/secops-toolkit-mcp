# Container image for the SecOps Toolkit MCP server.
# An MCP client (or Glama's introspection check) launches it over stdio.
FROM python:3.11-slim

# Pull the uv binary from its official image for fast, reproducible installs.
COPY --from=ghcr.io/astral-sh/uv:0.11.25 /uv /uvx /bin/

WORKDIR /app

# Copy only what's needed to build and install the package.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src

# Install exactly the locked dependencies (no dev tools) into the image.
RUN uv sync --frozen --no-dev

# Start the MCP server over stdio.
ENTRYPOINT ["uv", "run", "--no-dev", "secops-toolkit-mcp"]
