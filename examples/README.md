# Examples

Use the example that matches where your target runs and how you want to execute the scanner.

## Config files

- `config/local-url.yml`
  Scan a local HTTP endpoint such as `http://localhost:5000/chat`.
- `config/public-url.yml`
  Scan a public HTTPS endpoint from your machine or a runner.
- `config/ollama-target.yml`
  Scan an Ollama model directly instead of an HTTP app.
- `config/ci-url.yml`
  Shared baseline config for CI/CD jobs. Override `LLM_ENDPOINT` per environment.
- `llm-scan.yml`
  Backward-compatible generic example. Prefer the files in `config/` for new setups.

## Pipeline templates

- `github/llm-security.yml`
  GitHub Actions example without Docker. The scanner is installed directly in the runner via the composite action.
- `github/llm-security.docker.yml`
  GitHub Actions example that builds the scanner image and runs the scan in Docker.
- `gitlab/llm-security.gitlab-ci.yml`
  GitLab CI example that installs the package directly in the job container.
- `gitlab/llm-security.gitlab-ci.docker.yml`
  GitLab CI example that builds the scanner image and runs the scan in Docker.

## Docker

- `docker/docker-compose.local.yml`
  Local Docker Compose setup only:
  - Ollama runs in a container
  - the scanner runs in a container
  - your target app stays on the host machine by default via `http://host.docker.internal:5000/chat`

## Quick starts

Local HTTP app:

```bash
LLM_ENDPOINT=http://localhost:5000/chat \
llm-scanner --config examples/config/local-url.yml
```

Public endpoint:

```bash
LLM_ENDPOINT=https://your-app.com/chat \
llm-scanner --config examples/config/public-url.yml
```

Direct Ollama model scan:

```bash
llm-scanner --config examples/config/ollama-target.yml
```

Local Docker run:

```bash
docker compose -f examples/docker/docker-compose.local.yml up
```
