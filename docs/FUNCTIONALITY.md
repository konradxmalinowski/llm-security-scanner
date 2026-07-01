# Functionality Overview — LLM Security Scanner (OSS)

High-level reference for what this repo actually does today. Written from the current code; open questions at the bottom are for you to fill in.

## What it is

A CLI (`llm-scanner`) that fires a battery of OWASP Top 10 for LLMs (2025) attacks at a target — either an HTTP endpoint or a local Ollama model — and uses a second local Ollama model as an "AI judge" to decide whether each attack succeeded.

## Targets

- **`--target-type url`** — any HTTP/HTTPS endpoint (`httpx` async client), optional `--api-key` bearer token.
- **`--target-type ollama`** — a local Ollama model name; the target model and the judge model must differ.
- `--targets <file.yml>` — scan several targets from one YAML file for side-by-side comparison.

## Attack library

- YAML files under `payloads/`, one per OWASP category (`llm01_prompt_injection.yaml` … `llm10_unbounded_consumption.yaml`), each entry with `id`, `name`, `payload`, `judge_criteria`.
- 4–5 payloads per category, ~41 total, plus `payloads/extended/llm10_extended.yaml` with more Unbounded Consumption probes.
- `--categories` filters which OWASP categories run; `--severity` filters by minimum severity.
- LLM10 (Unbounded Consumption / DoS-style probes) is excluded by default — opt in with `--include-dos-tests`.

## Scan flow

1. **Preflight** (`preflight.py`) — checks Ollama is reachable, the judge model is pulled, and (for URL targets) the endpoint responds.
2. **Load payloads** — `YamlPayloadLoader`, filtered by category/severity.
3. **Scan** — attacks run concurrently (`asyncio.Semaphore`, bounded concurrency) against the target, collecting raw responses.
4. **Judge** — each `(payload, response)` pair goes to the Ollama judge model, which must return `{"success": bool, "reasoning": str}`; a three-tier parser recovers from malformed/non-JSON judge output rather than crashing.
5. **Suppressions** — `--suppressions <file.yml>` can exclude known false positives from the final report.
6. **Report** — risk score (0.0–10.0, severity-weighted) plus per-attack results.

## Reports

- Terminal (Rich table) — always shown.
- `--format` controls saved files: `md`, `json`, `html`, `txt` (default: all four) into a timestamped subfolder under `--output-dir` (default `./reports`).
- SARIF 2.1.0 output (`reporters/sarif.py`) — for code-scanning integrations (e.g. GitHub code scanning).
- Trend dashboard (`reporters/trend.py`) — Chart.js HTML dashboard across historical scans.
- Baseline management: `llm-scanner baseline save --name X` / `llm-scanner baseline compare --name X` to diff a new scan against a saved baseline.
- `--fail-on-score <n>` — exit code 1 if risk score ≥ n, for CI gating.

## CI/CD integration

- `.github/workflows/llm-scan.yml` + `.github/actions/llm-scan/action.yml` — GitHub Actions integration.
- `examples/gitlab/*.yml` — GitLab CI integration.
- `examples/docker/`, `Dockerfile` — containerized scanning (local Docker Compose target or CI runner).
- `examples/config/*.yml` — sample scan configs (`--config`) for local URL, public URL, Ollama target, and CI.

## Demo targets (`demo/`)

- `vulnerable_app.py` — intentionally vulnerable offline Flask chatbot (port 5000), no API key needed.
- `chatbot_openai_app.py` — real OpenAI-backed chatbot demo (port 5001), needs `OPENAI_API_KEY` in `.env`.

## Tech stack

Python 3.11+, `uv`, httpx, `ollama` SDK, Pydantic v2, Rich, Jinja2 (autoescape on), PyYAML (`safe_load` only), pytest + pytest-asyncio, ruff (with bandit S-rules).

## Not in this repo

The landing page and hosted web-scan service moved to the private `llm-security-scanner-saas` repo, which installs this package as a dependency and shells out to `llm-scanner`.

---

## Decisions (2026-07-01)

- **License**: MIT (`LICENSE`, `pyproject.toml` `license = "MIT"`).
- **Versioning/releases**: tagged GitHub releases + `CHANGELOG.md`, no PyPI publishing — install via `pip install git+https://github.com/konradxmalinowski/llm-security-scanner`.
- **Contribution model**: `CONTRIBUTING.md` + issue/PR templates added now, ahead of any external contributors.
- **DoS/LLM10 defaults**: stays opt-in (`--include-dos-tests`) — confirmed as the safe default.
- **Roadmap**: no concrete plans beyond the current scope yet, except:
  - support for judge models beyond Ollama (currently offline-first/Ollama-only per `CLAUDE.md` — this would need that constraint revisited)
  - deeper OWASP payload coverage (more than the current ~41 payloads)
- **Public link to the SaaS product**: none yet. Once the private `llm-security-scanner-saas` service has a public launch, this README should link to it as a hosted option.
