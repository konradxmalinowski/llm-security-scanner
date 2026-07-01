# LLM Security Scanner

A fully offline, one-command tool that tests LLM applications against all 10 OWASP Top 10 for LLMs 2025 vulnerabilities. Uses a local Ollama model as an AI judge — no cloud dependencies.

## Architecture

```
llm-scanner CLI (argparse)
      |
      +-- Preflight checks (Ollama daemon, model availability, HTTP reachability)
      |
      +-- YamlPayloadLoader --> payloads/ (LLM01-LLM10, >=40 payloads)
      |
      +-- TargetFactory
      |       +-- HttpTarget  (httpx AsyncClient, POST /endpoint)
      |       +-- OllamaTarget (ollama SDK AsyncClient)
      |
      +-- OllamaJudge (Ollama local model, temperature=0, structured JSON output)
      |
      +-- LLMScanner (asyncio.Semaphore concurrency=3, Rich progress bar)
      |       |
      |       +-- ScanReport (Pydantic v2, risk score 0.0-10.0)
      |
      +-- Reporters
              +-- Terminal   (Rich table, always shown)
              +-- Markdown   (--format md)
              +-- JSON       (--format json)
              +-- HTML       (--format html, Jinja2 autoescape=True)
```

## Quick Start

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- [Ollama](https://ollama.com/) running locally with at least one model

```bash
# Install
git clone <repo-url>
cd llm-security-scanner
uv pip install -e .

# Pull a judge model (if not already available)
ollama pull llama3.2:3b

# Scan a local Ollama model
llm-scanner --target mistral:7b --target-type ollama --judge-model llama3.2:3b

# Scan an HTTP endpoint
llm-scanner --target http://localhost:5000/chat --target-type url --judge-model llama3.2:3b

# Restrict categories and save reports
llm-scanner --target http://localhost:5000/chat --target-type url \
            --judge-model llama3.2:3b \
            --categories LLM01,LLM07 \
            --severity high \
            --format md,json,html \
            --output-dir ./reports

# Include DoS probes (opt-in, may stress the target)
llm-scanner --target http://localhost:5000/chat --target-type url \
            --judge-model llama3.2:3b --include-dos-tests
```

### Demo App (offline testing)

Run the intentionally vulnerable Flask chatbot to test the scanner without a real LLM endpoint:

```bash
# Install Flask optional dependency
uv pip install -e ".[demo]"

# Start the demo app
flask --app demo/vulnerable_app.py run --port 5000

# In another terminal, run the scanner against it
llm-scanner --target http://localhost:5000/chat --target-type url \
            --judge-model llama3.2:3b
```

## Sample Terminal Output

```
Target:   http://localhost:5000/chat (url)
Judge:    llama3.2:3b
Payloads: 45 loaded

Warming up judge model...

[LLM01-003: Role confusion via ...]  [####----]  18%  8/45  0:00:12

                  LLM Security Scan - http://localhost:5000/chat
+-----------+-----------+----------------------------------+----------+------------+
| ID        | Category  | Name                             | Severity | Result     |
+-----------+-----------+----------------------------------+----------+------------+
| LLM01-001 | LLM01     | Basic prompt injection           | high     | VULNERABLE |
| LLM01-002 | LLM01     | Role override injection          | critical | VULNERABLE |
| LLM07-001 | LLM07     | System prompt extraction         | critical | VULNERABLE |
| LLM07-002 | LLM07     | Indirect prompt leakage          | high     | Safe       |
| LLM02-001 | LLM02     | PII extraction via context       | medium   | Safe       |
+-----------+-----------+----------------------------------+----------+------------+

Attacks:    28/45 succeeded
Risk Score: 8.5/10.0
```

## CLI Reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--target` | Yes | - | URL or Ollama model name |
| `--target-type` | Yes | - | `url` or `ollama` |
| `--judge-model` | Yes | - | Ollama model for AI evaluation |
| `--categories` | No | LLM01-LLM09 | Comma-separated OWASP categories |
| `--severity` | No | all | Minimum: `critical`, `high`, `medium`, `low`, `info` |
| `--api-key` | No | None | Bearer token for URL targets |
| `--output-dir` | No | `./reports` | Directory for saved report files |
| `--format` | No | None | `md`, `json`, `html` (comma-separated) |
| `--include-dos-tests` | No | off | Include LLM10 Unbounded Consumption probes |

## OWASP Top 10 for LLMs 2025 Coverage

| Category | Name | Payloads | Notes |
|----------|------|----------|-------|
| LLM01 | Prompt Injection | 5+ | Included by default |
| LLM02 | Sensitive Information Disclosure | 5+ | Included by default |
| LLM03 | Supply Chain | 4+ | Included by default |
| LLM04 | Data and Model Poisoning | 4+ | Included by default |
| LLM05 | Improper Output Handling | 5+ | Included by default |
| LLM06 | Excessive Agency | 5+ | Included by default |
| LLM07 | System Prompt Leakage | 5+ | Included by default |
| LLM08 | Vector and Embedding Weaknesses | 4+ | Included by default |
| LLM09 | Misinformation | 4+ | Included by default |
| LLM10 | Unbounded Consumption | 5+ | Requires `--include-dos-tests` |

**Total: 46+ payloads across all 10 categories.**

## Tech Stack

| Component | Technology |
|-----------|------------|
| HTTP client | httpx 0.28+ (async, connection pooling) |
| Local inference | Ollama SDK 0.6+ |
| Terminal UI | Rich 15+ (progress bars, tables) |
| Data models | Pydantic v2 (JSON serialization, validation) |
| HTML reports | Jinja2 3.1+ (autoescape=True, XSS-safe) |
| Payload format | YAML (PyYAML, safe_load only) |
| CLI | argparse (stdlib, zero extra deps) |

## Security Properties

- **Offline-first**: All judge inference runs via local Ollama — no calls to OpenAI, Anthropic, or any cloud API
- **API key safety**: `--api-key` is passed as a Bearer header only; never logged, never printed in error messages
- **XSS-safe reports**: HTML reports use Jinja2 `autoescape=True`; attack payloads containing `<script>` render as escaped text
- **DoS opt-in**: LLM10 (Unbounded Consumption) probes require `--include-dos-tests` — not fired by default

## Project Structure

```
llm-security-scanner/
+-- src/llm_scanner/
|   +-- cli.py           # CLI entry point (argparse)
|   +-- scanner.py       # Bounded-concurrency scan engine
|   +-- models.py        # Pydantic data models
|   +-- preflight.py     # Health checks
|   +-- targets/         # HttpTarget, OllamaTarget, TargetFactory
|   +-- judge/           # OllamaJudge, three-tier JSON parser
|   +-- reporters/       # Terminal, Markdown, JSON, HTML reporters
|   +-- payloads/        # YamlPayloadLoader
|   +-- templates/       # report.html.j2
+-- payloads/            # YAML payload library (LLM01-LLM10)
+-- demo/                # Intentionally vulnerable Flask chatbot
+-- tests/               # pytest suite
```
