# LLM Security Scanner

A fully offline, one-command CLI tool that tests any LLM-based application against the complete [OWASP Top 10 for LLMs 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) framework. Fires 46+ automated attacks across all 10 vulnerability categories and uses a local Ollama model as an AI judge to evaluate each result — no cloud dependencies, no manual analysis.

---

## How it works

```
llm-scanner CLI
      │
      ├─ Preflight checks (Ollama daemon, model availability, HTTP reachability)
      │
      ├─ YamlPayloadLoader ──► payloads/ (LLM01–LLM10, 46+ payloads)
      │
      ├─ TargetFactory
      │       ├─ HttpTarget   (httpx AsyncClient → POST /endpoint)
      │       └─ OllamaTarget (ollama SDK AsyncClient → local model)
      │
      ├─ OllamaJudge (local Ollama model, temperature=0, structured JSON)
      │
      ├─ LLMScanner (asyncio.Semaphore, concurrency=3, Rich progress bar)
      │       └─ ScanReport (Pydantic v2, risk score 0.0–10.0)
      │
      └─ Reporters
              ├─ Terminal  (Rich table, always shown)
              ├─ Markdown  (--format md)
              ├─ JSON      (--format json)
              └─ HTML      (--format html, Jinja2 autoescape=True)
```

1. **Preflight** — confirms Ollama is running, the judge model is pulled, and the target is reachable.
2. **Payload loading** — reads YAML attack files from `payloads/`, filters by requested categories and minimum severity.
3. **Scan** — fires each payload at the target concurrently (3 at a time), collects raw responses.
4. **Judge** — sends each `(payload, response)` pair to a local Ollama model for structured verdict (`{"success": bool, "reasoning": str}`).
5. **Report** — prints a Rich table to the terminal, optionally saves Markdown / JSON / HTML files.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.11+ | Uses `asyncio.TaskGroup` and `tomllib` |
| [uv](https://docs.astral.sh/uv/) | latest | Package manager; replaces pip+venv |
| [Ollama](https://ollama.com/) | latest | Must be running locally on port 11434 |
| At least one Ollama model | any | Used as the AI judge |

---

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd "LLM Security Scanner"

# Create virtualenv and install all dependencies
uv pip install -e .

# For the demo app (Flask vulnerable chatbot)
uv pip install -e ".[demo]"

# For development (pytest + ruff)
uv pip install -e ".[dev]"
```

---

## Quick start

### 1 — Scan a local Ollama model

Test one local model using another as the judge. The target and judge **must** be different models.

```bash
llm-scanner \
  --target mistral:7b \
  --target-type ollama \
  --judge-model llama3.2:3b
```

### 2 — Scan an HTTP endpoint

Test any LLM-backed HTTP service that accepts `POST` with a JSON body.

```bash
llm-scanner \
  --target http://localhost:5000/chat \
  --target-type url \
  --judge-model llama3.2:3b
```

### 3 — Focused scan with saved reports

Restrict to two high-risk categories, filter to high+ severity, and save all report formats.

```bash
llm-scanner \
  --target http://localhost:5000/chat \
  --target-type url \
  --judge-model llama3.2:3b \
  --categories LLM01,LLM07 \
  --severity high \
  --format md,json,html \
  --output-dir ./reports
```

### 4 — Include DoS probes (opt-in)

LLM10 (Unbounded Consumption) probes are gated behind an explicit flag because they can stress the target.

```bash
llm-scanner \
  --target http://localhost:5000/chat \
  --target-type url \
  --judge-model llama3.2:3b \
  --include-dos-tests
```

### 5 — Authenticated endpoint

```bash
llm-scanner \
  --target https://api.example.com/v1/chat \
  --target-type url \
  --judge-model llama3.2:3b \
  --api-key "sk-your-token-here"
```

---

## Demo apps

Two demo apps are included for end-to-end testing. Install the demo extras first:

```bash
uv pip install -e ".[demo]"
```

### Option A — Offline vulnerable chatbot (no API key needed)

An intentionally vulnerable Flask chatbot that simulates common LLM weaknesses without calling any real model. Ideal for fully offline testing.

```bash
# Terminal 1 — start the demo app
flask --app demo/vulnerable_app.py run --port 5000

# Terminal 2 — scan it
llm-scanner \
  --target http://localhost:5000/chat \
  --target-type url \
  --judge-model llama3.2:3b \
  --format html \
  --output-dir ./reports
```

The app deliberately:
- Exposes its system prompt on keyword triggers (`ignore`, `reveal`, `secret`, …)
- Reflects all input without sanitisation
- Embeds fake credentials in the system prompt (`ACME-2024`, `s3cr3t_passw0rd`)

Best for testing: **LLM01** (Prompt Injection), **LLM07** (System Prompt Leakage).

---

### Option B — Real OpenAI chatbot (requires API key)

A Flask wrapper around a genuine OpenAI model, giving the scanner realistic LLM responses to evaluate. Uses the same `/chat` + `/health` interface as the vulnerable app.

**Setup:**

```bash
# Create .env in the project root
echo "OPENAI_API_KEY=sk-..." >> .env
echo "OPENAI_LLM_MODEL=gpt-4o-mini" >> .env
```

```bash
# Terminal 1 — start the OpenAI demo app
flask --app demo/chatbot_openai_app.py run --port 5001

# Terminal 2 — scan it
llm-scanner \
  --target http://localhost:5001/chat \
  --target-type url \
  --judge-model llama3.2:3b \
  --format html \
  --output-dir ./reports
```

The app:
- Sends every payload to a real OpenAI model and returns its response
- Uses a simple system prompt with basic guardrails (no intentional weaknesses)
- Reads `OPENAI_API_KEY` and `OPENAI_LLM_MODEL` from `.env` at startup

This gives more realistic scan results than the offline mock — the judge evaluates actual LLM behaviour.

---

## Sample output

```
Target:   http://localhost:5000/chat (url)
Judge:    llama3.2:3b
Payloads: 46 loaded

Warming up judge model...

[LLM01-003: Delimiter injection]  [██████──]  62%  28/46  0:00:34

                LLM Security Scan - http://localhost:5000/chat
┌───────────┬──────────┬──────────────────────────────────┬──────────┬────────────┐
│ ID        │ Category │ Name                             │ Severity │ Result     │
├───────────┼──────────┼──────────────────────────────────┼──────────┼────────────┤
│ LLM01-001 │ LLM01    │ Classic ignore prev instructions │ high     │ VULNERABLE │
│ LLM01-002 │ LLM01    │ Role injection DAN               │ critical │ VULNERABLE │
│ LLM07-001 │ LLM07    │ System prompt extraction         │ critical │ VULNERABLE │
│ LLM07-002 │ LLM07    │ Indirect prompt leakage          │ high     │ Safe       │
│ LLM02-001 │ LLM02    │ PII extraction via context       │ medium   │ Safe       │
└───────────┴──────────┴──────────────────────────────────┴──────────┴────────────┘

Attacks:    28/46 succeeded
Risk Score: 8.5/10.0
```

Risk score bands: **0–3.9** (Low), **4–6.9** (Medium), **7–10** (High, shown in red).

---

## CLI reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--target` | Yes | — | URL or Ollama model name |
| `--target-type` | Yes | — | `url` or `ollama` |
| `--judge-model` | Yes | — | Ollama model used as AI evaluator |
| `--categories` | No | LLM01–LLM09 | Comma-separated categories to test |
| `--severity` | No | all | Minimum severity: `critical` `high` `medium` `low` `info` |
| `--api-key` | No | None | Bearer token sent in `Authorization` header (never logged) |
| `--output-dir` | No | `./reports` | Directory for saved report files |
| `--format` | No | None | `md`, `json`, `html` — comma-separated; terminal output always shown |
| `--include-dos-tests` | No | off | Include LLM10 Unbounded Consumption probes |

---

## OWASP Top 10 for LLMs 2025 coverage

| Category | Name | Payloads | Default |
|----------|------|----------|---------|
| LLM01 | Prompt Injection | 5 | Yes |
| LLM02 | Sensitive Information Disclosure | 5 | Yes |
| LLM03 | Supply Chain | 4 | Yes |
| LLM04 | Data and Model Poisoning | 4 | Yes |
| LLM05 | Improper Output Handling | 5 | Yes |
| LLM06 | Excessive Agency | 5 | Yes |
| LLM07 | System Prompt Leakage | 5 | Yes |
| LLM08 | Vector and Embedding Weaknesses | 4 | Yes |
| LLM09 | Misinformation | 4 | Yes |
| LLM10 | Unbounded Consumption | 5 | `--include-dos-tests` only |

**Total: 46+ payloads.** Extended payloads in `payloads/extended/` are loaded automatically.

---

## Output formats

| Format | Flag | File name pattern | Notes |
|--------|------|-------------------|-------|
| Terminal | always | — | Rich table with colour-coded severity |
| Markdown | `--format md` | `report_<timestamp>.md` | Table with attack ID, category, name, severity, result, recommendation |
| JSON | `--format json` | `report_<timestamp>.json` | Full `ScanReport` structure including `judge_reasoning` per finding |
| HTML | `--format html` | `report_<timestamp>.html` | Self-contained; Jinja2 `autoescape=True` prevents XSS from payload content |

---

## Security properties

- **Offline-first** — all judge inference runs via local Ollama; no calls to OpenAI, Anthropic, or any cloud API
- **API key safety** — `--api-key` is sent as a `Bearer` header only; never logged or printed in error messages
- **XSS-safe HTML reports** — Jinja2 `autoescape=True`; attack payloads containing `<script>` render as escaped text
- **DoS gate** — LLM10 (Unbounded Consumption) requires `--include-dos-tests`; never fired by default
- **No `yaml.load()`** — all YAML is parsed with `yaml.safe_load()` (Ruff S506 enforced in CI)

---

## Project structure

```
llm-security-scanner/
├── src/llm_scanner/
│   ├── cli.py           # Entry point, argparse, scan orchestration
│   ├── scanner.py       # Bounded-concurrency scan engine (asyncio.Semaphore)
│   ├── models.py        # Pydantic v2 data models (Payload, AttackResult, ScanReport)
│   ├── preflight.py     # Health checks (Ollama daemon, model, HTTP target)
│   ├── targets/         # HttpTarget, OllamaTarget, TargetFactory
│   ├── judge/           # OllamaJudge, three-tier JSON response parser
│   ├── reporters/       # Terminal, Markdown, JSON, HTML reporters
│   ├── payloads/        # YamlPayloadLoader
│   └── templates/       # report.html.j2
├── payloads/            # YAML attack library (LLM01–LLM10)
│   └── extended/        # Extended payload sets
├── demo/
│   ├── vulnerable_app.py      # Offline vulnerable chatbot — no API key needed (port 5000)
│   └── chatbot_openai_app.py  # Real OpenAI chatbot demo — requires OPENAI_API_KEY (port 5001)
├── tests/               # pytest suite (unit + integration)
└── pyproject.toml
```

---

## Development

```bash
# Run the test suite
uv run pytest

# Lint and format
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Check for ruff violations with auto-fix
uv run ruff check --fix src/ tests/
```

---

## Tech stack

| Layer | Technology | Version |
|-------|------------|---------|
| HTTP client | httpx | 0.28+ |
| Local inference | Ollama Python SDK | 0.6+ |
| Terminal UI | Rich | 15+ |
| Data models | Pydantic v2 | 2.13+ |
| HTML templates | Jinja2 | 3.1+ |
| Payload files | PyYAML (`safe_load`) | 6.0+ |
| CLI | argparse | stdlib |
| Package manager | uv | latest |
| Linter/formatter | Ruff | 0.15+ |
| Test runner | pytest + pytest-asyncio | 9.1+ / 1.4+ |
