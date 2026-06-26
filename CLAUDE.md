<!-- GSD:project-start source:PROJECT.md -->

## Project

**LLM Security Scanner**

A Python CLI tool that tests LLM-based applications against the full OWASP Top 10 for LLMs vulnerability framework. It accepts either an HTTP endpoint or a local Ollama model as a target, runs a battery of ~50 automated attacks, and uses a second Ollama model as an AI Judge to evaluate each result — producing reports in terminal, Markdown, JSON, and HTML formats.

**Core Value:** Give security engineers a fully offline, one-command tool to test any LLM endpoint or local model against all 10 OWASP LLM attack categories — no cloud dependencies, no manual analysis.

### Constraints

- **Tech Stack**: Python 3.11+, httpx, ollama SDK, rich, Pydantic v2, jinja2, pytest — no deviations from spec
- **Offline-first**: All judge inference via local Ollama — no calls to OpenAI/Anthropic/etc.
- **Payload format**: YAML files per OWASP category; each payload must have `id`, `name`, `payload`, `judge_criteria`
- **Judge contract**: Must return parseable JSON `{"success": bool, "reasoning": str}` — parser must handle malformed output gracefully
- **OWASP coverage**: All 10 categories (LLM01–LLM10) must have at least 4 payloads each to reach ≥40 total

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->

## Technology Stack

## Recommended Stack

### Core Runtime

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| Python | 3.11+ | Runtime | `asyncio.TaskGroup` (3.11+) for parallel attack dispatch; modern `match` for pattern-matching judge output; `tomllib` stdlib |
| uv | latest | Package/venv manager | Replaces pip+venv; lockfile-native; `uv run` executes CLI without install |

### HTTP Client (Attack Delivery)

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| httpx | 0.28.1 | Async HTTP to URL targets | Sync+async parity (same API surface); native `AsyncClient`; fine-grained `Timeout(connect=5, read=120)` for slow LLM responses; `HTTPTransport(retries=N)` for flaky endpoints. Outperforms aiohttp on DX and error handling. |

### Ollama SDK (Local Model Inference)

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| ollama | 0.6.2 | Chat with local models | Official SDK; `AsyncClient` mirrors httpx's async model; structured output via Pydantic schema; `format='json'` for judge responses |

- `chat()` accepts a `messages` list — supports system prompt + user turn in one call, which is exactly the judge pattern: `[{"role": "system", "content": judge_prompt}, {"role": "user", "content": f"Payload: {p}\nResponse: {r}"}]`
- `generate()` is for single-prompt completion without conversation history — appropriate only for raw completions, not structured judge evaluation
- `chat()` with `format=JudgeOutput.model_json_schema()` forces structured JSON output natively (Ollama >= 0.5.0 supports Pydantic schema in `format`)

### Terminal UI

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| rich | 15.0.0 | Progress bars, colored tables, console output | Industry standard for Python CLI UX; `Progress` context manager with `track()` is idiomatic; `Table` renders colored severity columns without extra dependencies |

### Data Models

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| pydantic | 2.13.4 | AttackResult, ScanReport, Severity models | v2 is 10–20x faster than v1; `model_dump_json()` outputs JSON directly; `ConfigDict(extra='forbid')` catches YAML schema drift; enum serialization in JSON mode outputs values not members |

### Template Engine

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| jinja2 | 3.1.6 | HTML report generation | Standard for Python templating; `FileSystemLoader` loads from `templates/` dir; auto-escaping via `Environment(autoescape=True)` mandatory for security tools (prevents XSS in report if payloads contain HTML) |

### YAML Payload Loader

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| PyYAML | 6.0.3 | Loading payload YAML files | Sufficient for read-only structured data; simpler API than ruamel.yaml; always use `yaml.safe_load()` |

### CLI Framework

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| argparse | stdlib | CLI argument parsing | Per project spec; zero extra dependencies; sufficient for flat argument surface (~10 flags, no subcommands); security-tool users expect POSIX-standard `--flag value` syntax |

- **Click (38.7% market share in 2025):** Better DX for complex CLIs with subcommands, but adds a dependency. Unnecessary here — no subcommands, no command groups.
- **Typer:** Adds Click as transitive dep; designed for type-hint-native CLIs. Overkill for a single-command tool. Also 14ms startup vs argparse 18ms (negligible, but argparse wins on dep count).
- **argparse wins here because:** flat single-command surface; zero deps; pip-installable by security teams in air-gapped environments without extra packages.

### Testing

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| pytest | 9.1.1 | Test runner | Standard |
| pytest-asyncio | 1.4.0 | Async test support | Required for testing `AsyncClient` judge and httpx async scanner; `asyncio_mode = "auto"` eliminates decorator noise |

# No decorator needed in auto mode

### Linter / Formatter

| Technology | Version | Purpose | Why |
|------------|---------|---------|-----|
| ruff | 0.15.20 | Linting + formatting | Replaces flake8 + black + isort in one tool; 100x faster; S-series rules (flake8-bandit) flag unsafe YAML, subprocess calls, hardcoded secrets — exactly what a security tool should self-enforce |

- `S506`: `yaml.load()` without `Loader=yaml.SafeLoader` → force `yaml.safe_load()`
- `S701`: Jinja2 `Environment(autoescape=False)` → force `autoescape=True`
- `S105`/`S106`: hardcoded API keys/passwords in source
- `S113`: requests without timeout (not applicable with httpx, but good discipline)

## Dependency Summary

### Production (`[project.dependencies]`)

### Dev (`[project.optional-dependencies]`)

## Alternatives Explicitly Rejected

| Category | Recommended | Alternative | Why Rejected |
|----------|-------------|-------------|--------------|
| HTTP client | httpx | aiohttp | aiohttp's session lifecycle is more verbose; no sync parity; DX inferior |
| HTTP client | httpx | requests | Blocking — incompatible with async attack loop |
| CLI framework | argparse | Click | Adds dependency; subcommands not needed |
| CLI framework | argparse | Typer | Click transitive dep; startup overhead; overkill for flat CLI |
| Models | pydantic v2 | dataclasses | No JSON serialization; no validation; no schema generation for Ollama `format=` |
| YAML | PyYAML | ruamel.yaml | Needed only for round-trip write-back (preserving comments); payload files are read-only |
| YAML | PyYAML | StrictYAML | No standard pip install; unnecessary for internal authored payload files |
| Linting | ruff | flake8+black+isort | Three tools replaced by one; ruff is 100x faster |
| Judge inference | ollama.chat() | ollama.generate() | generate() lacks system/user turn structure for structured evaluation |
| Jinja2 autoescape | autoescape=True | autoescape=False | Attack payloads contain HTML/JS; False creates XSS in rendered reports; Ruff S701 flags it |

## Sources

- httpx async client: https://www.python-httpx.org/advanced/timeouts — HIGH confidence (official docs via Context7)
- Ollama Python SDK: https://github.com/ollama/ollama-python/blob/main/README.md — HIGH confidence (official SDK via Context7)
- Ollama chat vs generate: https://context7.com/ollama/ollama-python/llms.txt — HIGH confidence (official docs)
- Rich tables and progress: https://rich.readthedocs.io/en/stable/tables.html — HIGH confidence (official docs via Context7)
- Pydantic v2 serialization: https://github.com/pydantic/pydantic/blob/main/docs/concepts/serialization.md — HIGH confidence (official docs via Context7)
- pytest-asyncio auto mode: https://pytest-asyncio.readthedocs.io/en/stable/concepts.html — HIGH confidence (official docs via Context7)
- Ruff S-series (bandit) rules: https://docs.astral.sh/ruff/rules — HIGH confidence (official docs via Context7)
- PyYAML vs ruamel.yaml: https://yaml.dev/doc/ruamel.yaml/pyyaml/ — MEDIUM confidence (official ruamel docs, cross-checked with PyYAML docs)
- Jinja2 FileSystemLoader: https://jinja.palletsprojects.com/en/stable/api — HIGH confidence (official docs via Context7)
- argparse vs Click vs Typer: https://dasroot.net/posts/2025/12/building-cli-tools-python-click-typer-argparse/ — MEDIUM confidence (third-party article, consistent with project spec decision)
- Package versions: PyPI index (pip index versions), confirmed 2026-06-25

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
