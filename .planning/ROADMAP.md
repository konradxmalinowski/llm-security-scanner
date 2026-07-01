# Roadmap: LLM Security Scanner

## Overview

The scanner is built bottom-up in four horizontal layers that mirror the data-flow dependency graph from ARCHITECTURE.md. Phase 1 lays the data foundation (Pydantic models + YAML payload library) that every other layer imports. Phase 2 wires in the two I/O subsystems (targets + AI judge) that must exist before any scan loop can run. Phase 3 assembles the scan engine and CLI surface that drives those subsystems. Phase 4 adds the output layer (reporters), a demo target for offline testing, and the test suite that validates the whole stack — leaving the project shippable.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - Pydantic models + YAML payload library (the data layer every other layer imports) (completed 2026-06-27)
- [x] **Phase 2: Core Engine** - HTTP/Ollama targets + AI Judge + preflight health checks (completed 2026-06-30)
- [x] **Phase 3: Scanner + CLI** - Bounded-concurrency scan loop + full argparse CLI surface (completed 2026-07-01)
- [x] **Phase 4: Reports, Tests & Demo** - All four reporters + pytest suite + demo app + README (completed 2026-07-01)
- [ ] **Phase 5: Advanced Features** - CI/CD integration, baseline/regression mode, scan history dashboard, SARIF output, false-positive suppression, multi-target scan

## Phase Details

### Phase 1: Foundation

**Goal**: The data layer is in place — all Pydantic models round-trip through JSON and the full YAML payload library loads, validates, and filters correctly
**Depends on**: Nothing (first phase)
**Requirements**: MODEL-01, MODEL-02, MODEL-03, MODEL-04, PAYLOAD-01, PAYLOAD-02, PAYLOAD-03, PAYLOAD-04, PAYLOAD-05
**Success Criteria** (what must be TRUE):

  1. `Severity`, `AttackResult`, and `ScanReport` models serialize and deserialize via `model_dump_json()` without data loss
  2. `YamlPayloadLoader` loads all 10 YAML files and returns ≥40 `Payload` objects with IDs in `LLM{NN}-{NNN}` format (OWASP 2025 numbering)
  3. Filtering by category (e.g., `["LLM01"]`) returns only payloads from that OWASP category; filtering by severity returns only matching entries
  4. All 10 OWASP 2025 categories (LLM01–LLM10) have ≥4 payloads each with non-empty `judge_criteria` fields; LLM10 aggressive payloads are in `extended/` only
  5. `ruff check src/ payloads/` passes with zero errors on all model and loader files

**Plans**: 5 plans

### Phase 2: Core Engine

**Goal**: Any LLM target (HTTP or Ollama) can receive a payload and return a response; the AI Judge evaluates each result without ever crashing the scan
**Depends on**: Phase 1
**Requirements**: TARGET-01, TARGET-02, TARGET-03, TARGET-04, TARGET-05, JUDGE-01, JUDGE-02, JUDGE-03, JUDGE-04, JUDGE-05
**Success Criteria** (what must be TRUE):

  1. Preflight check prints a human-readable error and exits before any attack when the target is unreachable or the judge model is not available in Ollama
  2. `HttpTarget.send()` and `OllamaTarget.send()` both accept a prompt string and return a response string through the identical `AbstractTarget` interface
  3. Each attack uses a fresh `messages=[]` context — a successful jailbreak in attack N cannot influence attack N+1
  4. `OllamaJudge.evaluate()` returns `{"success": bool, "reasoning": str}` for valid judge output and returns a `JudgeResult` with an `error` field (never raises) for timeouts, model unavailability, or malformed JSON via the three-tier fallback parser
  5. Judge always calls Ollama with `temperature=0` and structured JSON output format; the judge model is enforced to differ from the target model at startup

**Plans**: 3 plans
Plans:
**Wave 1**

- [x] 02-01-PLAN.md — JudgeResult model + targets/ package (AbstractTarget, HttpTarget, OllamaTarget, TargetFactory) + target tests

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 02-02-PLAN.md — OllamaJudge + three-tier parser + judge tests

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 02-03-PLAN.md — Preflight health checks (Ollama daemon, model availability, HTTP target, judge conflict) + preflight tests

### Phase 3: Scanner + CLI

**Goal**: A user can invoke `llm-scanner` from the terminal and get a complete, bounded, progress-visible scan with a computed risk score
**Depends on**: Phase 2
**Requirements**: ENGINE-01, ENGINE-02, ENGINE-03, ENGINE-04, CLI-01, CLI-02, CLI-03, CLI-04, CLI-05, CLI-06, CLI-07, CLI-08
**Success Criteria** (what must be TRUE):

  1. `llm-scanner --target http://localhost:5000 --target-type url --judge-model llama3.2:3b` runs a full scan and prints results to the terminal with zero unhandled exceptions
  2. `--categories LLM01,LLM07` restricts the scan to only those two categories; `--severity high` skips medium, low, and info payloads
  3. LLM10 payloads are not dispatched unless `--include-dos-tests` is explicitly passed on the command line
  4. A Rich progress bar displays the current attack name, completion percentage, and elapsed time in real time during the scan
  5. The terminal summary shows a risk score 0.0–10.0 computed from the CVSS-inspired weighted severity formula (CRITICAL=4.0, HIGH=2.5, MEDIUM=1.5, LOW=0.5)

**Plans**: 2 plans
Plans:
**Wave 1**

- [x] 03-01-PLAN.md — LLMScanner engine (bounded concurrency, Rich progress, risk score) + scanner tests

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 03-02-PLAN.md — CLI entry point (argparse, all 8 flags, LLM10 opt-in) + CLI tests

### Phase 4: Reports, Tests & Demo

**Goal**: Every output format is correct and safe, the test suite passes green, and a new user can reproduce the full tool end-to-end from the README alone
**Depends on**: Phase 3
**Requirements**: REPORT-01, REPORT-02, REPORT-03, REPORT-04, DEMO-01, DEMO-02, QUAL-01, QUAL-02, QUAL-03
**Success Criteria** (what must be TRUE):

  1. `--format json,md,html` produces three timestamped files in `--output-dir`; the JSON file deserializes back to a valid `ScanReport` with no field loss
  2. HTML report renders payloads containing `<script>alert(1)</script>` as escaped text — the browser shows the literal string, not an alert dialog (Jinja2 `autoescape=True` enforced)
  3. `demo/vulnerable_app.py` starts with `flask run` and responds to `POST /chat` without any external dependencies beyond Flask
  4. `pytest tests/` passes with zero failures covering judge logic, report generation, and payload loader
  5. `ruff check .` reports zero errors including S-series security rules; `README.md` includes architecture diagram, quick-start commands, sample terminal output, and OWASP 2025 mapping table

**Plans**: 2 plans
Plans:
**Wave 1**

- [x] 04-01-PLAN.md — Reporters package (MarkdownReporter, JsonReporter, HtmlReporter + Jinja2 template) + CLI --format wiring + reporter tests

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 04-02-PLAN.md — Demo app (Flask vulnerable chatbot) + pyproject.toml Flask dep + README.md + ruff verification

### Phase 5: Advanced Features

**Goal**: Power users can integrate the scanner into CI/CD pipelines, track vulnerability trends over time, manage false positives, scan multiple targets in one run, and export results in industry-standard SARIF format
**Depends on**: Phase 4
**Requirements**: ADV-01, ADV-02, ADV-03, ADV-04, ADV-05, ADV-06
**Success Criteria** (what must be TRUE):

  1. `--fail-on-score 7.0` exits with code 1 when risk score exceeds the threshold; a ready-made `.github/workflows/llm-scan.yml` is included in the repo
  2. `llm-scanner baseline save` stores a scan result as a named baseline; `llm-scanner baseline compare` reports only new vulnerabilities vs the saved baseline
  3. `reports/index.html` is regenerated after every scan, showing a trend chart of Risk Score across all historical scans in the output directory
  4. `--format sarif` produces a valid SARIF 2.1.0 JSON file parseable by GitHub Security tab and VS Code SARIF Viewer
  5. `suppressions.yaml` entries exclude matching findings from the risk score and mark them "Accepted" in all report formats
  6. `--targets targets.yaml` accepts a multi-target YAML file and produces a side-by-side comparison table across all targets

**Plans**: 5 plans
Plans:
**Wave 1**

- [ ] 05-01-PLAN.md — Extend AttackResult with suppressed/suppression_reason fields + SuppressionLoader module + suppression tests

**Wave 2** *(blocked on Wave 1 completion — 05-02, 05-03, 05-04 run in parallel)*

- [ ] 05-02-PLAN.md — SarifReporter + register in reporters/__init__.py + SARIF tests
- [ ] 05-03-PLAN.md — TrendReporter + index.html.j2 Jinja2 template + trend tests
- [ ] 05-04-PLAN.md — BaselineManager (save/load/diff) + baseline tests

**Wave 3** *(blocked on Wave 2 completion)*

- [ ] 05-05-PLAN.md — CLI integration (--fail-on-score, --targets, --suppressions, baseline subcommands, suppression pipeline, trend regeneration) + GitHub Actions workflow + CLI tests

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 5/5 | Complete    | 2026-06-30 |
| 2. Core Engine | 3/3 | Complete    | 2026-06-30 |
| 3. Scanner + CLI | 2/2 | Complete    | 2026-07-01 |
| 4. Reports, Tests & Demo | 2/2 | Complete    | 2026-07-01 |
| 5. Advanced Features | 0/5 | Pending     | — |
