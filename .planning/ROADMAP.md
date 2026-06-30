# Roadmap: LLM Security Scanner

## Overview

The scanner is built bottom-up in four horizontal layers that mirror the data-flow dependency graph from ARCHITECTURE.md. Phase 1 lays the data foundation (Pydantic models + YAML payload library) that every other layer imports. Phase 2 wires in the two I/O subsystems (targets + AI judge) that must exist before any scan loop can run. Phase 3 assembles the scan engine and CLI surface that drives those subsystems. Phase 4 adds the output layer (reporters), a demo target for offline testing, and the test suite that validates the whole stack — leaving the project shippable.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - Pydantic models + YAML payload library (the data layer every other layer imports) (completed 2026-06-27)
- [ ] **Phase 2: Core Engine** - HTTP/Ollama targets + AI Judge + preflight health checks
- [ ] **Phase 3: Scanner + CLI** - Bounded-concurrency scan loop + full argparse CLI surface
- [ ] **Phase 4: Reports, Tests & Demo** - All four reporters + pytest suite + demo app + README

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
- [ ] 02-01-PLAN.md — JudgeResult model + targets/ package (AbstractTarget, HttpTarget, OllamaTarget, TargetFactory) + target tests
- [ ] 02-02-PLAN.md — OllamaJudge + three-tier parser + judge tests
- [ ] 02-03-PLAN.md — Preflight health checks (Ollama daemon, model availability, HTTP target, judge conflict) + preflight tests

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

**Plans**: TBD

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

**Plans**: TBD
**UI hint**: yes

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 5/5 | Complete    | 2026-06-30 |
| 2. Core Engine | 0/3 | Not started | - |
| 3. Scanner + CLI | 0/? | Not started | - |
| 4. Reports, Tests & Demo | 0/? | Not started | - |
