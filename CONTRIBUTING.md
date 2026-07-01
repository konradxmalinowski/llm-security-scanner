# Contributing

Thanks for considering a contribution to LLM Security Scanner.

## Setup

```bash
uv pip install -e ".[dev]"
```

## Before opening a PR

```bash
uv run pytest
uv run ruff check .
uv run ruff format .
```

- Keep payload YAML files (`payloads/`) matching the existing schema: `id`, `name`, `payload`, `judge_criteria`, `severity`.
- New payloads should map to a specific OWASP LLM Top 10 (2025) category — see `docs/FUNCTIONALITY.md` for the current category list.
- `ruff` runs with `flake8-bandit` (`S` rules) enabled — don't disable these without a clear reason in the PR description (e.g. `yaml.safe_load` and `Environment(autoescape=True)` are enforced project-wide for security reasons).

## Reporting bugs / requesting features

Open a GitHub issue using the provided templates. Include reproduction steps (target type, judge model, relevant flags) for bugs.

## Scope

This repo is the open-source scan engine and CLI only. Hosted/premium features are out of scope here — see `docs/FUNCTIONALITY.md` for what belongs where.
