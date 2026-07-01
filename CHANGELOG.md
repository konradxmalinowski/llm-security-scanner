# Changelog

Releases are tagged on GitHub (`vX.Y.Z`); this file summarizes what changed in each one. Tagging `vX.Y.Z` (matching the version in `pyproject.toml`) triggers `.github/workflows/release.yml`, which publishes to PyPI via trusted publishing. Until the first release ships, install via `pip install git+https://github.com/konradxmalinowski/llm-security-scanner`.

## Unreleased

- Split the hosted landing page / premium service out into a private repo (`llm-security-scanner-saas`). This repo is now scan-engine-only.
- Added `LICENSE` (MIT), `CONTRIBUTING.md`, issue/PR templates.
- Fixed example CI/CD pipelines (`examples/github/`, `examples/gitlab/`): Docker variants no longer try to build the scanner image from the consumer's own checkout (they had no Dockerfile to build from); GitLab variants no longer ship an environment-specific `LLM_ENDPOINT`/`OLLAMA_HOST` default that silently defeated the "did you configure this?" check; GitLab pipelines now only trigger on merge requests/manual runs instead of every push, matching the GitHub examples.
- Added `.github/workflows/release.yml`: tag-triggered PyPI publish via trusted publishing (OIDC, no stored API token). Docker CI/CD examples now build a minimal `pip install llm-security-scanner` image instead of cloning this repo's full source — requires the first PyPI release to exist (see `docs/FUNCTIONALITY.md` for the one-time pending-publisher setup).
