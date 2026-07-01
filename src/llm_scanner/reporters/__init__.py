from __future__ import annotations

from llm_scanner.reporters.html import HtmlReporter
from llm_scanner.reporters.json_reporter import JsonReporter
from llm_scanner.reporters.markdown import MarkdownReporter

__all__ = ["HtmlReporter", "JsonReporter", "MarkdownReporter", "get_file_reporter"]

_REPORTER_FACTORIES: dict[str, type] = {
    "md": MarkdownReporter,
    "json": JsonReporter,
    "html": HtmlReporter,
}


def get_file_reporter(fmt: str) -> MarkdownReporter | JsonReporter | HtmlReporter:
    """Return a file reporter for the given format string (md | json | html).

    Raises ValueError for unknown formats.
    """
    if fmt not in _REPORTER_FACTORIES:
        raise ValueError(
            f"Unknown report format: {fmt!r}. Choose from: md, json, html"
        )
    return _REPORTER_FACTORIES[fmt]()
