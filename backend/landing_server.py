"""Landing page server for LLM Security Scanner. Serves frontend/ on port 8080."""

import json
import os
import shutil
import socket
import subprocess
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, abort, request, send_file, send_from_directory, stream_with_context

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
PROJECT_ROOT = Path(__file__).parent.parent
SCANNER_BIN = PROJECT_ROOT / ".venv" / "bin" / "llm-scanner"
REPORTS_DIR = PROJECT_ROOT / "reports"
DEFAULT_JUDGE_MODEL = os.environ.get("LLM_SCANNER_JUDGE_MODEL", "llama3.2:3b")
SCAN_TIMEOUT_SECONDS = int(os.environ.get("LLM_SCANNER_TIMEOUT_SECONDS", "300"))

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/reports/<scan_id>/<filename>")
def report_file(scan_id: str, filename: str):
    scan_dir = (REPORTS_DIR / scan_id).resolve()
    try:
        scan_dir.relative_to(REPORTS_DIR.resolve())
    except ValueError:
        abort(404)

    path = (scan_dir / filename).resolve()
    try:
        path.relative_to(scan_dir)
    except ValueError:
        abort(404)
    if not path.is_file():
        abort(404)

    as_attachment = path.suffix.lower() != ".html"
    return send_file(path, as_attachment=as_attachment)


def _scanner_bin() -> str | None:
    """Return the installed scanner executable path."""
    if SCANNER_BIN.exists():
        return str(SCANNER_BIN)
    return shutil.which("llm-scanner")


def _host_resolves_to_public_ip(hostname: str) -> bool:
    """Resolve hostname and reject loopback/private/link-local targets."""
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False

    for entry in addresses:
        raw_ip = entry[4][0]
        try:
            ip = ip_address(raw_ip)
        except ValueError:
            return False
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
    return bool(addresses)


def _is_public_http_url(value: str) -> bool:
    """Allow only public HTTP(S) URLs for hosted scans."""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False

    hostname = parsed.hostname.strip().lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return False

    try:
        ip = ip_address(hostname)
    except ValueError:
        return _host_resolves_to_public_ip(hostname)

    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _normalize_target_url(value: str) -> str:
    """Accept bare host:port inputs from the form and default them to http://."""
    raw = value.strip()
    if "://" not in raw and raw:
        return f"http://{raw}"
    return raw


def _build_report_links(scan_dir: Path) -> dict[str, str]:
    filenames = {
        "html": "report.html",
        "json": "report.json",
        "markdown": "report.md",
        "text": "report.txt",
    }
    links: dict[str, str] = {}
    for key, filename in filenames.items():
        if (scan_dir / filename).is_file():
            links[key] = f"/reports/{scan_dir.name}/{filename}"
    return links


@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(silent=True) or {}

    target = _normalize_target_url(body.get("target", ""))
    judge_model = body.get("judge_model", "").strip() or DEFAULT_JUDGE_MODEL

    if not target:
        return {"error": "target is required"}, 400
    parsed_target = urlparse(target)
    if parsed_target.scheme not in {"http", "https"} or not parsed_target.hostname:
        return {
            "error": (
                "target must be a valid http/https URL, for example "
                "'https://chat.example.com/api/chat' or 'https://app.yourcompany.com/chat'."
            )
        }, 400
    if not _is_public_http_url(target):
        return {
            "error": (
                "Hosted scans only accept public http/https URLs. "
                "Use CLI or CI/CD for localhost, Docker, VPN, and other internal targets."
            )
        }, 400
    if not judge_model:
        return {"error": "judge_model is required"}, 400

    scanner_bin = _scanner_bin()
    if scanner_bin is None:
        return {
            "error": (
                f"Scanner binary not found at {SCANNER_BIN} or PATH. "
                "Run 'uv pip install -e .' to install it."
            )
        }, 500

    cmd = [
        scanner_bin,
        "--target", target,
        "--target-type", "url",
        "--judge-model", judge_model,
        "--format", "md,json,html,txt",
        "--output-dir", "reports",
    ]

    api_key = body.get("api_key", "").strip()
    if api_key:
        cmd += ["--api-key", api_key]

    severity = body.get("severity", "").strip()
    if severity:
        cmd += ["--severity", severity]

    categories = body.get("categories", "").strip()
    if categories:
        cmd += ["--categories", categories]

    if body.get("include_dos_tests") is True:
        cmd.append("--include-dos-tests")

    def generate():
        proc = None
        try:
            env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0", "TERM": "dumb"}
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                cwd=str(PROJECT_ROOT),
            )
            for line in proc.stdout:
                yield f"data: {json.dumps({'line': line.rstrip()})}\n\n"
            proc.wait(timeout=SCAN_TIMEOUT_SECONDS)
            report_dirs = [p for p in REPORTS_DIR.iterdir() if p.is_dir()] if REPORTS_DIR.exists() else []
            payload = {"done": True, "returncode": proc.returncode}
            if report_dirs:
                latest_scan = max(report_dirs, key=lambda p: p.stat().st_mtime)
                payload["scan_id"] = latest_scan.name
                payload["reports"] = _build_report_links(latest_scan)
            yield f"data: {json.dumps(payload)}\n\n"
        except subprocess.TimeoutExpired:
            if proc is not None:
                proc.kill()
            yield f"data: {json.dumps({'error': f'Scan timed out after {SCAN_TIMEOUT_SECONDS} seconds'})}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return Response(stream_with_context(generate()), headers=headers)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)  # noqa: S104
