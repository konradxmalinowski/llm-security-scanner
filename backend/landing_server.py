"""Landing page server for LLM Security Scanner. Serves frontend/ on port 8080."""

import json
import os
import shutil
import socket
import subprocess
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, request, send_from_directory, stream_with_context

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
PROJECT_ROOT = Path(__file__).parent.parent
SCANNER_BIN = PROJECT_ROOT / ".venv" / "bin" / "llm-scanner"
DEFAULT_JUDGE_MODEL = os.environ.get("LLM_SCANNER_JUDGE_MODEL", "llama3.2:3b")
SCAN_TIMEOUT_SECONDS = int(os.environ.get("LLM_SCANNER_TIMEOUT_SECONDS", "300"))

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")


@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/health")
def health():
    return {"status": "ok"}


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


@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(silent=True) or {}

    target = body.get("target", "").strip()
    judge_model = body.get("judge_model", "").strip() or DEFAULT_JUDGE_MODEL

    if not target:
        return {"error": "target is required"}, 400
    if not _is_public_http_url(target):
        return {
            "error": (
                "Hosted scans only accept public http/https URLs. "
                "Use the CI/CD runner for localhost, private networks, VPNs, and staging apps."
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
        "--format", "json,html",
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
            yield f"data: {json.dumps({'done': True, 'returncode': proc.returncode})}\n\n"
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
