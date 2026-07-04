FROM python:3.11-slim

ARG SCANNER_VERSION

RUN pip install --no-cache-dir "llm-security-scanner==${SCANNER_VERSION}"

ENTRYPOINT ["llm-scanner"]
