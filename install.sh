#!/bin/sh
set -eu
cd "$(dirname "$0")"
for tool in gitleaks trufflehog; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    brew install "$tool"
  fi
done
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m spacy download en_core_web_sm
