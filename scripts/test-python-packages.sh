#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/cred-python-tests.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

"$PYTHON_BIN" -m venv "$TMPDIR/venv"
VENV_PY="$TMPDIR/venv/bin/python"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install \
  -e "$REPO_ROOT/packages/sdk-python[dev]" \
  -e "$REPO_ROOT/packages/integrations/langchain[dev]" \
  -e "$REPO_ROOT/packages/integrations/crewai[dev]" \
  -e "$REPO_ROOT/packages/integrations/openai-agents[dev]" \
  -e "$REPO_ROOT/packages/integrations/autogen[dev]" \
  -e "$REPO_ROOT/packages/integrations/semantic-kernel[dev]" >/dev/null

"$VENV_PY" -m pytest "$REPO_ROOT/packages/sdk-python/tests"

for package_dir in \
  packages/integrations/langchain \
  packages/integrations/crewai \
  packages/integrations/openai-agents \
  packages/integrations/autogen \
  packages/integrations/semantic-kernel
do
  (
    cd "$REPO_ROOT/$package_dir"
    "$VENV_PY" -m pytest tests
  )
done
