#!/usr/bin/env bash
# Runs every Python package's tests in one environment, to prove they can be
# installed together. Pins come from scripts/python-test-constraints.txt because
# pip's resolver can give up or run for many minutes on these wide framework
# ranges (resolution-too-deep on Python 3.14). CI's per-package jobs run unpinned,
# so a new upstream release still shows up there.
set -euo pipefail

PYTHON_BIN="${PYTHON:-python3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONSTRAINTS="$REPO_ROOT/scripts/python-test-constraints.txt"

if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "test:python needs Python 3.10 or newer, since the framework integrations do. CI tests the SDK alone on 3.9." >&2
  exit 2
fi

# crewai declares Requires-Python <3.14 on every current release, so cred-crewai
# does too. Say so rather than let the run look complete.
CREWAI_DIRS=(packages/integrations/crewai)
if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info < (3, 14) else 1)'; then
  CREWAI_DIRS=()
  echo "SKIPPED cred-crewai: crewai does not support this Python (it declares <3.14). Run under 3.10 to 3.13 to cover it." >&2
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/cred-python-tests.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

"$PYTHON_BIN" -m venv "$TMPDIR/venv"
VENV_PY="$TMPDIR/venv/bin/python"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install --constraint "$CONSTRAINTS" \
  -e "$REPO_ROOT/packages/sdk-python[dev]" \
  -e "$REPO_ROOT/packages/integrations/langchain[dev]" \
  ${CREWAI_DIRS[@]+-e "$REPO_ROOT/packages/integrations/crewai[dev]"} \
  -e "$REPO_ROOT/packages/integrations/openai-agents[dev]" \
  -e "$REPO_ROOT/packages/integrations/autogen[dev]" \
  -e "$REPO_ROOT/packages/integrations/semantic-kernel[dev]" >/dev/null
"$VENV_PY" -m pip check

"$VENV_PY" -m pytest "$REPO_ROOT/packages/sdk-python/tests"

for package_dir in \
  packages/integrations/langchain \
  ${CREWAI_DIRS[@]+"${CREWAI_DIRS[@]}"} \
  packages/integrations/openai-agents \
  packages/integrations/autogen \
  packages/integrations/semantic-kernel
do
  (
    cd "$REPO_ROOT/$package_dir"
    "$VENV_PY" -m pytest tests
  )
done
