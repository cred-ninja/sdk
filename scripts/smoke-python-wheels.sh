#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/cred-python-wheel-smoke.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

DIST_DIR="$TMPDIR/dist"
mkdir -p "$DIST_DIR"

# The Python packages are released in lockstep (scripts/check-release-hygiene.mjs),
# so the SDK's version names every wheel built here.
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$REPO_ROOT/packages/sdk-python/pyproject.toml" | head -1)"
if [ -z "$VERSION" ]; then
  echo "could not read the version from packages/sdk-python/pyproject.toml" >&2
  exit 1
fi

"$PYTHON_BIN" -m venv "$TMPDIR/build-venv"
BUILD_PY="$TMPDIR/build-venv/bin/python"
"$BUILD_PY" -m pip install --upgrade pip build twine >/dev/null

for package_dir in \
  packages/sdk-python \
  packages/integrations/langchain \
  packages/integrations/crewai \
  packages/integrations/openai-agents \
  packages/integrations/autogen \
  packages/integrations/semantic-kernel
do
  "$BUILD_PY" -m build --sdist --wheel --outdir "$DIST_DIR" "$REPO_ROOT/$package_dir" >/dev/null
done

"$BUILD_PY" -m twine check "$DIST_DIR"/* >/dev/null

"$PYTHON_BIN" -m venv "$TMPDIR/venv"
VENV_PY="$TMPDIR/venv/bin/python"
"$VENV_PY" -m pip install --upgrade pip >/dev/null
"$VENV_PY" -m pip install --find-links "$DIST_DIR" \
  "cred-auth==$VERSION" \
  "cred-langchain==$VERSION" \
  "cred-crewai==$VERSION" \
  "cred-openai-agents==$VERSION" \
  "cred-autogen==$VERSION" \
  "cred-semantic-kernel==$VERSION" >/dev/null

"$VENV_PY" - <<'PY'
import cred
import cred_langchain
import cred_crewai
import cred_openai_agents
import cred_autogen
import cred_semantic_kernel

assert hasattr(cred, "Cred")
assert hasattr(cred_langchain, "CredToolkit")
assert hasattr(cred_crewai, "CredTool")
assert hasattr(cred_openai_agents, "cred_delegate_tool")
assert hasattr(cred_autogen, "cred_delegate_tool")
assert hasattr(cred_semantic_kernel, "CredPlugin")
print("fresh Python wheel install/import smoke ok")
PY
