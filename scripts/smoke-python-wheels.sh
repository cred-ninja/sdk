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
# Install the actual built files, never a same-version release from the index.
# The framework integrations require Python 3.10 except for LangChain.
# The SDK and LangChain integration also support Python 3.9.
"$BUILD_PY" - "$VENV_PY" "$DIST_DIR" <<'PY'
from email.parser import BytesParser
from pathlib import Path
import platform
import subprocess
import sys
from zipfile import ZipFile

from packaging.specifiers import SpecifierSet

consumer_python, dist_dir = sys.argv[1:]
exports = {
    "cred-auth": ("cred", "Cred"),
    "cred-langchain": ("cred_langchain", "CredToolkit"),
    "cred-openai-agents": ("cred_openai_agents", "cred_delegate_tool"),
    "cred-crewai": ("cred_crewai", "CredTool"),
    "cred-autogen": ("cred_autogen", "cred_delegate_tool"),
    "cred-semantic-kernel": ("cred_semantic_kernel", "CredPlugin"),
}
expected = set(exports)
if sys.version_info < (3, 10):
    expected = {"cred-auth", "cred-langchain"}

wheels = {}
for wheel in sorted(Path(dist_dir).glob("*.whl")):
    with ZipFile(wheel) as archive:
        metadata_path = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_path))
    if platform.python_version() in SpecifierSet(metadata["Requires-Python"]):
        wheels[metadata["Name"]] = str(wheel)
assert set(wheels) == expected, f"Unexpected compatible wheels: {set(wheels)} != {expected}"
subprocess.run([consumer_python, "-m", "pip", "install", *wheels.values()], check=True)
subprocess.run([consumer_python, "-m", "pip", "check"], check=True)
imports = "\n".join(
    f"import {module}; assert hasattr({module}, {attribute!r})"
    for name, (module, attribute) in exports.items() if name in wheels
)
subprocess.run([consumer_python, "-c", imports], check=True)
print(f"fresh Python {platform.python_version()} wheel install/import smoke ok: {', '.join(sorted(wheels))}")
PY
