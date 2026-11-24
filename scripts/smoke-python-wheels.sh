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


# Install the actual built files, never a same-version release from the index.
# The framework integrations require Python 3.10 except for LangChain.
# The SDK and LangChain integration also support Python 3.9.
"$BUILD_PY" - "$PYTHON_BIN" "$DIST_DIR" "$REPO_ROOT" "$TMPDIR" <<'PY'
from email.parser import BytesParser
from pathlib import Path
import platform
import os
import shutil
import subprocess
import sys
from zipfile import ZipFile

from packaging.specifiers import SpecifierSet

python, dist_dir, repo_root, work_dir = sys.argv[1:]
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
elif sys.version_info >= (3, 14):
    expected.discard("cred-crewai")  # CrewAI declares <3.14

wheels = {}
VERSION = None
for wheel in sorted(Path(dist_dir).glob("*.whl")):
    with ZipFile(wheel) as archive:
        metadata_path = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_path))
    if metadata["Name"] == "cred-auth":
        VERSION = metadata["Version"]
    if platform.python_version() in SpecifierSet(metadata["Requires-Python"]):
        wheels[metadata["Name"]] = str(wheel)
assert set(wheels) == expected, f"Unexpected compatible wheels: {set(wheels)} != {expected}"
# Separate consumers prove that no adapter relies on another adapter wheel.
selected = os.environ.get("CRED_WHEEL_ADAPTERS")
if selected:
    wanted = {"cred-" + name for name in selected.split(",")}
    assert wanted <= expected - {"cred-auth"}, f"Unsupported adapter selection: {wanted}"
else:
    wanted = expected - {"cred-auth"}
framework_pin = os.environ.get("CRED_WHEEL_FRAMEWORK_PIN")
assert not framework_pin or len(wanted) == 1, "A framework pin requires one adapter"
for name in ["cred-auth", *sorted(wanted)]:
    consumer = Path(work_dir) / name
    subprocess.run([python, "-m", "venv", str(consumer)], check=True)
    consumer_python = str(consumer / "bin" / "python")
    requirements = [wheels["cred-auth"], "pytest>=7"]
    if name != "cred-auth":
        requirements.append(wheels[name])
        if framework_pin:
            requirements.append(framework_pin)
        if framework_pin == "crewai==0.11.0":
            # Old CrewAI imports an undeclared, removed setuptools API.
            # Bound its old resolver graph for a repeatable lower-bound test;
            # these are test-only pins, not adapter dependency restrictions.
            requirements.extend(["setuptools<81", "langchain==0.1.20",
                                 "langchain-core==0.1.53", "langchain-openai==0.0.2.post1",
                                 "pydantic==2.14.4", "openai==1.109.1"])
        if framework_pin == "openai-agents==0.1.0":
            # The legacy framework's Usage defaults are incompatible with the
            # new required fields in OpenAI 3.x. Exercise its declared minimum.
            requirements.append("openai==1.87.0")
        if framework_pin == "semantic-kernel==1.0.0":
            # Legacy SK imports Pydantic's removed networks.Url and old OpenAI
            # types at import time. This is a lower-bound test profile only.
            requirements.extend(["pydantic==2.7.4", "pydantic-settings==2.2.1",
                                 "openai==1.30.1", "numpy==1.26.4"])
    subprocess.run([consumer_python, "-m", "pip", "install", *requirements], check=True)
    subprocess.run([consumer_python, "-m", "pip", "check"], check=True)
    checks = consumer / "checks"
    checks.mkdir()
    module, attribute = exports[name]
    imports = (
        f"import {module}; from pathlib import Path; "
        f"assert hasattr({module}, {attribute!r}); "
        f"assert Path({module}.__file__).resolve().is_relative_to(Path({str(consumer)!r}).resolve()); "
        "from cred.integration_support import DelegationTokenStore; "
        "from importlib.metadata import version; "
        f"assert version('cred-auth') == {VERSION!r}"
    )
    subprocess.run([consumer_python, "-I", "-c", imports], cwd=checks, check=True)
    env = dict(os.environ, OTEL_SDK_DISABLED="true")
    env.pop("PYTHONPATH", None)
    if name == "cred-auth":
        tests = ["packages/sdk-python/tests/test_integration_support.py"]
    else:
        env["CRED_NATIVE_ADAPTERS"] = name.removeprefix("cred-")
        tests = ["scripts/test_python_native_dispatch.py", "scripts/test_python_integration_support.py"]
    for source in tests:
        shutil.copyfile(Path(repo_root) / source, checks / Path(source).name)
    subprocess.run([consumer_python, "-I", "-m", "pytest", "-q", str(checks)],
                   cwd=checks, env=env, check=True)
    print(f"independent Python {platform.python_version()} wheel native smoke ok: {name}", flush=True)
PY
