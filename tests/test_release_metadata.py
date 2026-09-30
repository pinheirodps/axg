"""One version everywhere: packages, changelog and the pinned install instructions in the docs."""

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def test_sdks_share_the_core_version():
    python_sdk = tomllib.loads((ROOT / "sdks/axg-python-sdk/pyproject.toml").read_text(encoding="utf-8"))
    node_sdk = json.loads((ROOT / "sdks/axg-node-sdk/package.json").read_text(encoding="utf-8"))
    assert python_sdk["project"]["version"] == VERSION
    assert node_sdk["version"] == VERSION


def test_changelog_starts_with_the_current_release():
    heading = re.search(r"^## (\S+)", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M).group(1)
    assert heading in (VERSION, "Unreleased")


def test_pinned_install_instructions_use_the_current_release():
    docs = [ROOT / "README.md", *ROOT.glob("docs/*.md"), *ROOT.glob("sdks/*/README.md")]
    stale = []
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        pins = re.findall(r"axg(?:-python-sdk)?@v(\d+\.\d+\.\d+)", text)
        pins += re.findall(r"git clone --branch v(\d+\.\d+\.\d+)", text)
        pins += re.findall(r"ghcr\.io/pinheirodps/axg:(\d+\.\d+\.\d+)", text)
        stale += [f"{doc.name}: {pin}" for pin in pins if pin != VERSION]
    assert not stale, f"docs pin another release than {VERSION}: {stale}"
