"""Relative links and anchors in the documentation must resolve."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCS = [
    ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "CHANGELOG.md", ROOT / "SECURITY.md",
    *sorted((ROOT / "docs").glob("*.md")),
    *sorted(ROOT.glob("sdks/*/README.md")),
    *sorted(ROOT.glob("integrations/*/README.md")),
]


def _anchors(markdown: Path) -> set[str]:
    headings = re.findall(r"^#+\s+(.*)$", markdown.read_text(encoding="utf-8"), re.M)
    return {re.sub(r"[^\w\s-]", "", heading.strip().lower()).replace(" ", "-") for heading in headings}


def _links(markdown: Path) -> list[str]:
    text = re.sub(r"```.*?```", "", markdown.read_text(encoding="utf-8"), flags=re.S)
    return [link for link in re.findall(r"\]\(([^)\s]+)\)", text) if not link.startswith(("http://", "https://", "mailto:"))]


@pytest.mark.parametrize("markdown", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(markdown):
    broken = []
    for link in _links(markdown):
        path, _, anchor = link.partition("#")
        target = (markdown.parent / path).resolve() if path else markdown
        if not target.exists():
            broken.append(link)
        elif anchor and target.suffix == ".md" and anchor not in _anchors(target):
            broken.append(link)
    assert not broken, f"broken links in {markdown.name}: {broken}"
