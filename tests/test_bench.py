"""Every labeled benchmark workflow must produce exactly its expected findings."""

import json
from pathlib import Path

import pytest

from gha_sentinel.model import parse_workflow
from gha_sentinel.rules import scan

BENCH = Path(__file__).resolve().parent.parent / "bench"
EXPECTED = {
    k: v
    for k, v in json.loads((BENCH / "expected.json").read_text()).items()
    if not k.startswith("_")
}


def found(name: str) -> list[list[str]]:
    wf = parse_workflow((BENCH / "workflows" / name).read_text(), name)
    return sorted([f.rule, f.severity, f.confidence] for f in scan([wf]))


def test_every_fixture_is_labeled():
    assert sorted(EXPECTED) == sorted(
        p.name for p in (BENCH / "workflows").glob("*.yml")
    )


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture(name):
    assert found(name) == sorted(EXPECTED[name])
