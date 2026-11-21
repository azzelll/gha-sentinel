"""Parse GitHub Actions workflow YAML into a small model that keeps line numbers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class LineDict(dict):
    """A dict that remembers the YAML line it started on."""

    line: int = 0


class _Loader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: _Loader, node: yaml.MappingNode) -> LineDict:
    loader.flatten_mapping(node)
    d = LineDict()
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        # YAML 1.1 reads a bare `on:` key as boolean True.
        if key is True and key_node.value == "on":
            key = "on"
        d[key] = loader.construct_object(value_node, deep=True)
    d.line = node.start_mark.line + 1
    return d


_Loader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


@dataclass
class Step:
    index: int
    line: int
    name: str | None
    uses: str | None
    run: str | None
    with_: dict[str, Any]
    env: dict[str, Any]
    if_: str | None

    @property
    def label(self) -> str:
        return self.name or self.uses or f"step {self.index + 1}"


@dataclass
class Job:
    id: str
    line: int
    runs_on: Any
    permissions: Any
    env: dict[str, Any]
    if_: str | None
    environment: Any
    steps: list[Step] = field(default_factory=list)
    uses: str | None = None  # reusable workflow call
    needs: list[str] = field(default_factory=list)


@dataclass
class Workflow:
    path: str
    name: str | None
    triggers: dict[str, Any]
    permissions: Any
    env: dict[str, Any]
    jobs: list[Job]
    source: str

    @property
    def trigger_names(self) -> set[str]:
        return set(self.triggers)


def _triggers(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        return {raw: None}
    if isinstance(raw, list):
        return {str(t): None for t in raw}
    if isinstance(raw, dict):
        return {str(k): v for k, v in raw.items()}
    return {}


def _str(v: Any) -> str | None:
    return None if v is None else str(v)


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


class ParseError(Exception):
    pass


def parse_workflow(text: str, path: str = "<workflow>") -> Workflow:
    try:
        raw = yaml.load(text, Loader=_Loader)  # noqa: S506 - safe loader subclass
    except yaml.YAMLError as e:
        raise ParseError(f"{path}: invalid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ParseError(f"{path}: not a workflow mapping")
    jobs: list[Job] = []
    for job_id, j in _dict(raw.get("jobs")).items():
        if not isinstance(j, dict):
            continue
        job = Job(
            id=str(job_id),
            line=getattr(j, "line", 0),
            runs_on=j.get("runs-on"),
            permissions=j.get("permissions"),
            env=_dict(j.get("env")),
            if_=_str(j.get("if")),
            environment=j.get("environment"),
            uses=_str(j.get("uses")),
            needs=[
                str(n)
                for n in (
                    [j["needs"]]
                    if isinstance(j.get("needs"), str)
                    else j.get("needs") or []
                )
            ],
        )
        for i, s in enumerate(j.get("steps") or []):
            if not isinstance(s, dict):
                continue
            job.steps.append(
                Step(
                    index=i,
                    line=getattr(s, "line", 0),
                    name=_str(s.get("name")),
                    uses=_str(s.get("uses")),
                    run=_str(s.get("run")),
                    with_=_dict(s.get("with")),
                    env=_dict(s.get("env")),
                    if_=_str(s.get("if")),
                )
            )
        jobs.append(job)
    return Workflow(
        path=path,
        name=_str(raw.get("name")),
        triggers=_triggers(raw.get("on")),
        permissions=raw.get("permissions"),
        env=_dict(raw.get("env")),
        jobs=jobs,
        source=text,
    )


def load_dir(root: Path) -> list[Workflow]:
    """Parse every workflow under `<root>/.github/workflows` (or `root` itself)."""
    wf_dir = root / ".github" / "workflows"
    base = wf_dir if wf_dir.is_dir() else root
    out = []
    for p in sorted([*base.glob("*.yml"), *base.glob("*.yaml")]):
        out.append(
            parse_workflow(p.read_text(encoding="utf-8", errors="replace"), str(p))
        )
    return out
