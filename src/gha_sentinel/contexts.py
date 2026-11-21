"""Which `${{ }}` expressions can an outside attacker control?

Based on the contexts GitHub documents as untrusted input: anything a person
without write access can set by opening an issue, PR, comment, discussion or
by naming a branch.
"""

from __future__ import annotations

import re

EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)

# Normalised forms: array indexes become `*`.
_UNTRUSTED = [
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.pull_request\.(title|body)",
    r"github\.event\.pull_request\.head\.(ref|label|repo\.default_branch)",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.discussion\.(title|body)",
    r"github\.event\.pages\.\*\.page_name",
    r"github\.event\.commits\.\*\.(message|author\.(email|name))",
    r"github\.event\.head_commit\.(message|author\.(email|name))",
    r"github\.event\.workflow_run\.(head_branch|display_title|head_commit\.(message|author\.(email|name)))",
    r"github\.event\.workflow_run\.pull_requests\.\*\.head\.ref",
    r"github\.head_ref",
]
UNTRUSTED = re.compile(r"^(" + "|".join(_UNTRUSTED) + r")$")

# References that point at the PR author's code rather than the base branch.
UNTRUSTED_REF = re.compile(
    r"github\.event\.pull_request\.(head\.(sha|ref)|merge_commit_sha)"
    r"|github\.head_ref"
    r"|refs/pull/"
    r"|github\.event\.(number|pull_request\.number|issue\.number)"
    r"|github\.event\.workflow_run\.head_(sha|branch)"
)

_REF = re.compile(
    r"(?:github|env)(?:\.[A-Za-z_][\w-]*|\[\s*['\"]?[\w*-]+['\"]?\s*\]|\.\*)+"
)


def _normalise(ref: str) -> str:
    ref = re.sub(r"\[\s*['\"]?(\d+|\*)['\"]?\s*\]", ".*", ref)
    ref = re.sub(r"\[\s*['\"]([\w-]+)['\"]\s*\]", r".\1", ref)
    return ref


def references(expr: str) -> list[str]:
    return [_normalise(m.group(0)) for m in _REF.finditer(expr)]


def tainted_refs(text: str | None, tainted_env: set[str]) -> list[str]:
    """Untrusted context references used inside `${{ }}` in `text`."""
    if not text:
        return []
    found: list[str] = []
    for m in EXPR.finditer(text):
        inner = m.group(1)
        if re.search(r"toJSON\(\s*github\.event\s*\)", inner, re.I):
            found.append("toJSON(github.event)")
        for ref in references(inner):
            if UNTRUSTED.match(ref):
                found.append(ref)
            elif ref.startswith("env.") and ref[4:] in tainted_env:
                found.append(f"{ref} (from untrusted input)")
    return found


def env_taint(*envs: dict) -> set[str]:
    """Names of env vars whose value is built from untrusted input."""
    names: set[str] = set()
    for env in envs:
        for k, v in env.items():
            if isinstance(v, str) and tainted_refs(v, names):
                names.add(str(k))
    return names
