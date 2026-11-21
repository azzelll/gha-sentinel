"""Aggregate study/private/findings.json into study/RESULTS.md (no repository names).

uv run python study/analyze.py
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
rows = json.loads((ROOT / "private" / "findings.json").read_text())
labels_path = ROOT / "private" / "labels.json"
labels = json.loads(labels_path.read_text()) if labels_path.exists() else {}

scanned = [r for r in rows if r["workflows"]]
n_all, n = len(rows), len(scanned)
pct = lambda k, d=n: f"{100 * k / d:.1f}%" if d else "–"  # noqa: E731


def repos_with(pred) -> int:
    return sum(any(pred(f) for f in r["findings"]) for r in scanned)


lines = [
    "# Measurement study: GitHub Actions in the 1,000 most-starred repositories",
    "",
    f"- Repositories sampled: **{n_all}** (GitHub search, stars > 1000, sorted by stars).",
    f"- Repositories with at least one workflow: **{n}**; workflows parsed: **{sum(r['workflows'] for r in rows)}**"
    f" ({sum(r['parse_errors'] for r in rows)} files failed to parse).",
    "- Static analysis only. No workflow was run and no repository was contacted beyond reading public files.",
    "- Per-repository results are kept private until maintainers have had time to fix them.",
    "",
    "## Triggers outsiders can fire",
    "",
    "| Trigger | Repositories |",
    "|---|---|",
]
trig = Counter(t for r in scanned for t in r["triggers"])
for t in [
    "pull_request",
    "pull_request_target",
    "issue_comment",
    "issues",
    "workflow_run",
    "discussion",
]:
    lines.append(f"| `{t}` | {trig[t]} ({pct(trig[t])}) |")

lines += [
    "",
    "## Findings",
    "",
    "Repositories with at least one finding of each kind. *High confidence* means no guard was detected.",
    "",
    "| Rule | Severity | Repos (any confidence) | Repos (high confidence) |",
    "|---|---|---|---|",
]
pairs = sorted(
    {(f["rule"], f["severity"]) for r in scanned for f in r["findings"]},
    key=lambda p: (-["info", "low", "medium", "high", "critical"].index(p[1]), p[0]),
)
for rule, sev in pairs:
    a = repos_with(lambda f: f["rule"] == rule and f["severity"] == sev)
    h = repos_with(
        lambda f: f["rule"] == rule
        and f["severity"] == sev
        and f["confidence"] == "high"
    )
    lines.append(f"| {rule} | {sev} | {a} ({pct(a)}) | {h} ({pct(h)}) |")

unpinned = [f for r in scanned for f in r["findings"] if f["rule"] == "unpinned-action"]
lines += [
    "",
    f"Unpinned third-party action references: **{len(unpinned)}** across "
    f"{repos_with(lambda f: f['rule'] == 'unpinned-action')} repositories.",
]

v1_path, v2_path = (
    ROOT / "private" / "findings_v1.json",
    ROOT / "private" / "findings_v2.json",
)
if v1_path.exists() and v2_path.exists():

    def crit(path):
        return [
            (r["repo"], f)
            for r in json.loads(path.read_text())
            for f in r["findings"]
            if f["severity"] in {"critical", "high"} and f["confidence"] == "high"
        ]

    def verdicts(items):
        out = Counter()
        for _, f in items:
            out[
                labels.get(f"{f['file']}:{f['line']}:{f['rule']}", {}).get(
                    "manual", "unreviewed"
                )
            ] += 1
        return out

    c1, c2 = crit(v1_path), crit(v2_path)
    a, b = verdicts(c1), verdicts(c2)
    lines += [
        "",
        "## Manual review: what the first version got wrong",
        "",
        "Every critical/high, high-confidence finding was reviewed by hand against the full workflow "
        "(and, for `workflow_run`, the workflows that trigger it).",
        "",
        "| Scanner | Critical/high, high-confidence findings | Exploitable | Unclear | Not exploitable | Precision (decided) |",
        "|---|---|---|---|---|---|",
    ]
    for name, items, v in (("v1", c1, a), ("v2", c2, b)):
        decided = v["exploitable"] + v["not_exploitable"]
        prec = f"{v['exploitable'] / decided:.0%}" if decided else "–"
        lines.append(
            f"| {name} | {len(items)} | {v['exploitable']} | {v['unclear']} | {v['not_exploitable']} | {prec} |"
        )
    lines += [
        "",
        "v1's false positives fell into six classes, each now fixed and pinned by a benchmark fixture:",
        "",
        "1. `workflow_run` whose upstream workflows only run on push, schedule or release (outsiders cannot shape them).",
        "2. Guards on a job listed in `needs:` (author association, user allow-lists); a skipped dependency skips the job.",
        "3. Event gates such as `workflow_run.event == 'schedule'` or `event_name == 'workflow_dispatch'`, and "
        "`head_repository.full_name == github.repository`, `pull_request.merged == true`.",
        "4. `git fetch` (and `git merge-base`) treated as a checkout although the working tree never changes.",
        "5. Registry-only installs (`npm install -g`, `pip install black`, `python -m venv`) treated as running PR code.",
        "6. Jobs disabled with `if: false`.",
        "",
        "No finding judged exploitable was lost between v1 and v2. Two findings judged *unclear* in v1 "
        "(a docs generator and a code formatter run on PR code with secrets or a write token) are no longer "
        "reported at high confidence, because the steps that matched only install registry packages; "
        "they still deserve a manual look and are tracked privately.",
    ]
    triaged = [
        v
        for v in labels.values()
        if v.get("manual") in {"exploitable", "not_exploitable", "unclear"}
    ]
    for field, title in (("llm", "prompt v1"), ("llm_v2", "prompt v2")):
        got = [v for v in triaged if field in v]
        if not got:
            continue
        agree = sum(v[field] == v["manual"] for v in got)
        abstain = sum(v[field] == "unclear" for v in got)
        pos = [v for v in got if v[field] == "exploitable"]
        tp = sum(v["manual"] == "exploitable" for v in pos)
        lines.append(
            f"- LLM triage ({got[0].get('model', 'local model')}, {title}) on the {len(got)} v1 findings: "
            f"agrees with manual review on **{agree}/{len(got)}**, abstains ('unclear') on {abstain}, "
            f"says 'exploitable' {len(pos)} times ({tp} correct)."
        )
    if any("llm_v2" in v for v in triaged):
        lines.append(
            "- Caveat: prompt v2 was written after reading these findings, so its score on them is optimistic. "
            "It is reported to show what a checklist prompt changes, not as a held-out result."
        )

(ROOT / "RESULTS.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
