"""Print the context a reviewer needs for each critical/high finding (local only).

For workflow_run findings it also resolves which workflows trigger this one
(by `name:` in the same repository) and whether those run on fork PRs, since
only then can an outsider influence the triggering run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "src"))
import yaml  # noqa: E402

from gha_sentinel.model import parse_workflow  # noqa: E402

rows = json.loads((ROOT / "private" / "findings.json").read_text())
only = set(sys.argv[1:])
n = 0
for r in rows:
    if not any(
        f["severity"] in {"critical", "high"} and f["confidence"] == "high"
        for f in r["findings"]
    ):
        continue
    cache = ROOT / "cache" / r["repo"].replace("/", "__")
    names = {}
    for p in cache.glob("*.y*ml"):
        try:
            raw = yaml.safe_load(p.read_text(errors="replace")) or {}
            wf = parse_workflow(p.read_text(errors="replace"), p.name)
            names[str(raw.get("name", p.stem))] = (p.name, sorted(wf.trigger_names))
        except Exception:  # noqa: BLE001
            pass
    for f in r["findings"]:
        if f["severity"] not in {"critical", "high"} or f["confidence"] != "high":
            continue
        n += 1
        if only and str(n) not in only:
            continue
        src = (cache / Path(f["file"]).name).read_text(errors="replace")
        wf = parse_workflow(src, f["file"])
        print(
            f"\n===== #{n} {f['rule']} {r['repo']} {Path(f['file']).name} job={f['job']} line={f['line']}"
        )
        print("triggers:", json.dumps(wf.triggers, default=str)[:300])
        wr = wf.triggers.get("workflow_run")
        if isinstance(wr, dict):
            for w in wr.get("workflows") or []:
                print(f"  upstream '{w}':", names.get(str(w), "NOT FOUND in repo"))
        job = next(j for j in wf.jobs if j.id == f["job"])
        print(
            "job.if:",
            job.if_,
            "| environment:",
            job.environment,
            "| permissions:",
            job.permissions or wf.permissions,
        )
        for s in job.steps:
            mark = ">>" if s.line == f["line"] else "  "
            body = (s.run or "").strip().replace("\n", " ⏎ ")[:220]
            print(
                f"{mark} L{s.line} if={s.if_!r} uses={s.uses} with={json.dumps(s.with_, default=str)[:160]} run={body}"
            )
