"""Run LLM triage on every critical/high, high-confidence finding from the study.

    uv run python study/triage_run.py

Writes the model's verdict into study/private/labels.json under "llm".
Manual verdicts ("manual") are added by a human reviewer in the same file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "src"))

from gha_sentinel.rules import Finding  # noqa: E402
from gha_sentinel.triage import triage  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--prompt", default="v2", choices=["v1", "v2"])
ap.add_argument(
    "--findings", default="findings_v1.json", help="which scan's findings to triage"
)
args = ap.parse_args()
field = "llm" if args.prompt == "v1" else f"llm_{args.prompt}"

rows = json.loads((ROOT / "private" / args.findings).read_text())
labels_path = ROOT / "private" / "labels.json"
labels = json.loads(labels_path.read_text()) if labels_path.exists() else {}

todo = [
    (r["repo"], f)
    for r in rows
    for f in r["findings"]
    if f["severity"] in {"critical", "high"} and f["confidence"] == "high"
]
print(f"{len(todo)} findings to triage", flush=True)
for i, (repo, f) in enumerate(todo, 1):
    key = f"{f['file']}:{f['line']}:{f['rule']}"
    if field in labels.get(key, {}):
        continue
    wf_file = ROOT / "cache" / repo.replace("/", "__") / Path(f["file"]).name
    verdict = triage(
        Finding(**f), wf_file.read_text(errors="replace"), prompt=args.prompt
    )
    labels.setdefault(key, {"repo": repo, "rule": f["rule"], "severity": f["severity"]})
    labels[key].update(
        {
            field: verdict["verdict"],
            f"{field}_reason": verdict["reason"],
            "model": verdict["model"],
        }
    )
    labels_path.write_text(json.dumps(labels, indent=1))
    print(f"[{i}/{len(todo)}] {verdict['verdict']:16} {f['rule']} {key}", flush=True)
