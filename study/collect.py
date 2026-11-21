"""Measurement study: scan the workflows of the N most-starred public repositories.

    uv run python study/collect.py --top 1000

Reads public workflow files only (static analysis, nothing is executed or
contacted beyond GitHub's read APIs). Per-repository findings go to
study/private/ (git-ignored) because publishing unfixed vulnerabilities would
put those projects at risk; study/RESULTS.md holds aggregate numbers only.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "src"))

from gha_sentinel.model import ParseError, parse_workflow  # noqa: E402
from gha_sentinel.remote import API, _get, _token, list_workflow_files  # noqa: E402
from gha_sentinel.rules import scan  # noqa: E402

CACHE = ROOT / "cache"
PRIVATE = ROOT / "private"


def top_repos(n: int, token: str | None) -> list[dict]:
    repos: list[dict] = []
    for page in range(1, n // 100 + 2):
        if len(repos) >= n:
            break
        url = f"{API}/search/repositories?q=stars:%3E1000&sort=stars&order=desc&per_page=100&page={page}"
        data = json.loads(_get(url, token))
        repos += [
            {
                "full_name": r["full_name"],
                "stars": r["stargazers_count"],
                "archived": r["archived"],
            }
            for r in data["items"]
        ]
        time.sleep(2.5)  # search API: 30 requests per minute
    return repos[:n]


def fetch_repo(repo: str, token: str | None) -> list[tuple[str, str]]:
    """Return [(path, text)], cached on disk so reruns are free."""
    d = CACHE / repo.replace("/", "__")
    marker = d / ".done"
    if marker.exists():
        return [
            (f"{repo}/.github/workflows/{p.name}", p.read_text(errors="replace"))
            for p in sorted(d.glob("*.y*ml"))
        ]
    d.mkdir(parents=True, exist_ok=True)
    files = []
    for attempt in range(3):
        try:
            items = list_workflow_files(repo, token)
            break
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < 2:
                time.sleep(30)
                continue
            raise
    for item in items:
        text = _get(item["download_url"], None).decode("utf-8", errors="replace")
        (d / item["name"]).write_text(text)
        files.append((f"{repo}/{item['path']}", text))
    marker.write_text("")
    return files


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=1000)
    a = ap.parse_args()
    token = _token()
    CACHE.mkdir(exist_ok=True)
    PRIVATE.mkdir(exist_ok=True)
    repos_file = CACHE / f"top{a.top}.json"
    if repos_file.exists():
        repos = json.loads(repos_file.read_text())
    else:
        repos = top_repos(a.top, token)
        repos_file.write_text(json.dumps(repos))
    print(f"{len(repos)} repositories", flush=True)

    def work(r: dict):
        try:
            return r, fetch_repo(r["full_name"], token), None
        except Exception as e:  # noqa: BLE001 - record and continue
            return r, [], repr(e)[:200]

    rows, errors = [], []
    with ThreadPoolExecutor(max_workers=6) as pool:
        for i, (r, files, err) in enumerate(pool.map(work, repos), 1):
            if err:
                errors.append((r["full_name"], err))
            workflows, parse_errors = [], 0
            for path, text in files:
                try:
                    workflows.append(parse_workflow(text, path))
                except ParseError:
                    parse_errors += 1
            findings = scan(workflows)
            rows.append(
                {
                    "repo": r["full_name"],
                    "stars": r["stars"],
                    "archived": r["archived"],
                    "workflows": len(workflows),
                    "parse_errors": parse_errors,
                    "triggers": sorted({t for w in workflows for t in w.trigger_names}),
                    "findings": [f.to_dict() for f in findings],
                }
            )
            if i % 50 == 0:
                print(f"[{i}/{len(repos)}] scanned", flush=True)
    (PRIVATE / "findings.json").write_text(json.dumps(rows, indent=1))
    (PRIVATE / "errors.json").write_text(json.dumps(errors, indent=1))
    print(f"done: {len(rows)} repos, {len(errors)} fetch errors", flush=True)
    print(
        Counter(
            f["rule"] + ":" + f["severity"] for r in rows for f in r["findings"]
        ).most_common()
    )


if __name__ == "__main__":
    main()
