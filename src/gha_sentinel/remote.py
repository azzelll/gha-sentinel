"""Fetch a public repository's workflow files without cloning it.

One GitHub API call lists `.github/workflows`; file bodies come from
raw.githubusercontent.com, which does not count against the API quota.
Uses `GITHUB_TOKEN` (or `gh auth token`) when available.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request

from .model import Workflow, ParseError, parse_workflow

API = "https://api.github.com"
UA = "gha-sentinel (static workflow scanner)"


def _token() -> str | None:
    if os.environ.get("GITHUB_TOKEN"):
        return os.environ["GITHUB_TOKEN"]
    try:
        return (
            subprocess.run(
                ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
            ).stdout.strip()
            or None
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _get(
    url: str, token: str | None, accept: str = "application/vnd.github+json"
) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    if token and url.startswith(API):
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - fixed https hosts
        return r.read()


def list_workflow_files(repo: str, token: str | None = None) -> list[dict]:
    try:
        items = json.loads(
            _get(f"{API}/repos/{repo}/contents/.github/workflows", token)
        )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise
    return [
        i
        for i in items
        if i.get("type") == "file" and i["name"].endswith((".yml", ".yaml"))
    ]


def fetch_workflows(
    repo: str, token: str | None = None
) -> tuple[list[Workflow], list[str]]:
    token = token if token is not None else _token()
    workflows, errors = [], []
    for item in list_workflow_files(repo, token):
        text = _get(item["download_url"], None).decode("utf-8", errors="replace")
        try:
            workflows.append(parse_workflow(text, f"{repo}/{item['path']}"))
        except ParseError as e:
            errors.append(str(e))
    return workflows, errors
