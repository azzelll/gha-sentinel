"""gha-sentinel: static security scanner for GitHub Actions workflows."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report
from .model import ParseError, load_dir
from .rules import SEVERITY_ORDER, scan

__all__ = ["main", "scan"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="gha-sentinel", description=__doc__)
    p.add_argument(
        "target",
        help="a local repository / workflow directory, or owner/repo with --remote",
    )
    p.add_argument(
        "--remote", action="store_true", help="fetch workflows of a public GitHub repo"
    )
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    p.add_argument(
        "--no-unpinned", action="store_true", help="skip the unpinned-action rule"
    )
    a = p.parse_args(argv)

    try:
        if a.remote:
            from .remote import fetch_workflows

            workflows, errors = fetch_workflows(a.target)
            for e in errors:
                print(f"warning: {e}", file=sys.stderr)
        else:
            workflows = load_dir(Path(a.target))
    except ParseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    findings = [
        f
        for f in scan(workflows)
        if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[a.min_severity]
        and not (a.no_unpinned and f.rule == "unpinned-action")
    ]
    out = {"text": report.text, "json": report.as_json, "sarif": report.sarif}[
        a.format
    ](findings)
    print(out)
    # Non-zero exit when something high or worse is found, so CI can fail on it.
    return (
        1
        if any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["high"] for f in findings)
        else 0
    )
