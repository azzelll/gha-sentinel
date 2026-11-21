"""Optional LLM triage: ask a local model whether a finding is really exploitable.

The scanner is deliberately over-inclusive; triage reads the whole workflow
and the finding, and returns exploitable / not_exploitable / unclear with a
reason. Uses Ollama's /api/chat with a JSON schema, so no data leaves the
machine. Its accuracy is measured against manual review in study/.
"""

from __future__ import annotations

import json
import os
import urllib.request

from .rules import Finding

SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["exploitable", "not_exploitable", "unclear"],
        },
        "reason": {"type": "string"},
    },
    "required": ["verdict", "reason"],
}

PROMPT_V1 = """You are a GitHub Actions security reviewer.
A static scanner reported the finding below. Decide whether an outside attacker
(no write access to the repository) could actually exploit it.

Consider: which events trigger the workflow and whether outsiders can fire them;
`if:` conditions, label gates, author_association checks and protected
environments; whether the untrusted value reaches a shell or script; whether
checked-out PR code is executed; and what the token and secrets could do.
Answer "unclear" if it depends on repository settings you cannot see.

Finding: {rule} ({severity}) in job `{job}`{step}
Scanner message: {message}
Evidence: {evidence}

Workflow ({path}):
```yaml
{yaml}
```"""

# v2: v1 abstained ("unclear") on 30/31 study findings. v2 walks the model
# through explicit checks and only allows "unclear" when it can name the
# specific repository setting the answer depends on.
PROMPT_V2 = """You are a GitHub Actions security reviewer deciding if a static-analysis
finding is exploitable by an OUTSIDE attacker (any GitHub user, no write access).

Answer each check in your reason, briefly:
1. Trigger: can an outsider fire this workflow (open a PR/issue/comment)? If it only
   runs on push, schedule, release, workflow_dispatch, or a workflow_run whose
   upstream only runs on those, the answer is not_exploitable.
2. Gates: is the job or step gated by an `if:` an outsider cannot satisfy (author
   association, actor/login == someone, maintainer label, head repo == this repo,
   merged == true, event_name == push/schedule/dispatch), or by a job in `needs:`
   with such a gate, or by `if: false`? If so: not_exploitable.
3. Sink: does attacker-controlled text reach a shell/script, or does attacker code
   (from the PR head) actually execute (install, build, test, local action)? A bare
   `git fetch`, reading files as data, or installing fixed packages from a registry
   is not execution. If nothing executes: not_exploitable.
4. If 1-3 all point to exploitable: exploitable.

Use "unclear" ONLY if the answer depends on a repository setting you can name
(e.g. "depends on whether CODEOWNERS auto-requests reviews"). Say which.

Finding: {rule} ({severity}) in job `{job}`{step}
Scanner message: {message}
Evidence: {evidence}

Workflow ({path}):
```yaml
{yaml}
```"""

PROMPTS = {"v1": PROMPT_V1, "v2": PROMPT_V2}


def triage(
    finding: Finding,
    workflow_source: str,
    model: str | None = None,
    url: str | None = None,
    prompt: str = "v2",
) -> dict:
    model = model or os.environ.get("TRIAGE_MODEL", "qwen3:8b")
    url = url or os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
    body = {
        "model": model,
        "stream": False,
        "think": False,
        "format": SCHEMA,
        "options": {"temperature": 0, "seed": 7, "num_ctx": 8192},
        "messages": [
            {
                "role": "user",
                "content": PROMPTS[prompt].format(
                    rule=finding.rule,
                    severity=finding.severity,
                    job=finding.job,
                    step=f", step `{finding.step}`" if finding.step else "",
                    message=finding.message,
                    evidence=finding.evidence,
                    path=finding.file,
                    yaml=workflow_source[:6000],
                ),
            }
        ],
    }
    req = urllib.request.Request(
        f"{url}/api/chat",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=300) as r:  # noqa: S310 - local Ollama
        content = json.loads(r.read())["message"]["content"]
    try:
        out = json.loads(content)
        if out.get("verdict") in {"exploitable", "not_exploitable", "unclear"}:
            return {
                "verdict": out["verdict"],
                "reason": str(out.get("reason", ""))[:800],
                "model": model,
                "prompt": prompt,
            }
    except json.JSONDecodeError:
        pass
    return {
        "verdict": "unclear",
        "reason": "model returned invalid output",
        "model": model,
        "prompt": prompt,
    }
