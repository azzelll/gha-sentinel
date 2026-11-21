"""Detection rules. Each returns findings with a severity and a confidence.

Severity is the impact if exploitable; confidence drops when the workflow has
a guard (fork check, author association, label gate, protected environment)
that an attacker would first have to get past.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .contexts import UNTRUSTED_REF, env_taint, tainted_refs
from .model import Job, Step, Workflow

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Triggers an outsider can fire that run in the base repo with secrets and a
# token that may be able to write.
PRIVILEGED = {
    "pull_request_target",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "workflow_run",
}
# Triggers an outsider can fire, but sandboxed (fork PRs: read-only token, no secrets).
UNPRIVILEGED_EXTERNAL = {
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
}

FIRST_PARTY_OWNERS = {"actions", "github"}
SHA = re.compile(r"^[0-9a-f]{40}$")

EXECUTES_CODE = re.compile(
    r"\b(npm|yarn|pnpm|bun)\s+(i|install|ci|run|test|build|exec)\b"
    r"|\bnpx\b|\bpip3?\s+install\b|\bpython3?\b|\bpoetry\s+(install|run)\b|\buv\s+(sync|run)\b"
    r"|\bmake\b|\bcmake\b|\bgo\s+(build|test|run|generate)\b|\bcargo\s+(build|test|run)\b"
    r"|\bmvn\b|\bgradlew?\b|\bbundle\s+(install|exec)\b|\brake\b|\bcomposer\s+install\b"
    r"|\btox\b|\bpytest\b|\bdotnet\s+(build|test|run)\b|(^|\s)\./[\w./-]+|\bbash\s+[\w./-]+\.sh\b"
    r"|\bsh\s+[\w./-]+\.sh\b|\bpre-commit\b",
    re.M,
)

GUARD = re.compile(
    r"head\.repo\.full_name\s*==\s*github\.repository"
    r"|github\.repository\s*==\s*github\.event\.pull_request\.head\.repo\.full_name"
    r"|head\.repo\.fork\s*(==\s*false|!=\s*true)|!\s*github\.event\.pull_request\.head\.repo\.fork"
    r"|author_association"
    r"|labels\.\*\.name|github\.event\.label\.name"
    r"|github\.(actor|triggering_actor)\s*=="
    r"|github\.event\.(sender|comment\.user)\.login\s*==",
    re.I,
)


@dataclass
class Finding:
    rule: str
    severity: str
    confidence: str
    file: str
    line: int
    job: str
    step: str | None
    message: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _guards(wf: Workflow, job: Job, step: Step | None = None) -> list[str]:
    reasons: list[str] = []
    for cond in (job.if_, step.if_ if step else None):
        if cond and GUARD.search(cond):
            reasons.append(f"condition `{cond.strip()[:80]}`")
    if job.environment:
        reasons.append("protected environment (may require approval)")
    for trig, cfg in wf.triggers.items():
        if (
            isinstance(cfg, dict)
            and cfg.get("types") == ["labeled"]
            and trig == "pull_request_target"
        ):
            reasons.append("only runs when a maintainer adds a label")
    return reasons


def _owner(uses: str) -> str:
    return uses.split("/", 1)[0].lower()


def _is_checkout(step: Step) -> bool:
    return bool(step.uses and step.uses.split("@")[0].lower() == "actions/checkout")


def script_injection(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    privileged = wf.trigger_names & PRIVILEGED
    external = wf.trigger_names & UNPRIVILEGED_EXTERNAL
    for job in wf.jobs:
        tainted_env = env_taint(wf.env, job.env)
        for step in job.steps:
            env = tainted_env | env_taint(step.env)
            sinks: list[tuple[str, list[str]]] = []
            if step.run:
                sinks.append(("run", tainted_refs(step.run, env)))
            if step.uses and step.uses.split("@")[0].lower() == "actions/github-script":
                sinks.append(
                    (
                        "github-script",
                        tainted_refs(str(step.with_.get("script", "")), env),
                    )
                )
            for sink, refs in sinks:
                if not refs:
                    continue
                if privileged:
                    severity = "high"
                elif external:
                    severity = "low"
                else:
                    severity = "info"  # only maintainers can trigger
                guards = _guards(wf, job, step)
                trig = (
                    ", ".join(sorted(privileged or external or wf.trigger_names)) or "?"
                )
                out.append(
                    Finding(
                        rule="script-injection",
                        severity=severity,
                        confidence="low" if guards else "high",
                        file=wf.path,
                        line=step.line,
                        job=job.id,
                        step=step.label,
                        message=f"Untrusted input is expanded into a {sink} script (trigger: {trig}). "
                        "An attacker can inject shell or JavaScript."
                        + (f" Guarded by: {'; '.join(guards)}." if guards else ""),
                        evidence=", ".join(dict.fromkeys(refs)),
                        remediation='Pass the value through an env var and reference it as "$VAR" '
                        "in the script instead of ${{ }} expansion.",
                    )
                )
    return out


def pwn_request(wf: Workflow) -> list[Finding]:
    """A privileged trigger that checks out the PR's code and then runs it.

    Covers pull_request_target, workflow_run and comment-triggered flows such as
    `/test` commands on issue_comment that `gh pr checkout` the PR.
    """
    out: list[Finding] = []
    trig = wf.trigger_names & {"pull_request_target", "workflow_run", "issue_comment"}
    if not trig:
        return out
    for job in wf.jobs:
        checkout: Step | None = None
        for step in job.steps:
            refs = " ".join(str(v) for v in step.with_.values())
            if _is_checkout(step) and UNTRUSTED_REF.search(refs):
                checkout = step
                continue
            if (
                step.run
                and re.search(
                    r"\b(gh\s+pr\s+checkout|git\s+(fetch|checkout|switch))\b", step.run
                )
                and UNTRUSTED_REF.search(step.run)
            ):
                checkout = step
                continue
            if checkout is None:
                continue
            runs_code = bool(step.run and EXECUTES_CODE.search(step.run)) or bool(
                step.uses and step.uses.startswith("./")
            )
            if not runs_code:
                continue
            guards = _guards(wf, job, step)
            secrets = "secrets." in wf.source
            out.append(
                Finding(
                    rule="pwn-request",
                    severity="critical",
                    confidence="low" if guards else "high",
                    file=wf.path,
                    line=step.line,
                    job=job.id,
                    step=step.label,
                    message=f"{'/'.join(sorted(trig))} checks out untrusted PR code (step '{checkout.label}', "
                    f"line {checkout.line}) and then executes it here, with the base repository's "
                    f"{'secrets and ' if secrets else ''}token."
                    + (f" Guarded by: {'; '.join(guards)}." if guards else ""),
                    evidence=(step.run or step.uses or "")
                    .strip()
                    .splitlines()[0][:160],
                    remediation="Use the `pull_request` trigger for building untrusted code, or split into "
                    "an unprivileged build and a privileged workflow that only consumes its artifacts.",
                )
            )
            break  # one finding per job is enough
    return out


def unpinned_action(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    for job in wf.jobs:
        refs = [(s.line, s.uses, s.label) for s in job.steps if s.uses]
        if job.uses:
            refs.append((job.line, job.uses, None))
        for line, uses, label in refs:
            if uses.startswith("./") or uses.startswith("docker://"):
                continue
            if "@" not in uses:
                continue
            name, ref = uses.rsplit("@", 1)
            if _owner(name) in FIRST_PARTY_OWNERS or SHA.match(ref):
                continue
            out.append(
                Finding(
                    rule="unpinned-action",
                    severity="low",
                    confidence="high",
                    file=wf.path,
                    line=line,
                    job=job.id,
                    step=label,
                    message=f"Third-party action `{name}` is referenced by a mutable ref `{ref}`. "
                    "Whoever controls that ref controls this job.",
                    evidence=uses,
                    remediation="Pin to a full commit SHA and keep a comment with the version.",
                )
            )
    return out


def _write_all(p: object) -> bool:
    return p == "write-all"


def excessive_permissions(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    privileged = wf.trigger_names & PRIVILEGED
    for job in wf.jobs:
        if _write_all(wf.permissions) or _write_all(job.permissions):
            out.append(
                Finding(
                    "excessive-permissions",
                    "medium",
                    "high",
                    wf.path,
                    job.line,
                    job.id,
                    None,
                    "The job token has `write-all` permissions.",
                    "permissions: write-all",
                    "Grant only the scopes the job needs, e.g. `contents: read`.",
                )
            )
        elif (
            privileged
            and wf.permissions is None
            and job.permissions is None
            and job.steps
        ):
            out.append(
                Finding(
                    "excessive-permissions",
                    "medium",
                    "medium",
                    wf.path,
                    job.line,
                    job.id,
                    None,
                    f"Job runs on an outsider-triggerable event ({', '.join(sorted(privileged))}) without "
                    "a `permissions` block, so its token gets the repository default, which may be write.",
                    "no permissions block",
                    "Add `permissions: {}` at the top and grant per job.",
                )
            )
    return out


def self_hosted_on_pr(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    if not wf.trigger_names & {"pull_request", "pull_request_target"}:
        return out
    for job in wf.jobs:
        if "self-hosted" in str(job.runs_on):
            out.append(
                Finding(
                    "self-hosted-runner",
                    "medium",
                    "medium" if not _guards(wf, job) else "low",
                    wf.path,
                    job.line,
                    job.id,
                    None,
                    "PRs can run on a self-hosted runner. In a public repository, a fork PR can "
                    "execute code on that machine and persist on it.",
                    f"runs-on: {job.runs_on}",
                    "Use GitHub-hosted runners for PRs, or require approval for fork PR workflows.",
                )
            )
    return out


def artifact_poisoning(wf: Workflow) -> list[Finding]:
    out: list[Finding] = []
    if "workflow_run" not in wf.trigger_names:
        return out
    for job in wf.jobs:
        downloaded = False
        for step in job.steps:
            u = (step.uses or "").split("@")[0].lower()
            if u in {"actions/download-artifact", "dawidd6/action-download-artifact"}:
                downloaded = True
                continue
            if downloaded and step.run and EXECUTES_CODE.search(step.run):
                out.append(
                    Finding(
                        "artifact-poisoning",
                        "medium",
                        "medium",
                        wf.path,
                        step.line,
                        job.id,
                        step.label,
                        "A workflow_run job downloads artifacts produced by a PR build and then executes "
                        "code. If the artifact is attacker-controlled, so is this privileged step.",
                        (step.run or "").strip().splitlines()[0][:160],
                        "Treat artifacts as data: validate them and never execute or source them.",
                    )
                )
                break
    return out


RULES = [
    script_injection,
    pwn_request,
    excessive_permissions,
    self_hosted_on_pr,
    artifact_poisoning,
    unpinned_action,
]


def scan(workflows: list[Workflow]) -> list[Finding]:
    findings = [f for wf in workflows for rule in RULES for f in rule(wf)]
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
