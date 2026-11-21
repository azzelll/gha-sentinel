# gha-sentinel

**Static security scanner for GitHub Actions workflows, plus a measurement study of the 1,000 most-starred repositories.**

CI/CD is supply chain. A workflow that expands an issue title into a shell script, or that checks out a fork's pull request and runs `npm install` with the base repository's secrets, lets anyone with a GitHub account run code inside your project. gha-sentinel finds those patterns statically, explains why they are exploitable, and says how to fix them.

## Results at a glance

Scanned the workflows of the **1,000 most-starred GitHub repositories** (814 have workflows, 10,213 workflow files). Full write-up: [`study/RESULTS.md`](study/RESULTS.md).

- **Every critical/high finding was reviewed by hand.** The first version reported 31 high-confidence critical/high findings; only **1** was exploitable by an outsider (precision 4%). The review surfaced **six false-positive classes** (trusted `workflow_run` upstreams, guards inherited through `needs:`, event gates, `git fetch` mistaken for checkout, registry-only installs, disabled jobs). Fixing them cut the list to **2** findings (1 exploitable, 1 depending on repository settings) **without losing the real one**. Each fix is pinned by a benchmark fixture.
- **1 confirmed pwn request**: `pull_request_target` checks out the PR and runs `pip install -e .` with the repository token. It is being reported privately; the repository is not named and no other detail is given until it is fixed.
- **54% of repositories** reference third-party actions by a mutable tag (6,234 references), and 10% run outsider-triggerable workflows with excessive token permissions.
- **LLM triage was not safe as a filter.** A local 8B model (qwen3:8b) abstained on 30 of 31 findings with a plain prompt. A checklist prompt raised agreement with manual review to 22/31, but every one of its 6 "exploitable" verdicts was wrong and it dismissed the one real vulnerability, reading `pip install --upgrade pip` and missing the `pip install -e .` below it. Deterministic rules informed by manual review did far better.


## What it detects

| Rule | Severity | Pattern |
|---|---|---|
| `pwn-request` | critical | `pull_request_target`, `workflow_run` or a `/command` on `issue_comment` checks out the PR author's code and then **executes it** (install, build, test, local action) with the base repo's token and secrets |
| `script-injection` | high / low / info | Attacker-controlled context (issue/PR title and body, comment body, branch name, commit message, …) expanded with `${{ }}` into a `run:` script or `actions/github-script`. Severity depends on whether outsiders can trigger the workflow with privileges |
| `excessive-permissions` | medium | `write-all`, or an outsider-triggerable privileged workflow with no `permissions` block |
| `self-hosted-runner` | medium | PRs can run on a self-hosted runner |
| `artifact-poisoning` | medium | A `workflow_run` job downloads artifacts from a PR build and then executes code |
| `unpinned-action` | low | Third-party action referenced by a mutable tag or branch instead of a commit SHA |

**Two things that cut false positives**

- **Taint through `env`.** Passing untrusted input through an env var and reading it as `"$VAR"` is the recommended fix and is *not* flagged; re-expanding it as `${{ env.VAR }}` is. Bracket forms (`github.event['issue']['title']`), array indexes and `toJSON(github.event)` are normalised.
- **Guards lower confidence, not severity.** A finding behind `head.repo.full_name == github.repository`, an `author_association` check, a maintainer-applied label, or a protected `environment` is still reported, with `confidence: low` and the guard named, so you can verify the guard instead of guessing.

## Use it

```bash
uv tool install git+https://github.com/azzelll/gha-sentinel
gha-sentinel .                                # scan .github/workflows of the current repo
gha-sentinel owner/repo --remote              # scan a public repo without cloning
gha-sentinel . --format sarif > results.sarif # upload to GitHub code scanning
gha-sentinel . --min-severity high --no-unpinned
```

Exit code is `1` when anything high or critical is found, so it can gate CI:

```yaml
- run: uvx --from git+https://github.com/azzelll/gha-sentinel gha-sentinel . --min-severity high
```

### Optional: LLM triage

`gha_sentinel.triage` asks a **local** model (Ollama, nothing leaves the machine) to read the whole workflow and decide whether a finding is exploitable by an outsider. Its agreement with manual review is measured in the study rather than assumed.

## Benchmark

`bench/` holds 31 labeled workflows: vulnerable ones, their safe rewrites, guarded variants and traps (trusted contexts such as `head.sha` or `pull_request.number`, `workflow_dispatch` inputs, a PR checkout that is only diffed and never executed). Labels were written from GitHub Actions semantics, not from scanner output. `pytest` requires the scanner to reproduce every label exactly.

Writing the benchmark found a real gap: the first version missed comment-triggered "`/test`" flows (`issue_comment` → `gh pr checkout` → `make test`). Seven more fixtures come from the false-positive classes found by manually reviewing the study's findings, so those mistakes cannot quietly return.

## Measurement study

```bash
uv run python study/collect.py --top 1000   # fetch + scan (cached; ~1 API call per repo)
uv run python study/triage_run.py           # LLM triage of critical/high findings
uv run python study/analyze.py              # aggregate → study/RESULTS.md
```

Only public workflow files are read; nothing is executed. **Per-repository findings stay in `study/private/` (git-ignored)** and are reported to maintainers through private vulnerability reporting before anything specific is published.

## Limitations

- Static and intra-workflow: composite actions, reusable workflows called from elsewhere, and step outputs are not followed.
- Repository settings are invisible: "require approval for fork PR workflows", default token permissions and environment protection rules can make a finding unexploitable (or worse).
- The `EXECUTES_CODE` heuristic decides whether a step runs checked-out code; unusual build tools may be missed.
- Prior art worth knowing: [zizmor](https://github.com/zizmorcore/zizmor), [poutine](https://github.com/boostsecurityio/poutine), [actionlint](https://github.com/rhysd/actionlint) and GitHub Security Lab's work on [pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/). gha-sentinel's angle is env-taint, explicit guard reporting and the measurement study; a head-to-head comparison with zizmor on the benchmark is future work.

## Development

```bash
uv sync
uv run pytest
uv run ruff check src tests
```

MIT licensed.
