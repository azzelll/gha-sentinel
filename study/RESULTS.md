# Measurement study: GitHub Actions in the 1,000 most-starred repositories

- Repositories sampled: **1000** (GitHub search, stars > 1000, sorted by stars).
- Repositories with at least one workflow: **814**; workflows parsed: **10213** (2 files failed to parse).
- Static analysis only. No workflow was run and no repository was contacted beyond reading public files.
- Per-repository results are kept private until maintainers have had time to fix them.

## Triggers outsiders can fire

| Trigger | Repositories |
|---|---|
| `pull_request` | 734 (90.2%) |
| `pull_request_target` | 274 (33.7%) |
| `issue_comment` | 160 (19.7%) |
| `issues` | 216 (26.5%) |
| `workflow_run` | 150 (18.4%) |
| `discussion` | 18 (2.2%) |

## Findings

Repositories with at least one finding of each kind. *High confidence* means no guard was detected.

| Rule | Severity | Repos (any confidence) | Repos (high confidence) |
|---|---|---|---|
| pwn-request | critical | 14 (1.7%) | 2 (0.2%) |
| script-injection | high | 1 (0.1%) | 0 (0.0%) |
| artifact-poisoning | medium | 20 (2.5%) | 0 (0.0%) |
| excessive-permissions | medium | 83 (10.2%) | 11 (1.4%) |
| self-hosted-runner | medium | 20 (2.5%) | 0 (0.0%) |
| script-injection | low | 12 (1.5%) | 3 (0.4%) |
| unpinned-action | low | 441 (54.2%) | 441 (54.2%) |
| script-injection | info | 6 (0.7%) | 5 (0.6%) |

Unpinned third-party action references: **6234** across 441 repositories.

## Manual review: what the first version got wrong

Every critical/high, high-confidence finding was reviewed by hand against the full workflow (and, for `workflow_run`, the workflows that trigger it).

| Scanner | Critical/high, high-confidence findings | Exploitable | Unclear | Not exploitable | Precision (decided) |
|---|---|---|---|---|---|
| v1 | 31 | 1 | 3 | 27 | 4% |
| v2 | 2 | 1 | 1 | 0 | 100% |

v1's false positives fell into six classes, each now fixed and pinned by a benchmark fixture:

1. `workflow_run` whose upstream workflows only run on push, schedule or release (outsiders cannot shape them).
2. Guards on a job listed in `needs:` (author association, user allow-lists); a skipped dependency skips the job.
3. Event gates such as `workflow_run.event == 'schedule'` or `event_name == 'workflow_dispatch'`, and `head_repository.full_name == github.repository`, `pull_request.merged == true`.
4. `git fetch` (and `git merge-base`) treated as a checkout although the working tree never changes.
5. Registry-only installs (`npm install -g`, `pip install black`, `python -m venv`) treated as running PR code.
6. Jobs disabled with `if: false`.

No finding judged exploitable was lost between v1 and v2. Two findings judged *unclear* in v1 (a docs generator and a code formatter run on PR code with secrets or a write token) are no longer reported at high confidence, because the steps that matched only install registry packages; they still deserve a manual look and are tracked privately.
- LLM triage (qwen3:8b, prompt v1) on the 31 v1 findings: agrees with manual review on **3/31**, abstains ('unclear') on 30, says 'exploitable' 1 times (0 correct).
