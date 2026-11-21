import json

from gha_sentinel import main
from gha_sentinel.contexts import env_taint, tainted_refs
from gha_sentinel.model import parse_workflow
from gha_sentinel.report import sarif
from gha_sentinel.rules import scan


def test_bracket_and_index_forms_are_normalised():
    assert tainted_refs("${{ github.event['issue']['title'] }}", set()) == [
        "github.event.issue.title"
    ]
    assert tainted_refs("${{ github.event.commits[0].message }}", set()) == [
        "github.event.commits.*.message"
    ]


def test_trusted_contexts_are_not_flagged():
    text = "${{ github.event.pull_request.number }} ${{ github.sha }} ${{ github.event.pull_request.head.sha }}"
    assert tainted_refs(text, set()) == []


def test_env_taint_propagates_only_through_expansion():
    env = env_taint({"T": "${{ github.event.issue.title }}", "SAFE": "x"})
    assert env == {"T"}
    assert tainted_refs('echo "$T"', env) == []  # shell variable: safe
    assert tainted_refs("echo ${{ env.T }}", env) == ["env.T (from untrusted input)"]


def test_on_key_is_not_parsed_as_boolean():
    wf = parse_workflow("on: [push, issues]\njobs: {}\n")
    assert wf.trigger_names == {"push", "issues"}


def test_line_numbers_point_at_the_step():
    wf = parse_workflow(
        "on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        "      - run: echo ok\n      - run: echo ${{ github.event.issue.body }}\n"
    )
    [f] = scan([wf])
    assert f.line == 8


def test_cli_exit_code_and_sarif(tmp_path, capsys):
    (tmp_path / "w.yml").write_text(
        "on: issues\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        "      - run: echo ${{ github.event.issue.title }}\n"
    )
    assert main([str(tmp_path), "--format", "sarif"]) == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "script-injection"
    (tmp_path / "w.yml").write_text(
        "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ok\n"
    )
    assert main([str(tmp_path)]) == 0


def test_sarif_of_nothing_is_valid():
    assert json.loads(sarif([]))["runs"][0]["results"] == []


RELEASE = "name: Release\non: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo build\n"
CI = "name: CI\non: pull_request\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: echo test\n"
PUBLISH = (
    "on:\n  workflow_run:\n    workflows: [{up}]\n    types: [completed]\npermissions: {{}}\njobs:\n  p:\n"
    "    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n        with:\n"
    "          ref: ${{{{ github.event.workflow_run.head_sha }}}}\n      - run: make publish\n"
)


def test_workflow_run_from_trusted_upstream_is_not_a_pwn_request():
    wfs = [
        parse_workflow(RELEASE, "release.yml"),
        parse_workflow(PUBLISH.format(up="Release"), "publish.yml"),
    ]
    assert [f.rule for f in scan(wfs)] == []


def test_workflow_run_from_pr_upstream_is_a_pwn_request():
    wfs = [
        parse_workflow(CI, "ci.yml"),
        parse_workflow(PUBLISH.format(up="CI"), "publish.yml"),
    ]
    assert [f.rule for f in scan(wfs)] == ["pwn-request"]


def test_unknown_upstream_is_treated_as_untrusted():
    assert [
        f.rule for f in scan([parse_workflow(PUBLISH.format(up="Elsewhere"), "p.yml")])
    ] == ["pwn-request"]
