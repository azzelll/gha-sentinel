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
