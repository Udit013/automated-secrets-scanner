"""The CLI and CI gate: exit codes, baselines, history, and output formats."""

import json

import git
import pytest

from app import cli

KEY = "AKIA" + "V3WBCDEF4GHI7JKM"   # assembled at runtime: no real-format literal in source
KEY_2 = "AKIA" + "Q7RTZXWV2MNB8KLP"


@pytest.fixture()
def repo(tmp_path):
    """A git repo whose key was committed, then deleted from the working tree."""
    r = git.Repo.init(tmp_path)
    actor = git.Actor("t", "t@example.test")
    (tmp_path / "config.py").write_text(f'aws = "{KEY}"\n')
    r.index.add(["config.py"]); r.index.commit("add key", author=actor, committer=actor)
    (tmp_path / "config.py").unlink()
    (tmp_path / "app.py").write_text("x = 1\n")
    r.index.remove(["config.py"]); r.index.add(["app.py"]); r.index.commit("remove key", author=actor, committer=actor)
    return tmp_path


def run(*argv) -> int:
    return cli.main(list(argv))


def test_deleted_key_is_only_found_with_history(repo):
    assert run("scan", str(repo)) == 0
    assert run("scan", str(repo), "--history") == 1


def test_baseline_suppresses_known_credentials_only(repo, tmp_path_factory):
    base = tmp_path_factory.mktemp("b") / "baseline.json"
    assert run("baseline", str(repo), "--history", "-o", str(base)) == 0
    assert KEY not in base.read_text()                       # safe to commit
    assert run("scan", str(repo), "--history", "--baseline", str(base)) == 0
    (repo / "new.py").write_text(f'k = "{KEY_2}"\n')         # a genuinely new leak
    assert run("scan", str(repo), "--history", "--baseline", str(base)) == 1


def test_fail_on_threshold(tmp_path):
    (tmp_path / "a.py").write_text('password = "Xk9#mQ2vLp7w"\n')   # HIGH
    assert run("scan", str(tmp_path), "--fail-on", "critical") == 0
    assert run("scan", str(tmp_path), "--fail-on", "high") == 1
    assert run("scan", str(tmp_path), "--fail-on", "none") == 0


def test_sarif_reports_only_unbaselined(repo, tmp_path_factory):
    out = tmp_path_factory.mktemp("o")
    run("baseline", str(repo), "--history", "-o", str(out / "b.json"))
    (repo / "new.py").write_text(f'k = "{KEY_2}"\n')
    run("scan", str(repo), "--history", "--baseline", str(out / "b.json"), "--format", "sarif", "-o", str(out / "r.sarif"))
    doc = json.loads((out / "r.sarif").read_text())
    assert doc["version"] == "2.1.0" and len(doc["runs"][0]["results"]) == 1


def test_json_lists_credentials_not_lines(tmp_path, capsys):
    (tmp_path / "a.py").write_text(f'k = "{KEY}"\n')
    (tmp_path / "b.yml").write_text(f'key: "{KEY}"\n')
    run("scan", str(tmp_path), "--format", "json")
    creds = json.loads(capsys.readouterr().out)["credentials"]
    assert len(creds) == 1 and creds[0]["baselined"] is False


def test_errors_exit_2(tmp_path):
    assert run("scan", str(tmp_path / "missing")) == 2
    bad = tmp_path / "b.json"; bad.write_text('{"version": 99}')
    assert run("scan", str(tmp_path), "--baseline", str(bad)) == 2


def test_baseline_is_bound_to_its_fingerprint_key(repo, tmp_path_factory, monkeypatch):
    from app.scanner import core
    base = tmp_path_factory.mktemp("k") / "baseline.json"
    try:
        monkeypatch.setenv("FINGERPRINT_KEY", "team-key-one")
        assert run("baseline", str(repo), "--history", "-o", str(base)) == 0
        assert run("scan", str(repo), "--history", "--baseline", str(base)) == 0
        monkeypatch.setenv("FINGERPRINT_KEY", "team-key-two")
        assert run("scan", str(repo), "--history", "--baseline", str(base)) == 2
    finally:
        core.configure_fingerprint_key(core.DEFAULT_FINGERPRINT_KEY)


def test_cli_and_server_agree_on_fingerprints_with_a_shared_key(tmp_path, capsys, monkeypatch):
    from app.scanner import core
    (tmp_path / "a.py").write_text(f'k = "{KEY}"\n')
    try:
        monkeypatch.setenv("FINGERPRINT_KEY", "shared-key")
        run("scan", str(tmp_path), "--format", "json", "--fail-on", "none")
        cli_fp = json.loads(capsys.readouterr().out)["credentials"][0]["fingerprint"]
        core.configure_fingerprint_key(b"shared-key")       # what the server does with the same env
        assert core.scan_text(f'k = "{KEY}"', "a.py")[0].fingerprint == cli_fp
    finally:
        core.configure_fingerprint_key(core.DEFAULT_FINGERPRINT_KEY)


def test_one_run_writes_summary_sarif_and_exit_code(tmp_path, capsys):
    (tmp_path / "a.py").write_text(f'k = "{KEY}"\n')
    report = tmp_path / "out.sarif"
    assert run("scan", str(tmp_path), "--fail-on", "high", "--sarif", str(report)) == 1
    assert "AWS Access Key" in capsys.readouterr().out
    assert len(json.loads(report.read_text())["runs"][0]["results"]) == 1
    assert KEY not in report.read_text()
