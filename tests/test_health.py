import json

import pytest

from zkat import health


def test_run_health_checks_reports_core_checks():
    checks = health.run_health_checks(nmap_binary="definitely-not-real-nmap")
    by_name = {check.name: check for check in checks}

    assert by_name["python"].status == "ok"
    assert by_name["required-modules"].status == "ok"
    assert by_name["schema"].status == "ok"
    assert by_name["nmap"].status == "warn"


def test_health_cli_json_output(capsys):
    health.main(["--nmap-binary", "definitely-not-real-nmap", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert any(check["name"] == "schema" and check["status"] == "ok" for check in payload)


def test_health_cli_exits_nonzero_on_failure(monkeypatch):
    monkeypatch.setattr(
        health,
        "run_health_checks",
        lambda **kwargs: [health.HealthCheck("forced", "fail", "forced failure")],
    )

    with pytest.raises(SystemExit) as excinfo:
        health.main([])

    assert excinfo.value.code == 1
