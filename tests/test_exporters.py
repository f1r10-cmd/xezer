"""Bounty-ready hesabat ixracı (Faza 5) testləri.

Yoxlanılan prinsiplər:
  * Hər tapıntı üçün başlıq, severity (CVSS-xəritələnmiş), CWE, URL, reproduksiya
    (curl), sübut, remediasiya və confidence verilir.
  * `rejected` və `min_severity`-dən aşağı tapıntılar ixrac olunmur.
  * Secret-lər ixracda maskalanır (redaction).
  * Yalnız lokal fayl yazılır — xarici şəbəkə YOXDUR.
"""
from __future__ import annotations

import json

from qbh.report import exporters


def _finding(fid, *, module="bypass", severity="high", status="confirmed",
             title="Finding", desc="desc", evidence="ev", curl="curl -sk x"):
    return {"id": fid, "host_id": 1, "module": module, "severity": severity,
            "status": status, "title": title, "description": desc,
            "evidence": evidence, "curl_repro": curl, "confidence": 0.9,
            "source": f"{module}:x"}


HOSTS = {1: {"subdomain": "app.example.com"}}


class TestRemediation:
    def test_module_specific(self):
        assert "avtorizasiya" in exporters.remediation_for(
            {"module": "bypass"}).lower()
        assert "yeniləyin" in exporters.remediation_for(
            {"module": "cve-intel"}).lower()

    def test_generic_fallback(self):
        text = exporters.remediation_for({"module": "unknown"})
        assert "minimum imtiyaz" in text.lower()


class TestHackerOneReports:
    def test_shape(self):
        f = _finding(1)
        reports = exporters.hackerone_reports([f], HOSTS, {1: [
            {"kind": "http_response", "content": "HTTP 200"}]})
        assert len(reports) == 1
        attrs = reports[0]["data"]["attributes"]
        assert reports[0]["data"]["type"] == "report"
        assert attrs["title"] == "Finding"
        assert attrs["severity_rating"] == "high"
        assert attrs["cvss_score"] == exporters.CVSS_HINT["high"]
        assert attrs["weakness"] == "CWE-863"
        assert "Reproduksiya" in attrs["vulnerability_information"]
        assert "HTTP 200" in attrs["vulnerability_information"]
        assert attrs["structured_scope"]["asset_identifier"] == "app.example.com"

    def test_severity_mapping(self):
        for sev, rating in exporters.H1_SEVERITY.items():
            reports = exporters.hackerone_reports(
                [_finding(1, severity=sev)], HOSTS, {})
            assert reports[0]["data"]["attributes"]["severity_rating"] == rating

    def test_secret_redacted(self):
        f = _finding(1, desc="token found: password=hunter2xyz")
        reports = exporters.hackerone_reports([f], HOSTS, {})
        info = reports[0]["data"]["attributes"]["vulnerability_information"]
        assert "hunter2xyz" not in info
        assert "<redacted>" in info


class TestExportFile:
    def test_writes_h1_json(self, tmp_path):
        base = str(tmp_path / "report.md")
        path = exporters.export(base, findings=[_finding(1)],
                                hosts=HOSTS, evidence_by_finding={})
        assert path.endswith(".h1.json")
        data = json.loads(open(path, encoding="utf-8").read())
        assert data["count"] == 1
        assert data["reports"][0]["data"]["attributes"]["title"] == "Finding"

    def test_excludes_rejected(self, tmp_path):
        base = str(tmp_path / "r.md")
        findings = [_finding(1, status="confirmed"),
                    _finding(2, status="rejected", title="FP")]
        path = exporters.export(base, findings=findings, hosts=HOSTS,
                                evidence_by_finding={})
        data = json.loads(open(path, encoding="utf-8").read())
        titles = [r["data"]["attributes"]["title"]
                  for r in data["reports"]]
        assert titles == ["Finding"]

    def test_min_severity_filter(self, tmp_path):
        base = str(tmp_path / "r.md")
        findings = [_finding(1, severity="low", title="Low"),
                    _finding(2, severity="high", title="High")]
        path = exporters.export(base, findings=findings, hosts=HOSTS,
                                evidence_by_finding={}, min_severity="high")
        data = json.loads(open(path, encoding="utf-8").read())
        titles = [r["data"]["attributes"]["title"] for r in data["reports"]]
        assert titles == ["High"]
