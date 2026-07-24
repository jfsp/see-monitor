#!/usr/bin/env python3
"""
SEE-Monitor: Smoke tests
Offline tests that exercise scoring, DB round-trips, the app factory and the
core API without touching the network. Run with:  python -m pytest -q

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from data.database import Database          # noqa: E402
from scanner.assessor import assess_domain  # noqa: E402
from scanner.mx_resolver import normalise_mx_host  # noqa: E402


def _strong_scan(domain="example.com"):
    return {"domain": domain, "scanned_at": "2026-01-01T00:00:00Z", "checks": {
        "mx": {"has_mx": True, "null_mx": False,
               "mx_hosts": [{"host": "mx.example.com", "priority": 10}],
               "invalid_records": []},
        "spf": {"present": True, "valid": True, "all_qualifier": "-",
                "records": ["v=spf1 -all"], "issues": []},
        "dkim": {"present": True, "best_status": "strong", "any_testing": False,
                 "selectors": [{"selector": "s1", "status": "strong",
                                "key_type": "rsa", "key_bits": 2048,
                                "source": "registered", "revoked": False,
                                "testing": False}], "issues": []},
        "dmarc": {"present": True, "valid": True, "policy": "reject",
                  "pct": 100, "rua": ["mailto:r@example.com"],
                  "subdomain_policy": "reject", "issues": []},
        "dnssec": {"signed": True, "validated": True, "issues": []},
        "dane": {"applicable": True, "mx_with_tlsa": [{"mx": "mx.example.com"}],
                 "mx_without_tlsa": [], "coverage": 1.0, "usable": True,
                 "issues": []},
        "mta_sts": {"present": True, "policy_fetched": True, "mode": "enforce",
                    "mx_covered": True, "issues": []},
        "tlsrpt": {"present": True, "rua": ["mailto:t@example.com"],
                   "issues": []},
        "starttls": {"applicable": True, "supported_count": 1, "total": 1,
                     "coverage": 1.0, "all_starttls": True,
                     "any_weak_tls": False, "hosts": {}, "issues": []},
        "bimi": {"present": True, "vmc_url": "https://x/vmc.pem", "issues": []},
    }}


def test_mx_normalisation():
    assert normalise_mx_host("10 mx.example.com.") == "mx.example.com"
    assert normalise_mx_host(".") is None
    assert normalise_mx_host("not a host") is None


def test_very_strong():
    a = assess_domain(_strong_scan())
    assert a["score"] == 100.0
    assert a["rating"] == "very_strong"


def test_empty_domain_scores_zero():
    scan = {"domain": "void.example", "scanned_at": "2026-01-01T00:00:00Z",
            "checks": {"mx": {"has_mx": False, "null_mx": False,
                              "mx_hosts": [], "invalid_records": []}}}
    a = assess_domain(scan)
    assert a["rating"] == "not_implemented"
    # transport controls should be n/a for a domain with no MX
    assert a["control_scores"]["starttls"] is None


def test_null_mx_transport_na():
    scan = _strong_scan()
    scan["checks"]["mx"] = {"has_mx": False, "null_mx": True,
                            "mx_hosts": [], "invalid_records": []}
    a = assess_domain(scan)
    assert a["no_mail"] is True
    assert a["control_scores"]["dane"] is None


def test_weight_override_changes_score():
    scan = _strong_scan()
    scan["checks"]["dmarc"]["policy"] = "none"
    scan["checks"]["dmarc"]["rua"] = []
    base = assess_domain(scan)["score"]
    heavy = assess_domain(scan, {"scoring": {"weights": {"dmarc": 0.9}}})["score"]
    assert heavy < base  # heavier weight on a failing control lowers the score


def test_db_roundtrip():
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    scan = _strong_scan()
    a = assess_domain(scan)
    run_id = db.create_run(["example.com"])
    db.save_scan_result(run_id, scan)
    db.save_assessment(run_id, a)
    db.finish_run(run_id)
    latest = db.get_latest_assessments()
    assert len(latest) == 1
    assert latest[0]["domain"] == "example.com"
    assert latest[0]["control_scores"]["dmarc"] == 100
    stats = db.get_summary_stats()
    assert stats["total_domains"] == 1
    assert stats["ratings"]["very_strong"] == 1


def test_app_factory_and_login():
    os.environ["SEE_SECRET_KEY"] = "x" * 32
    path = tempfile.mktemp(suffix=".db")
    from app_factory import create_app
    app = create_app({"db_path": path, "scanning": {"active_smtp": False}})
    client = app.test_client()
    assert client.get("/api/version").status_code == 200
    r = client.post("/login", data={"username": "admin",
                                     "password": "changeme123"})
    assert r.status_code in (302, 303)
    assert client.get("/app/api/summary").status_code == 200


def test_dnsdumpster_selector_extraction():
    from scanner.dnsdumpster_client import extract_selectors, DNSDumpsterClient
    payload = {
        "cname": [
            {"host": "selector1._domainkey.example.com",
             "target": "selector1-example-com._domainkey.example.onmicrosoft.com"},
        ],
        "txt": ['k3._domainkey.example.com "v=DKIM1; p=..."'],
        "foreign": [{"host": "sel._domainkey.sub.example.com"}],
    }
    sels = set(extract_selectors(payload, "example.com"))
    assert sels == {"selector1", "k3"}          # host + txt captured
    assert "selector1-example-com" not in sels  # CNAME target ignored
    assert "sel" not in sels                     # different zone ignored
    # No API key => discovery is a safe no-op
    assert DNSDumpsterClient(None).discover_selectors("example.com") == []


def test_dkim_confirms_passive_selector():
    """A DNSDumpster-discovered selector must still be TXT-confirmed."""
    from scanner import dkim_check

    class FakeDNS:
        def txt(self, name):
            if name == "odd-selector._domainkey.example.com":
                return ["v=DKIM1; k=rsa; p=" + "A" * 400]  # ~2048-bit-ish
            return []

    res = dkim_check.check_dkim("example.com", registered_selectors=[],
                                dns_client=FakeDNS(), use_wordlist=False,
                                passive_selectors=["odd-selector"])
    assert res["present"] is True
    assert res["selectors"][0]["selector"] == "odd-selector"
    assert res["selectors"][0]["source"] == "dnsdumpster"


def test_securitytrails_selector_extraction():
    from scanner.securitytrails_client import (
        _extract_selectors, SecurityTrailsClient)
    subs = ["www", "mail", "selector1._domainkey", "s2._domainkey",
            "autodiscover", "k3._domainkey.mkt"]
    sels = set(_extract_selectors(subs))
    assert sels == {"selector1", "s2", "k3"}
    # No key => safe no-op
    st = SecurityTrailsClient(None)
    assert st.available is False
    g = st.gather("example.com")
    assert g["available"] is False and g["selectors"] == []


def test_cli_scan_renderer():
    import see_monitor
    scan = {"domain": "example.com", "scanned_at": "2026-01-01T00:00:00Z",
            "checks": {"mx": {"has_mx": True, "null_mx": False,
                              "mx_hosts": [{"host": "mx.example.com",
                                            "priority": 10}]},
                       "dmarc": {"record": "v=DMARC1; p=reject"}},
            "services": {
                "securitytrails": {"available": True, "mx": 1, "selectors": 3,
                                   "subdomains": 40, "error": None},
                "dnsdumpster": {"available": True, "selectors": 2, "error": None},
                "shodan": {"available": False}, "censys": {"available": False},
                "active_smtp": {"used": True, "mx_covered": 1, "mx_total": 1}}}
    a = {"domain": "example.com", "score": 72.0, "rating": "strong",
         "no_mail": False, "control_scores": {c: 80 for c in see_monitor._CONTROLS},
         "findings": [{"control": "spf", "severity": "warning", "message": "x"}]}
    basic = see_monitor._render_scan(scan, a, verbose=False)
    assert "example.com" in basic
    assert "SecurityTrails: MX×1, 3 selectors" in basic
    assert "DNSDumpster: 2 selectors" in basic
    # debug view adds the DMARC record and the finding line
    debug = see_monitor._render_scan(scan, a, verbose=True)
    assert "v=DMARC1; p=reject" in debug
    assert "detail" in debug


def test_spf_ordering_and_denyall():
    from scanner import spf_check

    class FakeDNS:
        def __init__(self, rec):
            self.rec = rec

        def txt(self, name):
            return [self.rec] if name == "d.example" else []

    bad = spf_check.check_spf("d.example",
                              FakeDNS("v=spf1 -all include:x.example"))
    assert bad["all_is_last"] is False
    assert any("not the last" in i for i in bad["issues"])

    deny = spf_check.check_spf("d.example", FakeDNS("v=spf1 -all"))
    assert deny["deny_all"] is True

    ptr = spf_check.check_spf("d.example", FakeDNS("v=spf1 ptr -all"))
    assert ptr["uses_ptr"] is True


def test_dkim_dual_algorithm_and_bounds():
    from scanner import dkim_check

    class FakeDNS:
        def txt(self, name):
            if name == "rsa._domainkey.d.example":
                return ["v=DKIM1; k=rsa; p=" + "A" * 400]        # ~2048
            if name == "big._domainkey.d.example":
                return ["v=DKIM1; k=rsa; h=sha1:sha256; p=" + "A" * 720]  # >2048
            if name == "ed._domainkey.d.example":
                return ["v=DKIM1; k=ed25519; p=" + "B" * 43]
            return []

    r = dkim_check.check_dkim(
        "d.example", registered_selectors=["rsa", "big", "ed"],
        dns_client=FakeDNS(), use_wordlist=False)
    assert r["has_rsa"] and r["has_ed25519"]
    assert set(r["algorithms"]) == {"rsa", "ed25519"}
    assert r["any_oversized_rsa"] is True
    assert r["any_sha1_hash"] is True


def test_dmarc_strict_ruf_external():
    from scanner import dmarc_check

    class FakeDNS:
        def txt(self, name):
            if name == "_dmarc.d.example":
                return ["v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; "
                        "rua=mailto:agg@thirdparty.net; ruf=mailto:f@d.example"]
            return []

        def query(self, name, rdtype):
            return []

    r = dmarc_check.check_dmarc("d.example", FakeDNS())
    assert r["strict_alignment"] is True
    assert r["has_ruf"] is True
    assert r["external_rua_domains"] == ["thirdparty.net"]
    assert r["external_ruf_domains"] == []       # same org


def _profile_scan(**over):
    """A fully-compliant scan; override individual checks to break a profile."""
    scan = _strong_scan("p.example")
    scan["checks"]["spf"].update(all_is_last=True, uses_ptr=False,
                                 deny_all=False)
    scan["checks"]["dkim"].update(has_rsa=True, has_ed25519=True,
                                  any_oversized_rsa=False, any_sha1_hash=False)
    scan["checks"]["dmarc"].update(strict_alignment=True, has_ruf=False,
                                   subdomain_policy="reject")
    for control, patch in over.items():
        scan["checks"].setdefault(control, {}).update(patch)
    return scan


def test_bsi_profile_gating():
    from scanner.assessor import assess_domain
    ok = assess_domain(_profile_scan(), guideline_id="bsi_tr03182")
    assert ok["compliant"] is True and ok["rating"] == "compliant"
    # Missing Ed25519 => BSI non-compliant, demoted below the top band
    bad = assess_domain(_profile_scan(dkim={"has_ed25519": False}),
                        guideline_id="bsi_tr03182")
    assert bad["compliant"] is False
    assert bad["rating"] != "compliant"
    assert any("Ed25519" in f["message"] for f in bad["findings"])


def test_acn_requires_ruf_bsi_forbids_it():
    from scanner.assessor import assess_domain
    scan = _profile_scan(dmarc={"has_ruf": True})          # ruf present
    acn = assess_domain(scan, guideline_id="acn_email")
    bsi = assess_domain(scan, guideline_id="bsi_tr03182")
    assert acn["compliance"]["dmarc_ruf"] is True          # ACN satisfied
    assert bsi["compliance"]["dmarc_no_ruf"] is False       # BSI violated
    assert bsi["compliant"] is False


def test_client_tls_na_does_not_block_ccn():
    from scanner.assessor import assess_domain
    scan = _profile_scan()          # no client_tls key => not applicable
    ccn = assess_domain(scan, guideline_id="ccn_cert_bp02")
    assert ccn["control_scores"]["client_tls"] is None
    assert ccn["compliance"]["client_tls_all"] is None      # n/a, not blocking
    assert ccn["compliant"] is True


def test_multiprofile_db_roundtrip():
    from scanner.assessor import assess_domain
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    scan = _profile_scan()
    run_id = db.create_run(["p.example"])
    db.save_scan_result(run_id, scan)
    for gid in ("nist_800_177r1", "bsi_tr03182", "acn_email"):
        db.save_assessment(run_id, assess_domain(scan, guideline_id=gid))
    db.finish_run(run_id)

    assert set(db.get_guidelines_present()) >= {
        "nist_800_177r1", "bsi_tr03182", "acn_email"}
    # default guideline filter returns exactly one row per domain
    nist = db.get_latest_assessments()
    assert len(nist) == 1 and nist[0]["guideline"] == "nist_800_177r1"
    bsi = db.get_latest_assessments(guideline="bsi_tr03182")
    assert len(bsi) == 1 and bsi[0]["guideline"] == "bsi_tr03182"
    # across-all view returns one row per (domain, guideline)
    allp = db.get_latest_assessments(guideline=None)
    assert len({a["guideline"] for a in allp}) == 3


def _mk_assessment(domain, ts, score, rating, gid="nist_800_177r1"):
    return {"domain": domain, "assessed_at": ts, "guideline": gid,
            "score": score, "rating": rating, "no_mail": False,
            "control_scores": {"spf": score}, "findings": []}


def test_timeline_bucketing():
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    run = db.create_run(["a.com", "b.com"])
    for d, ts, sc, rt in [
        ("a.com", "2026-06-01T10:00:00+00:00", 40, "medium"),
        ("b.com", "2026-06-02T10:00:00+00:00", 20, "not_implemented"),
        ("a.com", "2026-06-09T10:00:00+00:00", 70, "strong"),
        ("a.com", "2026-07-01T10:00:00+00:00", 90, "very_strong"),
    ]:
        db.save_assessment(run, _mk_assessment(d, ts, sc, rt))
    db.finish_run(run)

    weekly = db.get_timeline(["a.com", "b.com"], "nist_800_177r1", "weekly")
    labels = [b["label"] for b in weekly]
    assert labels == ["2026-W23", "2026-W24", "2026-W27"]   # chronological
    assert weekly[0]["avg_score"] == 30.0                   # mean of 40 & 20
    assert weekly[0]["scans"] == 2 and weekly[0]["domains"] == 2
    assert weekly[0]["ratings"] == {"medium": 1, "not_implemented": 1}

    monthly = db.get_timeline(None, "nist_800_177r1", "monthly")
    assert [b["label"] for b in monthly] == ["Jun 2026", "Jul 2026"]
    assert monthly[0]["scans"] == 3

    # scope filter honoured
    only_a = db.get_timeline(["a.com"], "nist_800_177r1", "monthly")
    assert only_a[0]["domains"] == 1


def test_timeline_and_guidelines_api():
    os.environ["SEE_SECRET_KEY"] = "y" * 32
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    run = db.create_run(["a.com"])
    db.save_assessment(run, _mk_assessment(
        "a.com", "2026-06-09T10:00:00+00:00", 80, "compliant", "bsi_tr03182"))
    db.finish_run(run)

    from app_factory import create_app
    app = create_app({"db_path": path, "scanning": {"active_smtp": False}})
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "changeme123"})

    gl = client.get("/app/api/guidelines").get_json()
    by_id = {g["id"]: g for g in gl}
    assert by_id["nist_800_177r1"]["bands"]                 # bands exposed
    assert len(by_id["bsi_tr03182"]["bands"]) == 3
    assert by_id["bsi_tr03182"]["has_data"] is True

    tl = client.get(
        "/app/api/timeline?period=quarterly&guideline=bsi_tr03182").get_json()
    assert tl["period"] == "quarterly"
    assert tl["buckets"][0]["ratings"] == {"compliant": 1}


def test_pdf_reports_generate():
    import pytest
    pytest.importorskip("reportlab")
    from reports.pdf_report import (
        build_scope_report_pdf, build_trend_report_pdf)
    bands = [{"rating": "not_implemented", "min_score": 0, "color": "#d64545"},
             {"rating": "partial", "min_score": 40, "color": "#e0a030"},
             {"rating": "compliant", "min_score": 80, "color": "#3aa76d"}]
    meta = {"scope_label": "org: X", "guideline_id": "bsi_tr03182",
            "guideline_name": "BSI TR-03182", "generated_at": "2026-07-22",
            "total": 2, "avg_score": 55.0,
            "ratings": {"compliant": 1, "not_implemented": 1}, "period": "weekly"}
    ass = [{"domain": "a", "score": 90, "rating": "compliant"},
           {"domain": "b", "score": 20, "rating": "not_implemented"}]
    buckets = [{"label": "2026-W24", "avg_score": 55, "domains": 2, "scans": 2,
                "ratings": {"compliant": 1, "not_implemented": 1}}]
    assert build_scope_report_pdf(meta, ass, buckets, bands)[:4] == b"%PDF"
    assert build_trend_report_pdf(meta, buckets, bands)[:4] == b"%PDF"
    # empty scope must not raise
    assert build_scope_report_pdf({**meta, "total": 0, "ratings": {}}, [], [],
                                  bands)[:4] == b"%PDF"


def test_report_pdf_endpoints():
    import pytest
    pytest.importorskip("reportlab")
    os.environ["SEE_SECRET_KEY"] = "p" * 32
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    run = db.create_run(["a.com"])
    db.save_assessment(run, _mk_assessment(
        "a.com", "2026-06-10T10:00:00+00:00", 80, "strong"))
    db.finish_run(run)
    from app_factory import create_app
    app = create_app({"db_path": path, "scanning": {"active_smtp": False}})
    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "changeme123"})
    for url in ("/app/api/report/pdf", "/app/api/report/trend.pdf?period=monthly",
                "/app/api/report/pdf?domain=a.com"):
        r = client.get(url)
        assert r.status_code == 200
        assert r.headers["Content-Type"] == "application/pdf"
        assert r.get_data()[:4] == b"%PDF"


def test_db_check_soundness():
    import sqlite3
    from scripts.db_check import run_checks
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    run = db.create_run(["a.com"])
    db.save_scan_result(run, {"domain": "a.com", "scanned_at": "2026-06-10T00:00:00+00:00",
                              "checks": {"spf": {"present": True}}})
    db.save_assessment(run, _mk_assessment("a.com", "2026-06-10T00:00:00+00:00",
                                           80, "strong"))
    db.finish_run(run)

    # Clean DB: no errors.
    assert not [i for i in run_checks(path) if i.level == "error"]

    # Inject inconsistencies via a raw connection (FK enforcement off).
    c = sqlite3.connect(path)
    c.execute("PRAGMA foreign_keys=OFF")
    c.execute("INSERT INTO raw_scans(run_id,domain,scanned_at,checks_json) "
              "VALUES('MISSING','x.com','t','{}')")               # FK orphan
    c.execute("INSERT INTO assessments(run_id,domain,assessed_at,guideline,"
              "score,rating,no_mail,controls_json,findings_json) VALUES"
              "(?, 'bad.com','t','nist_800_177r1',50,'medium',0,'{no','[]')",
              (run,))                                             # bad JSON
    c.execute("INSERT INTO assessments(run_id,domain,assessed_at,guideline,"
              "score,rating,no_mail,controls_json,findings_json) VALUES"
              "(?, 'z.com','t','made_up',175,'wat',5,'{}','[]')", (run,))
    c.commit()
    c.close()

    checks = {i.check for i in run_checks(path)}
    assert {"foreign_key_check", "json", "values"} <= checks
    assert any(i.level == "error" for i in run_checks(path))


def test_db_check_data_relations():
    import sqlite3
    os.environ["SEE_SECRET_KEY"] = "d" * 32
    from scripts.db_check import run_checks
    path = tempfile.mktemp(suffix=".db")
    Database(path)
    from app_factory import create_app
    create_app({"db_path": path, "scanning": {"active_smtp": False}})  # users+admin

    c = sqlite3.connect(path)
    now = "2026-07-22T00:00:00+00:00"
    c.execute("INSERT INTO users(username,email,password_hash,role,is_active,"
              "created_at) VALUES('ana','a@x','h','analyst',1,?)", (now,))
    c.execute("INSERT INTO communities(name,created_at) VALUES('Empty',?)", (now,))
    c.execute("INSERT INTO assessments(run_id,domain,assessed_at,guideline,score,"
              "rating,no_mail,controls_json,findings_json) VALUES"
              "(NULL,'lonely.com',?, 'nist_800_177r1',50,'medium',0,'{}','[]')",
              (now,))
    c.commit()
    c.close()

    seen = {i.check for i in run_checks(path)}
    assert "data.analyst_no_org" in seen
    assert "data.empty_community" in seen
    assert "data.domain_no_org" in seen
    assert "data.no_active_admin" not in seen        # default admin is active


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))


# ======================================================================
# v0.6.0 — correctness, new controls, sub-scores and evidence quality
# ======================================================================

class FakeRD:
    """Minimal stand-in for a dnspython rdata object."""

    def __init__(self, text="", **attrs):
        self._text = text
        for k, v in attrs.items():
            setattr(self, k, v)

    def to_text(self):
        return self._text


class FakeDNS:
    """
    Table-driven DNS stub.

    txt_map:   {name: [txt, ...]}
    rec_map:   {(name, rdtype): [FakeRD, ...]}
    """

    def __init__(self, txt_map=None, rec_map=None, ad=None):
        self.txt_map = txt_map or {}
        self.rec_map = rec_map or {}
        self._ad = ad
        self.queries = []

    def txt(self, name):
        self.queries.append((name, "TXT"))
        return list(self.txt_map.get(name, []))

    def query(self, name, rdtype):
        self.queries.append((name, rdtype))
        if rdtype == "TXT":
            return [FakeRD(t) for t in self.txt_map.get(name, [])]
        return list(self.rec_map.get((name, rdtype), []))

    def ad_flag(self, name, rdtype="SOA"):
        return self._ad

    def exists(self, name):
        return any(k[0] == name for k in self.rec_map) or name in self.txt_map


# ---------------------------------------------------------------- DMARC

def test_dmarc_tree_walk_inherits_apex_policy():
    """A subdomain with no record of its own must inherit via the tree walk."""
    from scanner.dmarc_check import check_dmarc
    dns = FakeDNS({"_dmarc.example.com":
                   ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:r@example.com"]})
    r = check_dmarc("mail.example.com", dns, verify_reporting=False)
    assert r["present"] is True
    assert r["inherited"] is True
    assert r["policy_domain"] == "example.com"
    assert r["policy"] == "reject"
    # What actually applies to the subdomain is sp=, not p=
    assert r["effective_policy"] == "quarantine"
    assert any("inherited from example.com" in i for i in r["issues"])


def test_dmarc_psd_record_is_not_inherited():
    """A public-suffix operator record must not be treated as the domain's."""
    from scanner.dmarc_check import check_dmarc
    dns = FakeDNS({"_dmarc.example.gov.uk": ["v=DMARC1; p=reject; psd=y"]})
    r = check_dmarc("agency.example.gov.uk", dns, verify_reporting=False)
    assert r["present"] is False
    assert r["policy_domain"] is None


def test_dmarc_np_tag_and_external_authorisation():
    from scanner.dmarc_check import check_dmarc
    txt = {
        "_dmarc.d.example": [
            "v=DMARC1; p=reject; sp=reject; np=none; "
            "rua=mailto:agg@vendor.net"],
        # No d.example._report._dmarc.vendor.net record => unauthorised
    }
    rec = {("vendor.net", "MX"): [FakeRD("10 mx.vendor.net.")]}
    r = check_dmarc("d.example", FakeDNS(txt, rec))
    assert r["np_policy"] == "none"
    assert r["external_rua_domains"] == ["vendor.net"]
    assert r["external_authorised"] == {"vendor.net": False}
    assert any("authorisation record" in i for i in r["issues"])
    assert any("np=none is weaker" in i for i in r["issues"])


def test_dmarc_np_reject_is_recognised():
    from scanner.dmarc_check import check_dmarc
    dns = FakeDNS({"_dmarc.d.example":
                   ["v=DMARC1; p=reject; sp=reject; np=reject; "
                    "rua=mailto:r@d.example"]})
    r = check_dmarc("d.example", dns, verify_reporting=False)
    assert r["np_policy"] == "reject"
    assert not any("np=" in i and "weaker" in i for i in r["issues"])


# ------------------------------------------------------------------ SPF

def test_spf_void_lookups_and_dangling_targets():
    from scanner.spf_check import check_spf
    txt = {
        "d.example": ["v=spf1 include:gone1.example include:gone2.example "
                      "include:gone3.example ip4:192.0.2.0/24 -all"],
    }
    r = check_spf("d.example", FakeDNS(txt))
    assert r["void_lookups"] == 3
    assert r["exceeds_void_limit"] is True
    assert set(r["dangling_targets"]) == {
        "gone1.example", "gone2.example", "gone3.example"}
    assert any("void lookups exceed" in i for i in r["issues"])


def test_spf_address_space_and_multi_tenant_include():
    from scanner.spf_check import check_spf
    txt = {
        "d.example": ["v=spf1 ip4:203.0.113.0/16 include:sendgrid.net -all"],
        "sendgrid.net": ["v=spf1 ip4:198.51.100.0/24 -all"],
    }
    r = check_spf("d.example", FakeDNS(txt))
    assert r["multi_tenant_includes"] == ["sendgrid.net"]
    assert r["authorised_addresses"] >= 65536
    assert r["void_lookups"] == 0
    assert any("shared sending platform" in i for i in r["issues"])
    assert any("addresses" in i for i in r["issues"])


# ----------------------------------------------------------------- DKIM

def test_dkim_unknown_is_not_scored_as_failure():
    """No selector found and none registered => unknown, scored n/a."""
    from scanner.dkim_check import check_dkim
    from scanner.assessor import assess_domain
    r = check_dkim("d.example", None, FakeDNS(), True, None)
    assert r["status"] == "unknown"
    assert r["confidence"] == "low"
    assert any("NOT proof" in i for i in r["issues"])

    scan = _strong_scan()
    scan["checks"]["dkim"] = r
    a = assess_domain(scan)
    assert a["control_scores"]["dkim"] is None      # n/a, not 0
    assert a["confidence"] in ("medium", "low")
    assert any("DKIM not confirmed" in n for n in a["confidence_notes"])


def test_dkim_registered_but_missing_is_a_real_failure():
    from scanner.dkim_check import check_dkim
    from scanner.assessor import assess_domain
    r = check_dkim("d.example", ["sel1"], FakeDNS(), False, None)
    assert r["status"] == "absent"
    assert r["confidence"] == "high"

    scan = _strong_scan()
    scan["checks"]["dkim"] = r
    a = assess_domain(scan)
    assert a["control_scores"]["dkim"] == 0


# ------------------------------------------------------------- STARTTLS

def test_starttls_three_state_scoring():
    from scanner.assessor import assess_domain

    def scan_with(starttls):
        scan = _strong_scan()
        scan["checks"]["starttls"] = starttls
        return scan

    unknown = {"applicable": True, "total": 2, "supported_count": 0,
               "no_tls_count": 0, "unknown_count": 2, "all_starttls": False,
               "any_weak_tls": False, "hosts": {}, "issues": []}
    assert assess_domain(scan_with(unknown))["control_scores"]["starttls"] is None

    refused = dict(unknown, no_tls_count=2, unknown_count=0)
    assert assess_domain(scan_with(refused))["control_scores"]["starttls"] == 0

    partial = {"applicable": True, "total": 2, "supported_count": 1,
               "no_tls_count": 0, "unknown_count": 1, "all_starttls": False,
               "any_weak_tls": False, "hosts": {}, "issues": []}
    score = assess_domain(scan_with(partial))["control_scores"]["starttls"]
    assert 0 < score <= 90


def test_starttls_certificate_problems_cap_the_score():
    from scanner.assessor import assess_domain
    scan = _strong_scan()
    scan["checks"]["starttls"] = {
        "applicable": True, "total": 1, "supported_count": 1,
        "no_tls_count": 0, "unknown_count": 0, "all_starttls": True,
        "any_weak_tls": False, "any_cert_hostname_mismatch": True,
        "hosts": {}, "issues": []}
    assert assess_domain(scan)["control_scores"]["starttls"] <= 55


# ----------------------------------------------------------------- BIMI

def test_bimi_absent_is_na_and_prerequisite_is_checked():
    from scanner.policy_checks import check_bimi
    from scanner.assessor import assess_domain

    absent = check_bimi("d.example", FakeDNS(), {"policy": "reject"})
    assert absent["present"] is False
    scan = _strong_scan()
    scan["checks"]["bimi"] = absent
    assert assess_domain(scan)["control_scores"]["bimi"] is None

    dns = FakeDNS({"default._bimi.d.example":
                   ["v=BIMI1; l=https://x/logo.svg; a=https://x/vmc.pem"]})
    weak = check_bimi("d.example", dns, {"policy": "none"})
    assert weak["prerequisite_met"] is False
    assert any("without DMARC enforcement" in i for i in weak["issues"])


# ---------------------------------------------------- certificates/DANE

def _self_signed(hostname="mx.example.com", days=365):
    """Build a throwaway self-signed certificate; returns DER bytes."""
    import datetime as dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(hostname)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_certificate_analysis_hostname_and_self_signed():
    from scanner.cert_check import analyse_certificate, certificate_issues
    der = _self_signed("mx.example.com")

    good = analyse_certificate([der], "mx.example.com")
    assert good["parsed"] and good["hostname_match"] is True
    assert good["self_signed"] is True
    assert good["expired"] is False
    assert good["pkix_valid"] is None          # leaf-only: not judged

    bad = analyse_certificate([der], "mail.other.example")
    assert bad["hostname_match"] is False
    assert any("does not match the MX hostname" in i
               for i in certificate_issues(bad, "mail.other.example"))


def test_certificate_wildcard_matching_is_single_label():
    from scanner.cert_check import _name_matches
    assert _name_matches("mx.example.com", "*.example.com") is True
    assert _name_matches("a.b.example.com", "*.example.com") is False
    assert _name_matches("example.com", "*.example.com") is False


def test_tlsa_parsing_rejects_unusable_parameters():
    from scanner.cert_check import parse_tlsa
    pkix_ee = parse_tlsa("1 1 1 " + "ab" * 32)
    assert pkix_ee["smtp_usable"] is False
    assert any("not usable for SMTP" in i for i in pkix_ee["issues"])

    short = parse_tlsa("3 1 1 abcd")
    assert short["digest_length_ok"] is False


def test_tlsa_matches_presented_certificate():
    import hashlib
    from scanner.cert_check import parse_tlsa, match_tlsa
    der = _self_signed("mx.example.com")
    digest = hashlib.sha256(der).hexdigest()

    good = [parse_tlsa(f"3 0 1 {digest}")]
    assert match_tlsa(good, [der])["matched"] is True

    stale = [parse_tlsa("3 0 1 " + "00" * 32)]
    assert match_tlsa(stale, [der])["matched"] is False

    # DANE-TA(2) cannot be judged from a leaf-only chain
    ta = [parse_tlsa("2 0 1 " + "00" * 32)]
    result = match_tlsa(ta, [der])
    assert result["matched"] is None and result["incomplete_chain"] is True


def test_dane_reports_mismatch_against_live_certificate():
    from scanner.policy_checks import check_dane
    der = _self_signed("mx.example.com")
    dns = FakeDNS(rec_map={("_25._tcp.mx.example.com", "TLSA"):
                           [FakeRD("3 0 1 " + "00" * 32)]})
    r = check_dane(["mx.example.com"], True, dns, {"mx.example.com": [der]})
    assert r["mismatched_mx"] == ["mx.example.com"]
    assert r["usable"] is False
    assert any("do NOT match" in i for i in r["issues"])


# ----------------------------------------------------------- reputation

def test_dnsbl_distinguishes_listed_from_refused():
    from scanner.dnsbl_check import check_dnsbl
    from scanner.assessor import assess_domain

    listed = FakeDNS(rec_map={
        ("1.113.0.203.zen.spamhaus.org", "A"): [FakeRD("127.0.0.4")]})
    r = check_dnsbl("d.example", ["203.0.113.1"], listed,
                    ["zen.spamhaus.org"], [])
    assert r["any_listed"] is True and r["listed_ips"] == ["203.0.113.1"]
    assert any("exploited host" in i for i in r["issues"])

    refused = FakeDNS(rec_map={
        ("1.113.0.203.zen.spamhaus.org", "A"): [FakeRD("127.255.255.254")]})
    b = check_dnsbl("d.example", ["203.0.113.1"], refused,
                    ["zen.spamhaus.org"], [])
    assert b["any_listed"] is False and b["any_blocked"] is True
    assert b["confidence"] == "low"

    scan = _strong_scan()
    scan["checks"]["reputation"] = b
    # A refused query must not be scored as a clean result
    assert assess_domain(scan)["control_scores"]["reputation"] is None

    scan["checks"]["reputation"] = r
    assert assess_domain(scan)["control_scores"]["reputation"] == 0


# ---------------------------------------------------------- DNS hygiene

def test_dns_hygiene_flags_dangling_and_missing_caa():
    from scanner.dns_hygiene import check_dns_hygiene, registrable_domain
    dns = FakeDNS(
        txt_map={},
        rec_map={
            ("mx.example.com", "A"): [FakeRD("203.0.113.10")],
            ("dead.example.com", "CNAME"): [
                FakeRD("gone.saas.example", target="gone.saas.example.")],
            ("example.com", "NS"): [FakeRD(target="ns1.provider.net.")],
        })
    r = check_dns_hygiene("example.com",
                          ["mx.example.com", "dead.example.com"],
                          dns, do_fcrdns=False)
    assert r["dangling_mx"] == ["dead.example.com"]
    assert r["mx_is_cname"] == ["dead.example.com"]
    assert r["takeover_risks"]
    assert r["caa"]["present"] is False
    assert r["ns_diverse"] is False
    assert any("takeover" in i for i in r["issues"])
    assert registrable_domain("mx1.mail.example.co.uk") == "example.co.uk"


def test_dns_hygiene_scoring_penalises_takeover_exposure():
    from scanner.assessor import assess_domain
    scan = _strong_scan()
    scan["checks"]["dns_hygiene"] = {
        "dangling_mx": ["dead.example.com"],
        "takeover_risks": [{"name": "mta-sts.example.com",
                            "cname": "gone.example", "reason": "dangling"}],
        "mx_is_cname": [], "fcrdns_ok": True,
        "caa": {"present": True}, "ipv6_ready": True,
        "nameservers": ["ns1.a.net", "ns2.b.net"], "ns_diverse": True,
        "issues": []}
    a = assess_domain(scan)
    assert a["control_scores"]["dns_hygiene"] == 20
    assert a["subscores"]["resilience"] is not None


# ----------------------------------------------------------- subdomains

def test_subdomain_coverage_detects_weaker_override():
    from scanner.subdomain_check import check_subdomains
    dns = FakeDNS(
        txt_map={"_dmarc.shop.example.com": ["v=DMARC1; p=none"]},
        rec_map={
            ("shop.example.com", "A"): [FakeRD("203.0.113.5")],
            ("news.example.com", "A"): [FakeRD("203.0.113.6")],
        })
    r = check_subdomains("example.com",
                         ["shop.example.com", "news.example.com",
                          "old.example.com"],
                         inherited_policy="reject", dns_client=dns)
    assert r["live"] == 2
    assert r["weaker_policy"] == ["shop.example.com"]
    assert r["unprotected"] == ["shop.example.com"]
    assert r["coverage"] == 0.5
    assert any("overrides sp=" in i for i in r["issues"])


def test_subdomain_check_na_without_candidates():
    from scanner.subdomain_check import check_subdomains
    from scanner.assessor import assess_domain
    r = check_subdomains("example.com", [], "reject", FakeDNS())
    assert r["applicable"] is False
    scan = _strong_scan()
    scan["checks"]["subdomains"] = r
    assert assess_domain(scan)["control_scores"]["subdomains"] is None


def test_crtsh_extraction_filters_and_deduplicates():
    from scanner.crtsh_client import CrtShClient
    client = CrtShClient()
    data = [
        {"name_value": "*.example.com\nmail.example.com"},
        {"name_value": "mail.example.com"},
        {"name_value": "example.com"},              # apex excluded
        {"name_value": "evil.other.com"},           # out of scope
        {"common_name": "vpn.example.com"},
    ]
    names = client._extract(data, "example.com")
    assert names == ["mail.example.com", "vpn.example.com"]


# ------------------------------------------------- sub-scores / storage

def test_subscores_and_confidence_are_computed():
    from scanner.assessor import assess_domain
    a = assess_domain(_strong_scan())
    for key in ("impersonation", "transport", "resilience"):
        assert key in a["subscores"]
    assert a["subscores"]["impersonation"] is not None
    assert a["confidence"] in ("high", "medium", "low")


def test_schema_v3_persists_subscores_and_confidence():
    from data.database import Database, SCHEMA_VERSION
    from scanner.assessor import assess_domain
    assert SCHEMA_VERSION == 3
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(os.path.join(tmp, "v3.db"))
        run = db.create_run(["example.com"])
        a = assess_domain(_strong_scan())
        db.save_assessment(run, a)
        stored = db.get_latest_assessments(["example.com"])[0]
        assert stored["subscores"] == a["subscores"]
        assert stored["confidence"] == a["confidence"]
        assert isinstance(stored["confidence_notes"], list)


def test_schema_v2_database_migrates_in_place():
    """A v2 database must gain the v3 columns without losing rows."""
    import json as _json
    import sqlite3
    from data.database import Database
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "legacy.db")
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE schema_version (version INTEGER NOT NULL,
                                         applied_at TEXT NOT NULL);
            CREATE TABLE scan_runs (id TEXT PRIMARY KEY, started_at TEXT,
                                    finished_at TEXT, status TEXT,
                                    trigger TEXT, domains_total INTEGER,
                                    domains_done INTEGER);
            CREATE TABLE assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT,
                domain TEXT NOT NULL, assessed_at TEXT NOT NULL,
                guideline TEXT NOT NULL, score REAL NOT NULL,
                rating TEXT NOT NULL, no_mail INTEGER NOT NULL DEFAULT 0,
                controls_json TEXT NOT NULL, findings_json TEXT NOT NULL);
        """)
        conn.execute("INSERT INTO schema_version VALUES (2, '2026-01-01')")
        conn.execute(
            "INSERT INTO assessments (run_id, domain, assessed_at, guideline,"
            " score, rating, no_mail, controls_json, findings_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("r1", "legacy.example", "2026-01-01T00:00:00Z",
             "nist_800_177r1", 55.0, "medium", 0, _json.dumps({"spf": 100}),
             _json.dumps([])))
        conn.commit()
        conn.close()

        db = Database(path)                       # triggers migration
        rows = db.get_latest_assessments(["legacy.example"])
        assert len(rows) == 1
        assert rows[0]["score"] == 55.0
        assert rows[0]["subscores"] == {}         # default for legacy rows
        assert rows[0]["confidence"] == "high"


def test_roadmap_covers_new_controls():
    from roadmap.generator import generate_domain_roadmap
    from scanner.assessor import assess_domain
    scan = _strong_scan()
    scan["checks"]["dns_hygiene"] = {
        "dangling_mx": [], "mx_is_cname": [],
        "takeover_risks": [{"name": "mta-sts.example.com",
                            "cname": "gone.example", "reason": "dangling"}],
        "caa": {"present": False}, "fcrdns_ok": False,
        "nameservers": ["ns1.a.net"], "ns_diverse": False, "issues": []}
    scan["checks"]["reputation"] = {
        "enabled": True, "applicable": True, "any_listed": True,
        "any_blocked": False, "listed_ips": ["203.0.113.1"], "issues": []}
    scan["checks"]["subdomains"] = {
        "applicable": True, "live": 2, "coverage": 0.5,
        "weaker_policy": ["shop.example.com"],
        "unprotected": ["shop.example.com"], "issues": []}
    a = assess_domain(scan)
    rm = generate_domain_roadmap(a, scan["checks"])
    controls = {act["control"]
                for phase in rm["phases"] for act in phase["activities"]}
    assert {"dns_hygiene", "reputation", "subdomains"} <= controls


def test_findings_from_new_controls_survive_profile_filtering():
    """A blocklisted MX must be reported even under a profile that omits it."""
    from scanner.assessor import assess_domain
    scan = _profile_scan()
    scan["checks"]["reputation"] = {
        "enabled": True, "applicable": True, "any_listed": True,
        "any_blocked": False, "listed_ips": ["203.0.113.1"],
        "issues": ["MX address(es) listed on a blocklist: 203.0.113.1"]}
    a = assess_domain(scan, guideline_id="bsi_tr03182")
    assert any(f["control"] == "reputation" for f in a["findings"])


# ======================================================================
# v0.6.1 — scheduler coverage, multi-profile scheduled runs, audit tool
# ======================================================================

def _sched_db(tmp):
    from data.database import Database
    return Database(os.path.join(tmp, "sched.db"))


def test_schedule_audit_reports_uncovered_domains():
    from scheduler.schedule_audit import audit_schedules
    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        lid = db.save_domain_list("Partial", ["a.example", "b.example"])
        db.save_domain_list("Not scheduled", ["c.example", "d.example"])
        with db._connect() as conn:
            conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, "
                "interval_hours, enabled, next_run_at) VALUES (?,?,?,1,?)",
                ("Weekly", lid, 168, "2026-01-08T00:00:00+00:00"))

        r = audit_schedules(db)
        assert r["known_domains"] == 4
        assert r["covered"] == ["a.example", "b.example"]
        assert r["uncovered"] == ["c.example", "d.example"]
        assert r["coverage"] == 0.5
        assert any("never be rescanned" in p for p in r["problems"])


def test_schedule_audit_flags_orphan_disabled_and_overdue():
    from scheduler.schedule_audit import audit_schedules
    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        lid = db.save_domain_list("L", ["a.example"])
        empty = db.save_domain_list("Empty", [])
        with db._connect() as conn:
            # Overdue: last run long ago, weekly interval
            conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, "
                "interval_hours, enabled, last_run_at) VALUES (?,?,?,1,?)",
                ("Stale", lid, 168, "2020-01-01T00:00:00+00:00"))
            # Unbound: no domain list at all
            conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, "
                "interval_hours, enabled) VALUES (?,NULL,?,1)",
                ("Unbound", 24))
            # Disabled, and bound to an empty list
            conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, "
                "interval_hours, enabled) VALUES (?,?,?,0)",
                ("Off", empty, 24))

        r = audit_schedules(db)
        assert "Unbound" in r["orphan_schedules"]
        assert "Off" in r["disabled_schedules"]
        assert [s["name"] for s in r["schedules"] if s["overdue"]] == ["Stale"]
        assert any("Overdue" in p for p in r["problems"])
        assert any("missing or empty domain list" in p for p in r["problems"])


def test_schedule_audit_detects_duplicate_coverage():
    from scheduler.schedule_audit import audit_schedules
    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        a = db.save_domain_list("A", ["dup.example", "x.example"])
        b = db.save_domain_list("B", ["dup.example", "y.example"])
        with db._connect() as conn:
            for name, lid in (("First", a), ("Second", b)):
                conn.execute(
                    "INSERT INTO scheduled_scans (name, domain_list_id, "
                    "interval_hours, enabled) VALUES (?,?,168,1)", (name, lid))
        r = audit_schedules(db)
        assert list(r["duplicated"]) == ["dup.example"]
        assert set(r["duplicated"]["dup.example"]) == {"First", "Second"}


def test_create_weekly_is_idempotent_and_closes_the_gap():
    from scheduler.schedule_audit import (audit_schedules,
                                          create_weekly_all_domains,
                                          AUTO_SCHEDULE_NAME)
    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        db.save_domain_list("Seed", ["a.example", "b.example", "c.example"])

        dry = create_weekly_all_domains(db, dry_run=True)
        assert dry["dry_run"] is True and dry["schedule_action"] == "created"
        assert audit_schedules(db)["coverage"] == 0.0   # nothing written

        first = create_weekly_all_domains(db)
        assert first["list_action"] == "created"
        assert first["schedule_action"] == "created"
        assert audit_schedules(db)["coverage"] == 1.0

        again = create_weekly_all_domains(db)
        assert again["list_action"] == "unchanged"
        assert again["schedule_action"] == "unchanged"

        with db._connect() as conn:
            rows = conn.execute(
                "SELECT COUNT(*) c FROM scheduled_scans WHERE name=?",
                (AUTO_SCHEDULE_NAME,)).fetchone()
        assert rows["c"] == 1                            # no duplicate


def test_create_weekly_picks_up_new_domains():
    from scheduler.schedule_audit import (audit_schedules,
                                          create_weekly_all_domains)
    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        db.save_domain_list("Seed", ["a.example"])
        create_weekly_all_domains(db)

        db.save_domain_list("Later", ["new.example"])
        assert audit_schedules(db)["uncovered"] == ["new.example"]

        again = create_weekly_all_domains(db)
        assert again["list_action"] == "updated"
        assert again["added"] == ["new.example"]
        assert audit_schedules(db)["coverage"] == 1.0


def test_create_weekly_respects_custom_interval():
    from scheduler.schedule_audit import (create_weekly_all_domains,
                                          AUTO_SCHEDULE_NAME)
    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        db.save_domain_list("Seed", ["a.example"])
        create_weekly_all_domains(db, interval_hours=24)
        with db._connect() as conn:
            row = conn.execute(
                "SELECT interval_hours FROM scheduled_scans WHERE name=?",
                (AUTO_SCHEDULE_NAME,)).fetchone()
        assert row["interval_hours"] == 24

        changed = create_weekly_all_domains(db, interval_hours=168)
        assert changed["schedule_action"] == "updated"


def test_scheduled_scan_writes_every_profile():
    """Regression: scheduled runs used to persist only the default profile."""
    from scheduler.scan_scheduler import ScanScheduler
    from scanner.assessor import available_guidelines
    scan = _strong_scan()

    class FakeOrchestrator:
        def scan_domain(self, domain):
            result = dict(scan)
            result["domain"] = domain
            return result

    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        lid = db.save_domain_list("L", ["example.com"])
        with db._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, "
                "interval_hours, enabled) VALUES (?,?,168,1)", ("W", lid))
            sid = cur.lastrowid

        sched = ScanScheduler(FakeOrchestrator(), db,
                              config={"scheduling": {"post_run_db_check": False}})
        run_id = sched._run_scheduled_scan(sid, lid)

        with db._connect() as conn:
            rows = conn.execute(
                "SELECT guideline FROM assessments WHERE run_id=?",
                (run_id,)).fetchall()
        assert {r["guideline"] for r in rows} == set(available_guidelines())


def test_scheduled_scan_updates_last_and_next_run():
    from scheduler.scan_scheduler import ScanScheduler
    scan = _strong_scan()

    class FakeOrchestrator:
        def scan_domain(self, domain):
            return dict(scan, domain=domain)

    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        lid = db.save_domain_list("L", ["example.com"])
        with db._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, "
                "interval_hours, enabled) VALUES (?,?,24,1)", ("W", lid))
            sid = cur.lastrowid

        sched = ScanScheduler(FakeOrchestrator(), db,
                              config={"scheduling": {"post_run_db_check": False}})
        sched._run_scheduled_scan(sid, lid)

        with db._connect() as conn:
            row = conn.execute(
                "SELECT last_run_at, next_run_at FROM scheduled_scans "
                "WHERE id=?", (sid,)).fetchone()
        assert row["last_run_at"] and row["next_run_at"]
        assert row["next_run_at"] > row["last_run_at"]


def test_scheduled_scan_marks_errors_when_db_check_fails(monkeypatch):
    from scheduler import scan_scheduler as ss
    scan = _strong_scan()

    class FakeOrchestrator:
        def scan_domain(self, domain):
            return dict(scan, domain=domain)

    class FakeIssue:
        level = "error"
        check = "json"
        detail = "synthetic failure"

    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        lid = db.save_domain_list("L", ["example.com"])
        with db._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scheduled_scans (name, domain_list_id, "
                "interval_hours, enabled) VALUES (?,?,168,1)", ("W", lid))
            sid = cur.lastrowid

        sched = ss.ScanScheduler(FakeOrchestrator(), db,
                                 config={"scheduling":
                                         {"post_run_db_check": True}})
        monkeypatch.setattr(sched, "_db_check_failed", lambda: True)
        run_id = sched._run_scheduled_scan(sid, lid)

        with db._connect() as conn:
            row = conn.execute("SELECT status FROM scan_runs WHERE id=?",
                               (run_id,)).fetchone()
        assert row["status"] == "completed_with_errors"


def test_db_check_failure_never_raises():
    """A broken health check must not lose the scan that was just written."""
    from scheduler.scan_scheduler import ScanScheduler
    with tempfile.TemporaryDirectory() as tmp:
        db = _sched_db(tmp)
        sched = ScanScheduler(None, db, config={})
        db.db_path = "/nonexistent/path/to.db"
        assert sched._db_check_failed() in (True, False)


def test_rescan_all_requires_known_domains(monkeypatch):
    """--rescan-all must fail clearly rather than silently scanning nothing."""
    from click.testing import CliRunner
    import see_monitor
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setattr(
            see_monitor, "load_config",
            lambda *a, **k: {"db_path": os.path.join(tmp, "empty.db"),
                             "scanning": {"active_smtp": False}})
        res = CliRunner().invoke(see_monitor.cli, ["scan", "--rescan-all"])
        assert res.exit_code != 0
        assert "no domains yet" in res.output.lower()


def test_scan_without_targets_mentions_rescan_all(monkeypatch):
    from click.testing import CliRunner
    import see_monitor
    with tempfile.TemporaryDirectory() as tmp:
        monkeypatch.setattr(
            see_monitor, "load_config",
            lambda *a, **k: {"db_path": os.path.join(tmp, "empty.db")})
        res = CliRunner().invoke(see_monitor.cli, ["scan"])
        assert res.exit_code != 0
        assert "--rescan-all" in res.output
