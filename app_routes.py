#!/usr/bin/env python3
"""
SEE-Monitor: App Blueprint (/app/*)
Dashboard SPA shell + REST API. All endpoints require login.
Admins see everything; community managers see their communities' orgs;
analysts see only their assigned domains.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import threading

from flask import (
    Blueprint, jsonify, request, render_template_string, current_app)

from auth.middleware import (
    require_auth, current_user, filter_assessments)
from auth.models import ROLE_ADMIN

logger = logging.getLogger(__name__)

app_bp = Blueprint("app_bp", __name__, url_prefix="/app")


def _db():
    return current_app.config["SEE_DB"]


def _orchestrator():
    return current_app.config["ORCHESTRATOR"]


def _cfg():
    return current_app.config.get("APP_CONFIG", {})


def _guideline():
    """Guideline profile from ?guideline=; validated, defaults to NIST."""
    from data.database import DEFAULT_GUIDELINE_ID
    from scanner.assessor import available_guidelines
    gid = (request.args.get("guideline") or "").strip()
    return gid if gid in available_guidelines() else DEFAULT_GUIDELINE_ID


def _allowed_domains(user):
    """None for admins (no filter), else the set of visible domains."""
    if user.is_admin:
        return None
    return set(current_app.config["AUTH_STORE"].get_user_domains(user.id))


def _allowed_org_ids(user, db):
    """None for admins, else org IDs visible to the user."""
    if user.is_admin:
        return None
    ids = set(getattr(user, "org_ids", []) or [])
    for cid in getattr(user, "community_ids", []) or []:
        ids.update(o["id"] for o in db.get_community_orgs(cid))
    return ids


# ----------------------------------------------------------------------
# SPA shell
# ----------------------------------------------------------------------
@app_bp.route("/")
@app_bp.route("/<path:_>")
@require_auth
def dashboard_home(_=None):
    from version import VERSION
    from dashboard.app import DASHBOARD_HTML
    user = current_user()
    return render_template_string(
        DASHBOARD_HTML, version=VERSION,
        username=user.username, role=user.role)


# ----------------------------------------------------------------------
# Summary + assessments
# ----------------------------------------------------------------------
@app_bp.route("/api/guidelines")
@require_auth
def api_guidelines():
    """List installed conformance profiles + which are present in stored data."""
    from scanner.assessor import available_guidelines, load_guideline
    from data.database import DEFAULT_GUIDELINE_ID
    present = set(_db().get_guidelines_present())
    out = []
    for gid in available_guidelines():
        try:
            g = load_guideline(None, gid)
            out.append({"id": gid, "name": g.get("name", gid),
                        "has_data": gid in present,
                        "is_default": gid == DEFAULT_GUIDELINE_ID,
                        "bands": sorted(g.get("rating_bands", []),
                                        key=lambda b: b.get("min_score", 0))})
        except Exception:
            continue
    return jsonify(out)


@app_bp.route("/api/summary")
@require_auth
def api_summary():
    user = current_user()
    allowed = _allowed_domains(user)
    stats = _db().get_summary_stats(
        None if allowed is None else list(allowed), guideline=_guideline())
    return jsonify(stats)


@app_bp.route("/api/assessments")
@require_auth
def api_assessments():
    user = current_user()
    assessments = _db().get_latest_assessments(guideline=_guideline())
    return jsonify(filter_assessments(assessments, user))


@app_bp.route("/api/domain/<domain>")
@require_auth
def api_domain_detail(domain):
    domain = domain.strip().lower()
    user = current_user()
    allowed = _allowed_domains(user)
    if allowed is not None and domain not in allowed:
        return jsonify({"error": "forbidden"}), 403
    db = _db()
    history = db.get_domain_history(domain, limit=30, guideline=_guideline())
    scans = db.get_domain_scans(domain, limit=1)
    return jsonify({
        "domain": domain,
        "latest": history[0] if history else None,
        "history": history,
        "checks": scans[0]["checks"] if scans else None,
        "organisation": db.get_domain_org(domain),
        "dkim_selectors": db.get_dkim_selectors(domain),
    })


# ----------------------------------------------------------------------
# DKIM selector registration
# ----------------------------------------------------------------------
@app_bp.route("/api/domain/<domain>/selectors", methods=["POST"])
@require_auth
def api_add_selector(domain):
    domain = domain.strip().lower()
    user = current_user()
    allowed = _allowed_domains(user)
    if allowed is not None and domain not in allowed:
        return jsonify({"error": "forbidden"}), 403
    selector = (request.get_json(silent=True) or {}).get("selector", "").strip()
    if not selector:
        return jsonify({"error": "selector required"}), 400
    _db().record_dkim_selector(domain, selector, source="manual")
    return jsonify({"ok": True,
                    "selectors": _db().get_dkim_selectors(domain)})


@app_bp.route("/api/domain/<domain>/selectors/<selector>",
              methods=["DELETE"])
@require_auth
def api_del_selector(domain, selector):
    domain = domain.strip().lower()
    user = current_user()
    allowed = _allowed_domains(user)
    if allowed is not None and domain not in allowed:
        return jsonify({"error": "forbidden"}), 403
    ok = _db().delete_dkim_selector(domain, selector)
    return jsonify({"ok": ok})


# ----------------------------------------------------------------------
# Scanning
# ----------------------------------------------------------------------
def _run_scan(app, run_id: str, domains: list[str]):
    with app.app_context():
        db = app.config["SEE_DB"]
        orch = app.config["ORCHESTRATOR"]
        cfg = app.config.get("APP_CONFIG", {})
        from scanner.assessor import assess_all_profiles
        status = "completed"
        for d in domains:
            try:
                scan = orch.scan_domain(d)
                db.save_scan_result(run_id, scan)
                for a in assess_all_profiles(scan, cfg).values():
                    db.save_assessment(run_id, a)
            except Exception:
                logger.exception("Scan failed for %s", d)
                status = "completed_with_errors"
            finally:
                db.bump_run_progress(run_id)
        db.finish_run(run_id, status)


@app_bp.route("/api/scan", methods=["POST"])
@require_auth
def api_scan():
    user = current_user()
    body = request.get_json(silent=True) or {}
    domains = [d.strip().lower().rstrip(".")
               for d in body.get("domains", []) if d.strip()]
    if not domains:
        return jsonify({"error": "no domains supplied"}), 400
    allowed = _allowed_domains(user)
    if allowed is not None:
        denied = [d for d in domains if d not in allowed]
        if denied:
            return jsonify({"error": "forbidden domains",
                            "domains": denied}), 403
    db = _db()
    run_id = db.create_run(domains, trigger=f"web:{user.username}")
    app = current_app._get_current_object()
    threading.Thread(target=_run_scan, args=(app, run_id, domains),
                     daemon=True).start()
    return jsonify({"run_id": run_id, "domains": len(domains)})


@app_bp.route("/api/runs")
@require_auth
def api_runs():
    return jsonify(_db().list_runs(limit=20))


# ----------------------------------------------------------------------
# Organisations
# ----------------------------------------------------------------------
@app_bp.route("/api/organisations")
@require_auth
def api_organisations():
    user = current_user()
    db = _db()
    allowed = _allowed_org_ids(user, db)
    orgs = db.get_organisations()
    if allowed is not None:
        orgs = [o for o in orgs if o["id"] in allowed]
    agg = db._build_group_aggregate(orgs)
    return jsonify(agg["organisations"])


@app_bp.route("/api/org/<int:org_id>")
@require_auth
def api_org_detail(org_id):
    user = current_user()
    db = _db()
    allowed = _allowed_org_ids(user, db)
    if allowed is not None and org_id not in allowed:
        return jsonify({"error": "forbidden"}), 403
    org = db.get_organisation(org_id)
    if not org:
        return jsonify({"error": "not found"}), 404
    domains = db.get_org_domains(org_id)
    gid = _guideline()
    assessments = db.get_latest_assessments(domains, guideline=gid)
    assessed = {a["domain"] for a in assessments}
    return jsonify({
        "organisation": org,
        "domains": domains,
        "unassessed": sorted(set(domains) - assessed),
        "assessments": assessments,
        "stats": db.get_summary_stats(domains, guideline=gid),
    })


# ----------------------------------------------------------------------
# Group reports (community / country / region)
# ----------------------------------------------------------------------
@app_bp.route("/api/communities")
@require_auth
def api_communities():
    user = current_user()
    db = _db()
    comms = db.get_communities()
    if not user.is_admin:
        visible = set(getattr(user, "community_ids", []) or [])
        comms = [c for c in comms if c["id"] in visible]
    return jsonify(comms)


@app_bp.route("/api/community/<int:cid>/report")
@require_auth
def api_community_report(cid):
    user = current_user()
    if not user.is_admin and \
            cid not in (getattr(user, "community_ids", []) or []):
        return jsonify({"error": "forbidden"}), 403
    return jsonify(_db().get_community_aggregate(cid, guideline=_guideline()))


@app_bp.route("/api/countries")
@require_auth
def api_countries():
    user = current_user()
    db = _db()
    allowed = _allowed_org_ids(user, db)
    if allowed is None:
        return jsonify(db.get_countries())
    countries = {}
    for o in db.get_organisations():
        if o["id"] in allowed and o.get("country_code"):
            countries[o["country_code"]] = \
                countries.get(o["country_code"], 0) + 1
    return jsonify([{"country_code": c, "org_count": n}
                    for c, n in sorted(countries.items())])


@app_bp.route("/api/country/<code>/report")
@require_auth
def api_country_report(code):
    user = current_user()
    db = _db()
    return jsonify(db.get_country_aggregate(
        code, allowed_org_ids=_allowed_org_ids(user, db),
        guideline=_guideline()))


@app_bp.route("/api/regions")
@require_auth
def api_regions():
    user = current_user()
    db = _db()
    allowed = _allowed_org_ids(user, db)
    if allowed is None:
        return jsonify(db.get_regions())
    regions = {}
    for o in db.get_organisations():
        if o["id"] in allowed and o.get("region"):
            regions[o["region"]] = regions.get(o["region"], 0) + 1
    return jsonify([{"region": r, "org_count": n}
                    for r, n in sorted(regions.items())])


@app_bp.route("/api/region/<region>/report")
@require_auth
def api_region_report(region):
    user = current_user()
    db = _db()
    return jsonify(db.get_region_aggregate(
        region, allowed_org_ids=_allowed_org_ids(user, db),
        guideline=_guideline()))


# ----------------------------------------------------------------------
# Timeline / trends
# ----------------------------------------------------------------------
def _scope_domains(user, db):
    """Resolve the RBAC-scoped domain set + a label from query params.

    ?domain= | ?org= | ?community= | ?country= | ?region= | (default: all).
    Returns (domains_or_None, label). None means 'all visible' (admins).
    Raises PermissionError on a forbidden explicit scope.
    """
    allowed = _allowed_domains(user)          # None for admin
    allowed_orgs = _allowed_org_ids(user, db)

    def _restrict(domains):
        if allowed is None:
            return domains
        return [d for d in domains if d in allowed]

    domain = (request.args.get("domain") or "").strip().lower()
    org_id = request.args.get("org", type=int)
    community_id = request.args.get("community", type=int)
    country = (request.args.get("country") or "").strip()
    region = (request.args.get("region") or "").strip()

    if domain:
        if allowed is not None and domain not in allowed:
            raise PermissionError
        return [domain], domain
    if org_id:
        if allowed_orgs is not None and org_id not in allowed_orgs:
            raise PermissionError
        org = db.get_organisation(org_id) or {}
        return _restrict(db.get_org_domains(org_id)), \
            f"org: {org.get('name', org_id)}"
    if community_id:
        if not user.is_admin and community_id not in \
                (getattr(user, "community_ids", []) or []):
            raise PermissionError
        return _restrict(db.get_community_domains(community_id)), \
            f"community: {community_id}"
    if country:
        agg = db.get_country_aggregate(country, allowed_org_ids=allowed_orgs)
        domains = []
        for o in agg.get("organisations", []):
            domains += db.get_org_domains(o["id"])
        return _restrict(sorted(set(domains))), f"country: {country.upper()}"
    if region:
        agg = db.get_region_aggregate(region, allowed_org_ids=allowed_orgs)
        domains = []
        for o in agg.get("organisations", []):
            domains += db.get_org_domains(o["id"])
        return _restrict(sorted(set(domains))), f"region: {region}"
    return (None if allowed is None else list(allowed)), "all domains"


@app_bp.route("/api/timeline")
@require_auth
def api_timeline():
    """Trend of assessments over time for a scope + guideline.

    Query: period=weekly|monthly|quarterly|yearly, guideline=<id>, and one
    optional scope (domain/org/community/country/region; default all visible).
    """
    user = current_user()
    db = _db()
    period = (request.args.get("period") or "weekly").lower()
    try:
        domains, label = _scope_domains(user, db)
    except PermissionError:
        return jsonify({"error": "forbidden"}), 403
    guideline = _guideline()
    series = db.get_timeline(domains, guideline=guideline, period=period)
    return jsonify({
        "scope": label, "guideline": guideline, "period": period,
        "domains": None if domains is None else len(domains),
        "buckets": series,
    })


# ----------------------------------------------------------------------
# Roadmaps
# ----------------------------------------------------------------------
@app_bp.route("/api/roadmap/domain/<domain>")
@require_auth
def api_domain_roadmap(domain):
    domain = domain.strip().lower()
    user = current_user()
    allowed = _allowed_domains(user)
    if allowed is not None and domain not in allowed:
        return jsonify({"error": "forbidden"}), 403
    from roadmap.generator import generate_domain_roadmap
    db = _db()
    history = db.get_domain_history(domain, limit=1, guideline=_guideline())
    if not history:
        return jsonify({"error": "no assessment for this domain"}), 404
    scans = db.get_domain_scans(domain, limit=1)
    roadmap = generate_domain_roadmap(
        history[0], scans[0]["checks"] if scans else None)
    db.save_roadmap(roadmap, domain=domain, scope="domain")
    return jsonify(roadmap)


@app_bp.route("/api/roadmap/group")
@require_auth
def api_group_roadmap():
    """Aggregate roadmap: ?org=<id> | ?community=<id> | (default: all visible)."""
    user = current_user()
    db = _db()
    from roadmap.generator import generate_group_roadmap
    org_id = request.args.get("org", type=int)
    community_id = request.args.get("community", type=int)
    if org_id:
        allowed = _allowed_org_ids(user, db)
        if allowed is not None and org_id not in allowed:
            return jsonify({"error": "forbidden"}), 403
        domains = db.get_org_domains(org_id)
        label = f"org:{org_id}"
    elif community_id:
        if not user.is_admin and community_id not in \
                (getattr(user, "community_ids", []) or []):
            return jsonify({"error": "forbidden"}), 403
        domains = db.get_community_domains(community_id)
        label = f"community:{community_id}"
    else:
        allowed = _allowed_domains(user)
        domains = None if allowed is None else list(allowed)
        label = "all"
    assessments = db.get_latest_assessments(domains, guideline=_guideline())
    return jsonify(generate_group_roadmap(assessments, label))
