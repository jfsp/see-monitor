#!/usr/bin/env python3
"""
SEE-Monitor: passive-API connectivity checker.

Verifies that the passive-intelligence APIs configured in ``config.yaml`` are
reachable and that their credentials work. One bundled script covers every
service; run it with no arguments to test all of them, or name one or more
services to test only those::

    python3 scripts/check_apis.py                 # test everything
    python3 scripts/check_apis.py shodan censys   # test only these
    python3 scripts/check_apis.py --json          # machine-readable output
    python3 scripts/check_apis.py --config /etc/see-monitor/config.yaml

Design notes
------------
* It reuses the real scanner client classes (``scanner/*_client.py``) for
  credential wiring and their exported base URLs — no auth logic is duplicated.
* Where the provider offers a health/account endpoint, the check is
  **quota-free** (Shodan ``/api-info``, Censys ``/account``, SecurityTrails
  ``/ping`` + ``/account/usage``). DNSDumpster has no such endpoint, so it
  performs a single real lookup — this consumes one request and is labelled as
  such. crt.sh needs no key and has no quota.

Exit status
-----------
* ``0`` — every *configured* service that was tested passed.
* ``1`` — at least one configured service failed (bad key, quota, or network).
* ``2`` — bad invocation (unknown service name, config not found).

An unconfigured service (empty key) is reported and skipped; it does not by
itself cause a non-zero exit.

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import argparse
import json
import os
import sys
import time

# Make the project root importable regardless of the caller's CWD.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import requests  # noqa: E402  (third-party, already a runtime dependency)

import see_monitor  # noqa: E402  (module; we override its frozen CONFIG_PATHS)
from scanner.shodan_client import ShodanClient, _API as SHODAN_API  # noqa: E402
from scanner.censys_client import (  # noqa: E402
    CensysClient, _API as CENSYS_API, _CREDITS_PATH as CENSYS_CREDITS)
from scanner.securitytrails_client import (  # noqa: E402
    SecurityTrailsClient, _BASE as ST_BASE)
from scanner.dnsdumpster_client import (  # noqa: E402
    DNSDumpsterClient, _API_URL as DD_URL)
from scanner.crtsh_client import CrtShClient, CRTSH_URL  # noqa: E402


# Result status constants.
OK = "ok"
FAIL = "fail"
SKIP = "skip"          # not configured

_VERBOSE = False
# Query-param keys whose values must never be printed in verbose output.
_SECRET_PARAMS = {"key", "api_key", "apikey", "token", "secret", "apitoken"}


def _vlog(msg):
    if _VERBOSE:
        print(msg, file=sys.stderr)


def _safe_params(params):
    if not params:
        return ""
    red = {k: ("***" if k.lower() in _SECRET_PARAMS else v)
           for k, v in params.items()}
    return f" params={red}"


def _get(label, url, timeout, **kw):
    """requests.get with verbose timing. Secrets (Authorization header, known
    secret query params) are never printed."""
    t0 = time.monotonic()
    _vlog(f"    → {label}: GET {url}{_safe_params(kw.get('params'))} "
          f"(timeout={timeout}s)")
    resp = requests.get(url, timeout=timeout, **kw)
    _vlog(f"    ← {label}: HTTP {resp.status_code} in "
          f"{time.monotonic() - t0:.2f}s")
    return resp


def _r(name, status, detail="", note=""):
    return {"service": name, "status": status, "detail": detail, "note": note}


# ---------------------------------------------------------------------------
# Per-service checks. Each takes (cfg, timeout, domain) and returns a result.
# ---------------------------------------------------------------------------

def check_shodan(cfg, timeout, domain):
    client = ShodanClient((cfg.get("shodan") or {}).get("api_key"),
                          timeout=timeout)
    if not client.available:
        return _r("shodan", SKIP, "no api_key in config")
    try:
        resp = _get("shodan", f"{SHODAN_API}/api-info", timeout,
                    params={"key": client.api_key})
        if resp.status_code == 401:
            return _r("shodan", FAIL, "API key rejected (401)")
        resp.raise_for_status()
        d = resp.json()
        detail = (f"plan={d.get('plan', '?')} "
                  f"query_credits={d.get('query_credits', '?')} "
                  f"scan_credits={d.get('scan_credits', '?')}")
        return _r("shodan", OK, detail, "quota-free (/api-info)")
    except Exception as exc:                       # noqa: BLE001
        return _r("shodan", FAIL, _err(exc))


def check_censys(cfg, timeout, domain):
    ccfg = cfg.get("censys") or {}
    client = CensysClient(ccfg.get("personal_access_token"),
                          ccfg.get("organization_id"), timeout=timeout)
    if not client.available:
        return _r("censys", SKIP, "no personal_access_token in config")
    # Validate the token against the Platform Free-user credit-balance endpoint,
    # which "does not cost any credits to execute" — quota-free. Reuses the
    # client's Bearer header + optional org-id params (no auth logic copied).
    try:
        resp = _get("censys", CENSYS_API + CENSYS_CREDITS, timeout,
                    headers=client._headers("application/json"),
                    params=client._params())
        if resp.status_code == 401:
            return _r("censys", FAIL,
                      "token rejected (401) — the Personal Access Token is "
                      "invalid or inactive")
        if resp.status_code == 404:
            return _r("censys", FAIL,
                      "user not found (404) — token may be organisation-scoped; "
                      "set censys.organization_id in config")
        resp.raise_for_status()
        result = (resp.json().get("result") or {})
        detail = f"balance={result.get('balance', '?')}"
        if result.get("resets_at"):
            detail += f" resets_at={result['resets_at']}"
        return _r("censys", OK, detail, "quota-free (/v3/accounts/users/credits)")
    except Exception as exc:                       # noqa: BLE001
        return _r("censys", FAIL, _err(exc))


def check_securitytrails(cfg, timeout, domain):
    client = SecurityTrailsClient((cfg.get("securitytrails") or {}).get("api_key"),
                                  timeout=timeout)
    if not client.available:
        return _r("securitytrails", SKIP, "no api_key in config")
    headers = {"APIKEY": client.api_key, "Accept": "application/json"}
    try:
        resp = _get("securitytrails/ping", f"{ST_BASE}/ping", timeout,
                    headers=headers)
        if resp.status_code == 401:
            return _r("securitytrails", FAIL, "API key rejected (401)")
        resp.raise_for_status()
        # Ping OK — add quota from the account/usage endpoint (also quota-free).
        detail = "ping ok"
        try:
            u = _get("securitytrails/usage", f"{ST_BASE}/account/usage",
                     timeout, headers=headers)
            if u.ok:
                j = u.json()
                detail = (f"allowed/month={j.get('allowed_monthly_usage', '?')} "
                          f"current={j.get('current_monthly_usage', '?')}")
        except Exception:                          # noqa: BLE001
            pass
        return _r("securitytrails", OK, detail, "quota-free (/ping)")
    except Exception as exc:                       # noqa: BLE001
        return _r("securitytrails", FAIL, _err(exc))


def check_dnsdumpster(cfg, timeout, domain):
    client = DNSDumpsterClient((cfg.get("dnsdumpster") or {}).get("api_key"),
                               timeout=timeout)
    if not client.available:
        return _r("dnsdumpster", SKIP, "no api_key in config")
    # DNSDumpster has no health endpoint, so read the status of one real lookup.
    # We reuse the client's exported URL + stored key (no auth logic copied);
    # the client's own query() swallows the status code, which we want here.
    try:
        resp = _get("dnsdumpster", DD_URL.format(domain=domain), timeout,
                    headers={"X-API-Key": client.api_key,
                             "Accept": "application/json"})
        if resp.status_code == 401:
            return _r("dnsdumpster", FAIL, "API key rejected (401)")
        if resp.status_code == 429:
            return _r("dnsdumpster", FAIL, "quota / rate limit exceeded (429)")
        # A 400 "Invalid domain" means the request authenticated fine (a bad key
        # would be 401) and the API simply rejected THIS domain — some domains,
        # notably reserved ones like example.com, are refused. That is proof the
        # API + key work, not a failure of the service.
        if resp.status_code == 400 and "domain" in resp.text.lower():
            return _r("dnsdumpster", OK,
                      f"key valid; provider rejected domain '{domain}'",
                      "API/key OK — pass a resolvable --domain to see a lookup")
        resp.raise_for_status()
        resp.json()  # ensure it parses
        return _r("dnsdumpster", OK, f"lookup for {domain} ok",
                  "consumed 1 request (no quota-free endpoint)")
    except Exception as exc:                       # noqa: BLE001
        return _r("dnsdumpster", FAIL, _err(exc))


def check_crtsh(cfg, timeout, domain):
    # Keyless and quota-free; reuse the real client so we exercise its path.
    client = CrtShClient(
        enabled=bool((cfg.get("crtsh") or {}).get("enabled", True)),
        timeout=timeout)
    if not client.available:
        return _r("crtsh", SKIP, "disabled in config (crtsh.enabled=false)")
    # crt.sh is frequently slow or unavailable and the `%.<domain>` JSON dump can
    # be large, so cap its wait well below the global timeout to avoid dragging
    # the whole run. Retry only on fast 5xx responses; a read timeout is not
    # retried (that would just multiply the wait).
    ct = min(timeout, 8)
    last = "no response"
    for attempt in range(3):
        try:
            resp = _get(f"crtsh#{attempt + 1}", CRTSH_URL, ct,
                        params={"q": f"%.{domain}", "output": "json"},
                        headers={"User-Agent": "see-monitor/apicheck"})
        except requests.exceptions.RequestException as exc:
            last = _err(exc)
            if "timed out" in last.lower() or "timeout" in last.lower():
                break            # don't retry timeouts — fail fast
            # otherwise a connection blip: retryable
        else:
            if resp.status_code < 400:
                # Parse the count from the payload we already fetched (reuse the
                # client's extractor) — no second heavy `%.` query.
                try:
                    names = client._extract(resp.json(), domain.strip().lower())
                except Exception:                  # noqa: BLE001
                    names = []
                return _r("crtsh", OK, f"{len(names)} name(s) for {domain}",
                          "no key / no quota")
            if resp.status_code < 500:
                return _r("crtsh", FAIL, f"crt.sh HTTP {resp.status_code}")
            last = f"HTTP {resp.status_code}"       # 5xx: retryable
        if attempt < 2:
            _vlog(f"    crtsh: attempt {attempt + 1} failed ({last}); retrying")
            time.sleep(1)
    return _r("crtsh", FAIL,
              f"crt.sh unavailable ({last})",
              "crt.sh is frequently down/slow; CT subdomain discovery degrades "
              "gracefully and does not affect scoring or the keyed sources")


CHECKS = {
    "shodan": check_shodan,
    "censys": check_censys,
    "dnsdumpster": check_dnsdumpster,
    "securitytrails": check_securitytrails,
    "crtsh": check_crtsh,
}


def _err(exc) -> str:
    """Compact one-line error string."""
    msg = str(exc) or exc.__class__.__name__
    return msg.splitlines()[0][:200]


def _load(config_path):
    """Load config, honouring --config. Reuses see_monitor.load_config() by
    overriding its search list (CONFIG_PATHS is frozen at import, so setting
    SEE_CONFIG afterwards would be ignored). Returns (cfg, resolved_path)."""
    if config_path and not os.path.exists(config_path):
        print(f"config not found: {config_path}", file=sys.stderr)
        sys.exit(2)
    if config_path:
        candidates = [config_path]
    else:
        candidates = list(see_monitor.CONFIG_PATHS) + [
            os.path.join(_ROOT, "config", "config.yaml")]
    see_monitor.CONFIG_PATHS = [c for c in candidates if c]
    cfg = see_monitor.load_config()
    resolved = next((c for c in see_monitor.CONFIG_PATHS if os.path.exists(c)),
                    None)
    return cfg, resolved


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Test SEE-Monitor passive APIs using config.yaml keys.")
    ap.add_argument("services", nargs="*", metavar="SERVICE",
                    help=f"services to test (default: all). "
                         f"choices: {', '.join(CHECKS)}")
    ap.add_argument("--config", metavar="PATH",
                    help="config file (default: SEE_CONFIG, ./config/config.yaml, "
                         "/etc/see-monitor/config.yaml)")
    ap.add_argument("--domain", default="google.com",
                    help="domain used by lookups that need one "
                         "(dnsdumpster, crtsh). Default: google.com. "
                         "Reserved domains like example.com are rejected by "
                         "DNSDumpster, so pick a real one.")
    ap.add_argument("--timeout", type=int, default=15, help="per-request seconds")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print each request, HTTP status and timing to stderr")
    args = ap.parse_args(argv)

    global _VERBOSE
    _VERBOSE = args.verbose

    selected = args.services or list(CHECKS)
    unknown = [s for s in selected if s not in CHECKS]
    if unknown:
        print(f"unknown service(s): {', '.join(unknown)}. "
              f"choices: {', '.join(CHECKS)}", file=sys.stderr)
        return 2

    cfg, resolved = _load(args.config)
    searched = resolved or "none found"
    _vlog(f"config: {searched}  |  timeout={args.timeout}s  |  "
          f"domain={args.domain}  |  services={', '.join(selected)}")

    results = []
    run_t0 = time.monotonic()
    for s in selected:
        _vlog(f"[{s}] checking…")
        t0 = time.monotonic()
        res = CHECKS[s](cfg, args.timeout, args.domain)
        res["elapsed"] = round(time.monotonic() - t0, 2)
        _vlog(f"[{s}] {res['status']} in {res['elapsed']}s")
        results.append(res)
    _vlog(f"total: {time.monotonic() - run_t0:.2f}s")

    if args.json:
        print(json.dumps({"config": args.config or None, "results": results},
                         indent=2))
    else:
        sym = {OK: "\u2713", FAIL: "\u2717", SKIP: "\u2014"}
        width = max(len(r["service"]) for r in results)
        print(f"SEE-Monitor API check  (config: {searched or 'none found'})")
        print("-" * 60)
        for r in results:
            tstr = f"  [{r['elapsed']}s]" if _VERBOSE else ""
            line = f"{sym[r['status']]} {r['service']:<{width}}  {r['detail']}{tstr}"
            print(line)
            if r["note"]:
                print(f"  {' ' * width}  ({r['note']})")

    failed = [r for r in results if r["status"] == FAIL]
    if not args.json:
        n_ok = sum(r["status"] == OK for r in results)
        n_skip = sum(r["status"] == SKIP for r in results)
        print("-" * 60)
        print(f"{n_ok} ok, {len(failed)} failed, {n_skip} not configured")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
