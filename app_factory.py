#!/usr/bin/env python3
"""
SEE-Monitor: Application Factory (with RBAC)
Creates the Flask application with:
  - Auth blueprint  (/login, /logout, /change-password)
  - Admin blueprint (/admin/*)
  - App blueprint   (/app/* — dashboard)
  - Security headers middleware

SPDX-License-Identifier: GPL-3.0-or-later
Copyright (C) 2026 SEE-Monitor Contributors
AI-assisted development: portions generated with Claude (Anthropic)
"""

import logging
import os
import sys
from datetime import timedelta

from flask import Flask, redirect, url_for, jsonify

sys.path.insert(0, os.path.dirname(__file__))

from auth.store import AuthStore
from auth.middleware import LocalAuthProvider, SESSION_LIFETIME_SECONDS
from data.database import Database
from scanner.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)


def create_app(config: dict = None) -> Flask:
    if config is None:
        try:
            from see_monitor import load_config
            cfg = load_config()
        except Exception:
            cfg = {}
    else:
        cfg = config

    # Reload blueprint modules so repeated create_app calls (tests) get fresh
    # Blueprint instances.
    import importlib
    import auth.auth_routes as _auth_mod
    import admin.routes as _admin_mod
    import app_routes as _app_mod
    for _mod in (_auth_mod, _admin_mod, _app_mod):
        importlib.reload(_mod)
    from auth.auth_routes import auth_bp
    from admin.routes import admin_bp
    from app_routes import app_bp

    app = Flask(__name__)

    secret = cfg.get("secret_key", os.environ.get("SEE_SECRET_KEY", ""))
    if not secret or secret == "seemonitor-dev-key":
        import secrets as _sec
        secret = _sec.token_hex(32)
        logger.warning(
            "No SECRET_KEY configured — generated a random one. "
            "Set SEE_SECRET_KEY environment variable for persistence.")
    app.secret_key = secret

    https_enabled = cfg.get("https_enabled", cfg.get("cookie_secure", False))
    app.config.update(
        SESSION_COOKIE_SECURE=https_enabled,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(
            seconds=SESSION_LIFETIME_SECONDS),
    )

    db_path = cfg.get("db_path", "data/see_monitor.db")
    db = Database(db_path)
    app.config["SEE_DB"] = db

    store = AuthStore(db_path)
    provider = LocalAuthProvider(store)
    app.config["AUTH_STORE"] = store
    app.config["AUTH_PROVIDER"] = provider

    app.config["ORCHESTRATOR"] = ScanOrchestrator(cfg, db=db)
    app.config["APP_CONFIG"] = cfg

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(app_bp)

    @app.route("/")
    def root():
        return redirect(url_for("auth_bp.login"))

    from version import VERSION
    app.config["SEE_VERSION"] = VERSION

    @app.route("/api/version")
    def api_version():
        return jsonify({"version": VERSION, "name": "SEE-Monitor"})

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = \
            "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';")
        if https_enabled:
            response.headers["Strict-Transport-Security"] = \
                "max-age=31536000; includeSubDomains"
        return response

    logger.info("SEE-Monitor v%s application factory initialised", VERSION)
    return app
