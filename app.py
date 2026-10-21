"""
SecureShip Demo API
===================

A lightweight Flask application used as the scan target for the
Automated Cloud-Native DevSecOps Pipeline. It is intentionally small, but it
follows secure-by-default practices so that the pipeline has something
realistic to scan:

* No debug mode in production and no hard-coded secrets.
* Configuration comes from environment variables.
* Hardened HTTP response headers on every response.
* Strict input validation on user-supplied data.
* A health endpoint for container orchestrators (Docker / Kubernetes).
"""

from __future__ import annotations

import os
import platform
import re
import secrets
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, request

APP_NAME = "SecureShip Demo API"
APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")

# Only allow simple, human-readable names (letters, digits, space, dot, dash, underscore).
NAME_PATTERN = re.compile(r"^[\w .\-]{1,50}$")

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app() -> Flask:
    """Application factory."""
    app = Flask(__name__)

    # Secrets are injected at runtime (e.g. from a secret manager); a random
    # per-process key is generated as a safe fallback so nothing is hard-coded.
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KiB request body limit

    @app.after_request
    def apply_security_headers(response: Response) -> Response:
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        # Do not advertise the server stack.
        response.headers.pop("Server", None)
        return response

    @app.get("/")
    def index():
        return jsonify(
            name=APP_NAME,
            version=APP_VERSION,
            message="Shipped through an automated DevSecOps pipeline.",
            endpoints=["/health", "/api/info", "/api/greet?name=<name>"],
        )

    @app.get("/health")
    def health():
        return jsonify(status="ok", timestamp=datetime.now(timezone.utc).isoformat())

    @app.get("/api/info")
    def info():
        return jsonify(
            app=APP_NAME,
            version=APP_VERSION,
            python=platform.python_version(),
            environment=os.environ.get("APP_ENV", "development"),
            security={
                "sast": "Bandit",
                "sca_and_secrets": "Trivy",
                "container_scan": "Trivy",
            },
        )

    @app.get("/api/greet")
    def greet():
        name = request.args.get("name", "DevSecOps Engineer").strip()
        if not NAME_PATTERN.fullmatch(name):
            return jsonify(error="Invalid 'name' parameter."), 400
        return jsonify(greeting=f"Hello, {name}! Your build passed the security gate.")

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify(error="Not found"), 404

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return jsonify(error="Method not allowed"), 405

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify(error="Payload too large"), 413

    return app


app = create_app()


if __name__ == "__main__":
    # Local development entry point. Production uses Gunicorn (see Dockerfile).
    # Binding to localhost by default avoids exposing the dev server publicly.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
