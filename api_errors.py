"""
api_errors.py
~~~~~~~~~~~~~
One JSON error format for the API and the sign-in guard, so a bad token and a
bad request body look the same to callers.
"""

from __future__ import annotations

from typing import Optional

from flask import jsonify


TITLES = {
    400: "Bad request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not found", 405: "Method not allowed", 409: "Conflict",
    413: "Payload too large", 429: "Too many requests",
    500: "Internal server error", 503: "Service unavailable",
}


def problem(status: int, detail: str, *, code: Optional[str] = None,
            errors: Optional[list[dict]] = None, headers: Optional[dict] = None):
    """A RFC 9457-style application/problem+json response."""
    body = {
        "type": "https://skyfarer.local/errors/" + (code or str(status)),
        "title": TITLES.get(status, "Error"),
        "status": status,
        "detail": detail,
        "errors": errors or [],
    }
    response = jsonify(body)
    response.status_code = status
    response.mimetype = "application/problem+json"
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    return response
