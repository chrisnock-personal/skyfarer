"""
wsgi.py
~~~~~~~
The dashboard under a production web server (gunicorn, as docker-compose.yml
runs it). The first-run setup code and the sign-in throttle are in Postgres,
so several workers – or several replicas – share them safely.

    gunicorn --workers 2 --threads 8 --bind 0.0.0.0:8080 wsgi:app
"""

from dashboard import app, configure_app

configure_app()

__all__ = ["app"]
