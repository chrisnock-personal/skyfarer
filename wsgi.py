"""
wsgi.py
~~~~~~~
The dashboard under a production web server (gunicorn, as docker-compose.yml
runs it). Run one worker process, with threads for concurrency: the first-run
setup code and the sign-in throttle are kept in that process's memory.

    gunicorn --workers 1 --threads 8 --bind 0.0.0.0:8080 wsgi:app
"""

from dashboard import app, configure_app

configure_app()

__all__ = ["app"]
