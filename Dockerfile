FROM python:3.12-slim

LABEL org.opencontainers.image.title="Skyfarer" \
      org.opencontainers.image.description="Watches cloud provider status pages for incidents in your regions"

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY poller.py feeds.py db.py dashboard.py history.py notifiers.py providers.py settings.py admin.py api.py api_errors.py oidc.py cli.py skyfarer_mcp.py wsgi.py ./
COPY docs/openapi.json docs/openapi.json
COPY templates/ templates/
COPY static/ static/
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Default: continuous poll loop.  Override with --once or --dry-run.
ENTRYPOINT ["python", "-u", "poller.py"]
