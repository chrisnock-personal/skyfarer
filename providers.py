"""
providers.py
~~~~~~~~~~~~
Optional read-only account API keys. They answer two questions that a status
page can't: which regions does this account actually have resources in, and
how many of those resources does an incident touch?

Only compute instances are counted (DigitalOcean Droplets, Hetzner servers and
Linodes). This is not infrastructure monitoring: Skyfarer never checks the
health of an individual VM or service, and only ever makes GET requests. A
provider that has no key is simply skipped.

The poller calls discover() once per cycle, watches the regions it returns,
and keeps the last good read in Postgres so the dashboard can show it without
holding an API key or making its own calls.
"""

from __future__ import annotations

import logging
import os
from collections import Counter

import requests

import feeds

log = logging.getLogger("skyfarer.providers")

API_TIMEOUT = 8
MAX_PAGES = 100

DO_DROPLETS_URL = os.getenv("DIGITALOCEAN_API_URL", "https://api.digitalocean.com/v2/droplets")
HETZNER_SERVERS_URL = os.getenv("HETZNER_API_URL", "https://api.hetzner.cloud/v1/servers")
LINODE_INSTANCES_URL = os.getenv("LINODE_API_URL", "https://api.linode.com/v4/linode/instances")

# The last successful discovery, and the providers whose read failed. A failed
# read must not be reported as "zero resources": the old snapshot stays in use
# and the incident gets no count this cycle.
DISCOVERED: dict[str, dict[str, int]] = {}
ERRORS: dict[str, str] = {}


def _get_json(name: str, url: str, token: str, params: dict) -> dict:
    try:
        response = requests.get(
            url, params=params, timeout=API_TIMEOUT,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        response.raise_for_status()
        data = response.json()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        raise RuntimeError(f"HTTP {status}") from None
    except requests.RequestException as exc:
        raise RuntimeError(type(exc).__name__) from None
    except ValueError:
        raise RuntimeError("invalid JSON") from None
    if not isinstance(data, dict):
        raise RuntimeError("unexpected response")
    log.debug("%s account API: read %s", name, url)
    return data


def _discover_digitalocean(token: str) -> dict[str, int]:
    """Droplet regions are slugs such as lon1; the status page names them LON1."""
    counts: Counter = Counter()
    for page in range(1, MAX_PAGES + 1):
        data = _get_json("DigitalOcean", DO_DROPLETS_URL, token,
                         {"page": page, "per_page": 200})
        for droplet in data.get("droplets") or []:
            slug = (droplet.get("region") or {}).get("slug") if isinstance(droplet, dict) else ""
            if slug:
                counts[str(slug).upper()] += 1
        pagination = (data.get("meta") or {}).get("pagination") or {}
        if page >= int(pagination.get("pages") or 1):
            break
    return dict(counts)


def _discover_hetzner(token: str) -> dict[str, int]:
    """Hetzner's server location names (fsn1, nbg1...) are also its status
    page's region codes, in upper case."""
    counts: Counter = Counter()
    page = 1
    while page <= MAX_PAGES:
        data = _get_json("Hetzner", HETZNER_SERVERS_URL, token,
                         {"page": page, "per_page": 100})
        for server in data.get("servers") or []:
            name = (server.get("location") or {}).get("name") if isinstance(server, dict) else ""
            if name:
                counts[str(name).upper()] += 1
        pagination = (data.get("meta") or {}).get("pagination") or {}
        next_page = pagination.get("next_page")
        if not next_page:
            break
        page = int(next_page)
    return dict(counts)


def _discover_linode(token: str) -> dict[str, int]:
    """Linode region IDs (gb-lon, eu-west...) prefix the component names on
    status.linode.com, e.g. GB-LON (London 2)."""
    counts: Counter = Counter()
    for page in range(1, MAX_PAGES + 1):
        data = _get_json("Linode", LINODE_INSTANCES_URL, token,
                         {"page": page, "page_size": 100})
        for instance in data.get("data") or []:
            region = instance.get("region") if isinstance(instance, dict) else ""
            if region:
                counts[str(region).upper()] += 1
        if page >= int(data.get("pages") or 1):
            break
    return dict(counts)


# provider -> (API key setting, enabled setting, name of the read function).
# The name is looked up at call time so tests (and future overrides) can patch
# the reader without rebuilding this table.
API_KEYS: dict[str, tuple[str, str, str]] = {
    "DigitalOcean": ("DIGITALOCEAN_API_KEY", "DIGITALOCEAN_ENABLED", "_discover_digitalocean"),
    "Hetzner": ("HETZNER_API_KEY", "HETZNER_ENABLED", "_discover_hetzner"),
    "Linode": ("LINODE_API_KEY", "LINODE_ENABLED", "_discover_linode"),
}


def discover() -> tuple[dict[str, dict[str, int]], dict[str, str], set[str]]:
    """Read every configured account API. Returns (regions, errors, cleared):
    `regions` is the region snapshot to watch — good reads, or the last good
    read when an API failed — `errors` names those that failed, and `cleared`
    names those whose key is absent or whose provider is switched off."""
    global DISCOVERED, ERRORS
    regions: dict[str, dict[str, int]] = {}
    errors: dict[str, str] = {}
    cleared: set[str] = set()
    for name, (key_setting, enabled_setting, reader) in API_KEYS.items():
        token = os.getenv(key_setting, "").strip()
        if not token or os.getenv(enabled_setting, "true").lower() == "false":
            cleared.add(name)
            continue
        try:
            regions[name] = globals()[reader](token)
        except Exception as exc:
            reason = str(exc) or type(exc).__name__
            log.error("%s account API: %s; keeping the last good read", name, reason)
            errors[name] = reason
            # Keep watching the last known regions, but don't report a count
            # from a read that didn't happen this cycle.
            regions[name] = dict(DISCOVERED.get(name, {}))
    DISCOVERED, ERRORS = regions, errors
    return regions, errors, cleared


def impact(provider: str, regions) -> dict | None:
    """How many of the account's resources does an incident in these regions
    touch? None means there's no usable account read (no key, a failed read,
    or a provider we don't discover). Zero is a real answer when the key was
    read successfully and no resources are in those regions."""
    setting = API_KEYS.get(provider)
    if not setting or provider in ERRORS:
        return None
    key_setting, enabled_setting, _ = setting
    if not os.getenv(key_setting, "").strip() or \
            os.getenv(enabled_setting, "true").lower() == "false":
        return None
    counts = DISCOVERED.get(provider)
    if counts is None:
        return None
    watched = [r for r in regions if r and r != "*"]
    if not watched or "all" in watched:
        selected = dict(counts)
    else:
        selected = {}
        for label, count in counts.items():
            if any(_same_region(region, label) for region in watched):
                selected[label] = count
    return {"total": sum(selected.values()),
            "regions": dict(sorted(selected.items()))}


def _same_region(watched: str, discovered: str) -> bool:
    """A configured LON should include a discovered LON1, but a configured
    NBG1 must not pick up NBG10."""
    if watched.lower() == discovered.lower():
        return True
    return feeds.region_pattern(watched).search(discovered) is not None
