"""
notifiers.py
~~~~~~~~~~~~
Sends incident notices to Zendesk, ServiceNow, Jira Service Management,
Freshdesk, Pushover, PagerDuty, Microsoft
Teams, SNMP trap receivers and any number of outbound webhooks.

Notices go through the `notifications` table, one row per channel. A poll cycle
adds rows in the same transaction that records the incident, and they are sent
after it commits. So a cycle that rolls back sends nothing, each channel fails
and retries alone, and one channel being down can't hold up the others.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import re
import os
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field as dc_field
from typing import Callable, Optional
from urllib.parse import urlsplit

import requests

import db

log = logging.getLogger("skyfarer.notifiers")


def _env_list(name: str, default: str = "") -> list[str]:
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


EVENTS = ("opened", "updated", "resolved")
PAGERDUTY_SEVERITIES = ("critical", "error", "warning", "info")
SNMP_TRAP_NUMBERS = {"opened": 1, "updated": 2, "resolved": 3}


def servicenow_url(instance: str) -> str:
    """SERVICENOW_INSTANCE is an instance name ("yourcompany") or its full URL."""
    instance = instance.strip().rstrip("/")
    if not instance or "://" in instance:
        return instance
    return f"https://{instance}.service-now.com"


def freshdesk_url(domain: str) -> str:
    """FRESHDESK_DOMAIN is a helpdesk name ("yourcompany") or its full URL."""
    domain = domain.strip().rstrip("/")
    if not domain or "://" in domain:
        return domain
    return f"https://{domain}.freshdesk.com"


def jsm_url(site: str) -> str:
    """JSM_SITE is a site name ("yourcompany") or its full URL."""
    site = site.strip().rstrip("/")
    if not site or "://" in site:
        return site
    return f"https://{site}.atlassian.net"


@dataclass
class Webhook:
    """One outbound webhook. There can be any number; each is its own channel."""
    id: int
    name: str
    url: str
    method: str = "POST"
    headers: str = ""              # JSON object of extra headers
    template: str = ""             # body template; empty sends every field as JSON
    content_type: str = "application/json"
    secret: str = ""               # signs the body with HMAC-SHA256
    events: list[str] = dc_field(default_factory=list)   # empty: follow NOTIFY_EVENTS

    @property
    def channel(self) -> str:
        return f"webhook-{self.id}"


def _env_webhook() -> list[Webhook]:
    """The single webhook that .env can describe (WEBHOOK_URL and friends)."""
    if not os.getenv("WEBHOOK_URL"):
        return []
    return [Webhook(
        id=1, name=os.getenv("WEBHOOK_NAME", "Webhook"), url=os.getenv("WEBHOOK_URL", ""),
        method=os.getenv("WEBHOOK_METHOD", "POST").upper(),
        headers=os.getenv("WEBHOOK_HEADERS", ""), template=os.getenv("WEBHOOK_TEMPLATE", ""),
        content_type=os.getenv("WEBHOOK_CONTENT_TYPE", "application/json"),
        secret=os.getenv("WEBHOOK_SECRET", ""), events=_env_list("WEBHOOK_EVENTS"))]


def configure(webhooks: Optional[list[Webhook]] = None) -> None:
    """Read the settings from the environment. settings.apply() puts the
    database's values there and calls this before every poll, passing the
    webhooks, which live in a table of their own."""
    global NOTIFY_EVENTS, NOTIFY_MAX_AGE_HOURS, NOTIFY_MAINTENANCE, NOTIFY_RETRY_HOURS
    global ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_TOKEN, ZD_PRIORITY, ZD_TAGS
    global ZD_GROUP_ID_RAW, ZD_GROUP_ID
    global SERVICENOW_URL, SERVICENOW_USER, SERVICENOW_PASSWORD, SERVICENOW_TOKEN
    global SERVICENOW_TABLE, SERVICENOW_IMPACT, SERVICENOW_URGENCY, SERVICENOW_ASSIGNMENT_GROUP
    global SERVICENOW_CALLER, SERVICENOW_CATEGORY, SERVICENOW_RESOLVE, SERVICENOW_RESOLVED_STATE
    global SERVICENOW_CLOSE_CODE, SERVICENOW_EXTRA_FIELDS_RAW
    global PUSHOVER_API_URL, PUSHOVER_TOKEN, PUSHOVER_USER, PUSHOVER_PRIORITY
    global PAGERDUTY_EVENTS_URL, PAGERDUTY_ROUTING_KEY, PAGERDUTY_SEVERITY, TEAMS_WEBHOOK_URL
    global SNMP_TRAP_TARGETS, SNMP_COMMUNITY, SNMP_BASE_OID, WEBHOOKS
    global JSM_URL, JSM_EMAIL, JSM_API_TOKEN, JSM_PROJECT, JSM_REQUEST_TYPE, JSM_RESOLVE
    global JSM_TRANSITION, JSM_EXTRA_FIELDS_RAW
    global FRESHDESK_URL, FRESHDESK_API_KEY, FRESHDESK_REQUESTER, FRESHDESK_PRIORITY
    global FRESHDESK_GROUP_ID_RAW, FRESHDESK_TAGS, FRESHDESK_RESOLVE, FRESHDESK_RESOLVED_STATUS
    global FRESHDESK_EXTRA_FIELDS_RAW

    NOTIFY_EVENTS = _env_list("NOTIFY_EVENTS", "opened,resolved")
    NOTIFY_MAX_AGE_HOURS = _env_float("NOTIFY_MAX_AGE_HOURS", 24)
    NOTIFY_MAINTENANCE = os.getenv("NOTIFY_MAINTENANCE", "").lower() in ("1", "true", "yes")
    NOTIFY_RETRY_HOURS = _env_float("NOTIFY_RETRY_HOURS", 24)

    ZENDESK_SUBDOMAIN = os.getenv("ZENDESK_SUBDOMAIN", "")
    ZENDESK_EMAIL = os.getenv("ZENDESK_EMAIL", "")
    ZENDESK_API_TOKEN = os.getenv("ZENDESK_API_TOKEN", "")
    ZD_PRIORITY = os.getenv("ZD_TICKET_PRIORITY", "high")
    ZD_TAGS = _env_list("ZD_TICKET_TAGS", "skyfarer,auto-raised")
    ZD_GROUP_ID_RAW = os.getenv("ZD_TICKET_GROUP_ID", "").strip()
    ZD_GROUP_ID = int(ZD_GROUP_ID_RAW) if ZD_GROUP_ID_RAW.isdigit() else None

    SERVICENOW_URL = servicenow_url(os.getenv("SERVICENOW_INSTANCE", ""))
    SERVICENOW_USER = os.getenv("SERVICENOW_USER", "")
    SERVICENOW_PASSWORD = os.getenv("SERVICENOW_PASSWORD", "")
    SERVICENOW_TOKEN = os.getenv("SERVICENOW_TOKEN", "")          # OAuth bearer, instead of a user
    SERVICENOW_TABLE = os.getenv("SERVICENOW_TABLE", "") or "incident"
    SERVICENOW_IMPACT = os.getenv("SERVICENOW_IMPACT", "2")
    SERVICENOW_URGENCY = os.getenv("SERVICENOW_URGENCY", "2")
    SERVICENOW_ASSIGNMENT_GROUP = os.getenv("SERVICENOW_ASSIGNMENT_GROUP", "")
    SERVICENOW_CALLER = os.getenv("SERVICENOW_CALLER", "")
    SERVICENOW_CATEGORY = os.getenv("SERVICENOW_CATEGORY", "")
    SERVICENOW_RESOLVE = os.getenv("SERVICENOW_RESOLVE", "true").lower() in ("1", "true", "yes")
    SERVICENOW_RESOLVED_STATE = os.getenv("SERVICENOW_RESOLVED_STATE", "") or "6"
    SERVICENOW_CLOSE_CODE = os.getenv("SERVICENOW_CLOSE_CODE", "Resolved by caller")
    SERVICENOW_EXTRA_FIELDS_RAW = os.getenv("SERVICENOW_EXTRA_FIELDS", "")

    JSM_URL = jsm_url(os.getenv("JSM_SITE", ""))
    JSM_EMAIL = os.getenv("JSM_EMAIL", "")
    JSM_API_TOKEN = os.getenv("JSM_API_TOKEN", "")
    JSM_PROJECT = os.getenv("JSM_PROJECT", "").strip().upper()
    JSM_REQUEST_TYPE = os.getenv("JSM_REQUEST_TYPE", "").strip()
    JSM_RESOLVE = os.getenv("JSM_RESOLVE", "true").lower() in ("1", "true", "yes")
    JSM_TRANSITION = os.getenv("JSM_TRANSITION", "").strip() or "Resolve"
    JSM_EXTRA_FIELDS_RAW = os.getenv("JSM_EXTRA_FIELDS", "")

    FRESHDESK_URL = freshdesk_url(os.getenv("FRESHDESK_DOMAIN", ""))
    FRESHDESK_API_KEY = os.getenv("FRESHDESK_API_KEY", "")
    FRESHDESK_REQUESTER = os.getenv("FRESHDESK_REQUESTER_EMAIL", "").strip()
    FRESHDESK_PRIORITY = os.getenv("FRESHDESK_PRIORITY", "") or "2"
    FRESHDESK_GROUP_ID_RAW = os.getenv("FRESHDESK_GROUP_ID", "").strip()
    FRESHDESK_TAGS = _env_list("FRESHDESK_TAGS", "skyfarer,auto-raised")
    FRESHDESK_RESOLVE = os.getenv("FRESHDESK_RESOLVE", "true").lower() in ("1", "true", "yes")
    FRESHDESK_RESOLVED_STATUS = os.getenv("FRESHDESK_RESOLVED_STATUS", "") or "4"
    FRESHDESK_EXTRA_FIELDS_RAW = os.getenv("FRESHDESK_EXTRA_FIELDS", "")

    PUSHOVER_API_URL = os.getenv("PUSHOVER_API_URL", "https://api.pushover.net/1/messages.json")
    PUSHOVER_TOKEN = os.getenv("PUSHOVER_TOKEN", "")
    PUSHOVER_USER = os.getenv("PUSHOVER_USER", "")
    PUSHOVER_PRIORITY = os.getenv("PUSHOVER_PRIORITY", "0")

    PAGERDUTY_EVENTS_URL = os.getenv("PAGERDUTY_EVENTS_URL", "https://events.pagerduty.com/v2/enqueue")
    PAGERDUTY_ROUTING_KEY = os.getenv("PAGERDUTY_ROUTING_KEY", "")
    PAGERDUTY_SEVERITY = os.getenv("PAGERDUTY_SEVERITY", "error")

    TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")

    SNMP_TRAP_TARGETS = _env_list("SNMP_TRAP_TARGETS")
    SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "")
    # Under the experimental arc until you have your own enterprise number. If you
    # change it, change SKYFARER-MIB.txt to match.
    SNMP_BASE_OID = (os.getenv("SNMP_BASE_OID", "") or "1.3.6.1.3.77701").rstrip(".")

    WEBHOOKS = _env_webhook() if webhooks is None else list(webhooks)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


configure()


class PermanentFailure(Exception):
    """The request can't succeed as it stands: don't send it again."""


class RetryLater(Exception):
    """A temporary problem: leave the notice queued."""


def _request(method: str, url: str, **kwargs) -> requests.Response:
    try:
        return requests.request(method, url, timeout=30, **kwargs)
    except requests.RequestException as exc:
        # Not str(exc): that contains the URL, and a Teams webhook URL is a
        # secret that would end up in the database and on the dashboard.
        raise RetryLater(type(exc).__name__) from None


def _check(resp: requests.Response, *, retry: tuple[int, ...] = (429,)) -> None:
    if resp.ok:
        return
    message = f"HTTP {resp.status_code}"
    if resp.status_code >= 500 or resp.status_code in retry:
        raise RetryLater(message)
    raise PermanentFailure(message)


def _subject(row: dict) -> str:
    n = row["payload"]
    return f"[{n['provider']}] {n['region']} – {n['title']}"


# ─── Zendesk ────────────────────────────────────────────────────────────────

def _zd_auth() -> tuple[str, str]:
    return (f"{ZENDESK_EMAIL}/token", ZENDESK_API_TOKEN)


def _zd_url(path: str) -> str:
    return f"https://{ZENDESK_SUBDOMAIN}.zendesk.com/api/v2/{path}"


def zendesk_ticket(row: dict) -> dict:
    n = row["payload"]
    body = (
        f"**Provider:** {n['provider']}\n"
        f"**Region:** {n['region']}\n"
        f"**Link:** {n['link']}\n\n"
        f"--- Timeline ---\n\n"
        f"**Incident published:** {n['published']}\n"
        f"**Last updated:**       {n['updated']}\n"
        f"**Detected by poller:** {n['noticed']}\n\n"
        f"--- Detail ---\n\n"
        f"{n['summary']}"
    )
    ticket: dict = {
        "subject": _subject(row)[:150],
        "comment": {"body": body},
        "priority": ZD_PRIORITY,
        "tags": ZD_TAGS,
    }
    if ZD_GROUP_ID is not None:
        ticket["group_id"] = ZD_GROUP_ID
    return {"ticket": ticket}


def zendesk_resolve(row: dict) -> dict:
    n = row["payload"]
    comment = (
        f"**Incident resolved by {n['provider']}**\n\n"
        f"**Resolution detected:** {n['noticed']}\n"
        f"**Feed last updated:**   {n['updated']}\n"
        f"**Link:** {n['link']}\n\n"
        f"--- Latest detail ---\n\n"
        f"{n['summary']}\n\n"
        f"---\n\n"
        f"This ticket has been moved to **pending** for manual review and closure."
    )
    return {"ticket": {"status": "pending", "comment": {"body": comment, "public": False}}}


def zendesk_note(row: dict) -> dict:
    n = row["payload"]
    count = n.get("update_count", 1)
    heading = (f"**{count} new updates from {n['provider']}**"
               if count > 1 else f"**New update from {n['provider']}**")
    comment = (
        f"{heading}\n\n"
        f"**Latest published:** {n['published']}\n"
        f"**Link:** {n['link']}\n\n"
        f"--- Latest detail ---\n\n"
        f"{n['title']}\n\n{n['summary']}"
    )
    return {"ticket": {"comment": {"body": comment, "public": False}}}


def send_zendesk(row: dict) -> Optional[int]:
    """Returns the ticket ID when one is created."""
    # An expired token gets fixed: keep those tickets queued until it is.
    retry = (401, 403, 429)
    if row["event"] == "opened":
        resp = _request("POST", _zd_url("tickets.json"),
                        json=zendesk_ticket(row), auth=_zd_auth())
        _check(resp, retry=retry)
        return resp.json().get("ticket", {}).get("id")

    if not row["ticket_id"]:
        raise PermanentFailure("incident has no ticket")
    payload = zendesk_resolve(row) if row["event"] == "resolved" else zendesk_note(row)
    resp = _request("PUT", _zd_url(f"tickets/{row['ticket_id']}.json"),
                    json=payload, auth=_zd_auth())
    _check(resp, retry=retry)
    return None


# ─── ServiceNow ─────────────────────────────────────────────────────────────

def _sn_extra_fields() -> dict:
    """SERVICENOW_EXTRA_FIELDS: a JSON object of more fields to set on every
    new record, such as {"u_service": "Cloud hosting"}. Checked at startup."""
    if not SERVICENOW_EXTRA_FIELDS_RAW.strip():
        return {}
    value = json.loads(SERVICENOW_EXTRA_FIELDS_RAW)
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def _sn_auth() -> dict:
    if SERVICENOW_TOKEN:
        return {"headers": {"Authorization": f"Bearer {SERVICENOW_TOKEN}",
                            "Accept": "application/json"}}
    return {"auth": (SERVICENOW_USER, SERVICENOW_PASSWORD),
            "headers": {"Accept": "application/json"}}


def _sn_url(sys_id: str = "") -> str:
    path = f"{SERVICENOW_URL}/api/now/table/{SERVICENOW_TABLE}"
    return f"{path}/{sys_id}" if sys_id else f"{path}?sysparm_fields=sys_id,number"


def servicenow_record(row: dict) -> dict:
    """A new record. ServiceNow work notes and descriptions are plain text."""
    n = row["payload"]
    description = (
        f"Provider: {n['provider']}\n"
        f"Region: {n['region']}\n"
        f"Status page: {n['link']}\n\n"
        f"Incident published: {n['published']}\n"
        f"Last updated: {n['updated']}\n"
        f"Detected by Skyfarer: {n['noticed']}\n\n"
        f"{n['summary']}"
    )
    record = {
        "short_description": _subject(row)[:160],
        "description": description,
        "impact": SERVICENOW_IMPACT,
        "urgency": SERVICENOW_URGENCY,
        # Ties the record to its Skyfarer incident for searches and dedup rules.
        "correlation_id": f"skyfarer-{row['incident_id']}",
        "correlation_display": "Skyfarer",
    }
    for field, value in (("assignment_group", SERVICENOW_ASSIGNMENT_GROUP),
                         ("caller_id", SERVICENOW_CALLER),
                         ("category", SERVICENOW_CATEGORY)):
        if value:
            record[field] = value
    record.update(_sn_extra_fields())
    return record


def servicenow_note(row: dict) -> dict:
    n = row["payload"]
    count = n.get("update_count", 1)
    heading = (f"{count} new updates from {n['provider']}" if count > 1
               else f"New update from {n['provider']}")
    return {"work_notes": (f"{heading} (published {n['published']})\n"
                           f"{n['link']}\n\n{n['title']}\n\n{n['summary']}")}


def servicenow_resolve(row: dict) -> dict:
    n = row["payload"]
    notes = (f"{n['provider']} reports this incident resolved "
             f"(feed updated {n['updated']}, detected {n['noticed']}).\n"
             f"{n['link']}\n\n{n['summary']}")
    if not SERVICENOW_RESOLVE:
        return {"work_notes": notes + "\n\nLeft open for manual review and closure."}
    return {"state": SERVICENOW_RESOLVED_STATE, "close_code": SERVICENOW_CLOSE_CODE,
            "close_notes": notes, "work_notes": notes}


def send_servicenow(row: dict) -> Optional[dict]:
    """Returns {"ref": sys_id, "number": "INC..."} when a record is created."""
    # As with Zendesk, an expired password or token gets fixed: keep the
    # notices queued until it is.
    retry = (401, 403, 429)
    if row["event"] == "opened":
        resp = _request("POST", _sn_url(), json=servicenow_record(row), **_sn_auth())
        _check(resp, retry=retry)
        result = resp.json().get("result") or {}
        if not result.get("sys_id"):
            raise PermanentFailure("no sys_id in the response")
        return {"ref": result["sys_id"], "number": result.get("number") or ""}

    if not row.get("ticket_ref"):
        raise PermanentFailure("incident has no ServiceNow record")
    payload = servicenow_resolve(row) if row["event"] == "resolved" else servicenow_note(row)
    resp = _request("PATCH", _sn_url(row["ticket_ref"]), json=payload, **_sn_auth())
    _check(resp, retry=retry)
    return None


# ─── Jira Service Management ────────────────────────────────────────────────

_jsm_ids: dict[tuple, tuple[str, str]] = {}


def _jsm_kwargs() -> dict:
    return {"auth": (JSM_EMAIL, JSM_API_TOKEN),
            "headers": {"Accept": "application/json"}}


def _jsm_check(resp: requests.Response) -> None:
    """As _check, but a refused request says why: JSM's errorMessage names the
    field or transition at fault, which is what the person needs to fix."""
    if resp.ok:
        return
    # As with Zendesk and ServiceNow, an expired token gets fixed: keep the
    # notices queued until it is.
    if resp.status_code >= 500 or resp.status_code in (401, 403, 429):
        raise RetryLater(f"HTTP {resp.status_code}")
    try:
        body = resp.json()
        # The Service Desk API says errorMessage; Jira's own API errorMessages
        # and errors (by field).
        detail = body.get("errorMessage") or "; ".join(
            list(body.get("errorMessages") or [])
            + [f"{k}: {v}" for k, v in (body.get("errors") or {}).items()])
    except (ValueError, AttributeError):
        detail = ""
    raise PermanentFailure(f"HTTP {resp.status_code}" + (f": {detail}"[:300] if detail else ""))


def _jsm_get(path: str, api: str = "servicedeskapi") -> dict:
    resp = _request("GET", f"{JSM_URL}/rest/{api}/{path}", **_jsm_kwargs())
    _jsm_check(resp)
    return resp.json()


def _jsm_pick(items: list[dict], wanted: str, name_key: str, what: str) -> dict:
    """The item whose ID or name is `wanted`; a name may match without regard
    to case, or as part of a longer name ("Resolve" finds "Resolve this
    issue"). Fails with the names that do exist, so the setting is easy to fix."""
    w = wanted.strip().lower()
    for test in (lambda i: str(i.get("id")) == wanted.strip(),
                 lambda i: str(i.get(name_key, "")).lower() == w,
                 lambda i: w in str(i.get(name_key, "")).lower()):
        found = [i for i in items if test(i)]
        if found:
            return found[0]
    names = ", ".join(str(i.get(name_key)) for i in items) or "none"
    raise PermanentFailure(f"no {what} called {wanted!r} (there are: {names})"[:300])


def jsm_ids() -> tuple[str, str]:
    """The service desk ID and request type ID for JSM_PROJECT and
    JSM_REQUEST_TYPE, looked up once per setting."""
    key = (JSM_URL, JSM_PROJECT, JSM_REQUEST_TYPE)
    if key not in _jsm_ids:
        desks = _jsm_get("servicedesk?limit=100").get("values") or []
        desk = _jsm_pick(desks, JSM_PROJECT, "projectKey", "service desk with project key")
        types = _jsm_get(f"servicedesk/{desk['id']}/requesttype?limit=100").get("values") or []
        if JSM_REQUEST_TYPE:
            rtype = _jsm_pick(types, JSM_REQUEST_TYPE, "name", "request type")
        elif types:
            rtype = types[0]
        else:
            raise PermanentFailure(f"service desk {JSM_PROJECT} has no request types")
        _jsm_ids[key] = (str(desk["id"]), str(rtype["id"]))
    return _jsm_ids[key]


def _jsm_extra_fields() -> dict:
    """JSM_EXTRA_FIELDS: a JSON object of more request fields, such as
    {"priority": {"name": "High"}}. Checked when it's saved."""
    if not JSM_EXTRA_FIELDS_RAW.strip():
        return {}
    value = json.loads(JSM_EXTRA_FIELDS_RAW)
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def jsm_request(row: dict) -> dict:
    n = row["payload"]
    desk_id, type_id = jsm_ids()
    description = (
        f"Provider: {n['provider']}\n"
        f"Region: {n['region']}\n"
        f"Status page: {n['link']}\n\n"
        f"Incident published: {n['published']}\n"
        f"Last updated: {n['updated']}\n"
        f"Detected by Skyfarer: {n['noticed']}\n\n"
        f"{n['summary']}"
    )
    fields = {"summary": _subject(row)[:250], "description": description[:30000]}
    fields.update(_jsm_extra_fields())
    return {"serviceDeskId": desk_id, "requestTypeId": type_id, "requestFieldValues": fields}


def jsm_note(row: dict) -> dict:
    n = row["payload"]
    count = n.get("update_count", 1)
    heading = (f"{count} new updates from {n['provider']}" if count > 1
               else f"New update from {n['provider']}")
    return {"body": (f"{heading} (published {n['published']})\n{n['link']}\n\n"
                     f"{n['title']}\n\n{n['summary']}")[:30000], "public": False}


def _jsm_closing_note(row: dict) -> str:
    n = row["payload"]
    return (f"{n['provider']} reports this incident resolved "
            f"(feed updated {n['updated']}, detected {n['noticed']}).\n"
            f"{n['link']}\n\n{n['summary']}")[:30000]


def send_jsm(row: dict) -> Optional[dict]:
    """Returns {"ref": key, "number": key} when a request is created."""
    base = f"{JSM_URL}/rest/servicedeskapi/request"
    if row["event"] == "opened":
        resp = _request("POST", base, json=jsm_request(row), **_jsm_kwargs())
        _jsm_check(resp)
        key = resp.json().get("issueKey")
        if not key:
            raise PermanentFailure("no issueKey in the response")
        return {"ref": key, "number": key}

    key = row.get("ticket_ref")
    if not key:
        raise PermanentFailure("incident has no Jira Service Management request")
    if row["event"] == "resolved" and JSM_RESOLVE:
        # The Service Desk API only offers the transitions a customer may make,
        # which is often none: an agent's workflow transitions come from Jira's
        # own issue API. Checked before the note, so a wrong name adds nothing.
        transitions = _jsm_get(f"issue/{key}/transitions", api="api/3").get("transitions") or []
        transition = _jsm_pick(transitions, JSM_TRANSITION, "name", "transition")
        resp = _request("POST", f"{base}/{key}/comment", **_jsm_kwargs(),
                        json={"body": _jsm_closing_note(row), "public": False})
        _jsm_check(resp)
        resp = _request("POST", f"{JSM_URL}/rest/api/3/issue/{key}/transitions", **_jsm_kwargs(),
                        json={"transition": {"id": str(transition["id"])}})
        _jsm_check(resp)
        return None
    body = jsm_note(row) if row["event"] == "updated" else {
        "body": _jsm_closing_note(row) + "\n\nLeft open for manual review and closure.",
        "public": False}
    resp = _request("POST", f"{base}/{key}/comment", json=body, **_jsm_kwargs())
    _jsm_check(resp)
    return None


# ─── Freshdesk ──────────────────────────────────────────────────────────────

FRESHDESK_STATUSES = {"4": "Resolved", "5": "Closed"}


def _fd_kwargs() -> dict:
    # Freshdesk's API key is the user name; the password is ignored.
    return {"auth": (FRESHDESK_API_KEY, "X"), "headers": {"Accept": "application/json"}}


def _fd_check(resp: requests.Response) -> None:
    """As _check, but a refused request says why: Freshdesk lists each field
    at fault, such as one your helpdesk requires before a ticket can close."""
    if resp.ok:
        return
    if resp.status_code >= 500 or resp.status_code in (401, 403, 429):
        raise RetryLater(f"HTTP {resp.status_code}")
    try:
        body = resp.json()
        detail = "; ".join(f"{e.get('field', '')}: {e.get('message', '')}".strip(": ")
                           for e in body.get("errors") or []) or body.get("description", "")
    except (ValueError, AttributeError):
        detail = ""
    raise PermanentFailure(f"HTTP {resp.status_code}" + (f": {detail}"[:300] if detail else ""))


def _fd_html(text: str) -> str:
    """Freshdesk bodies are HTML: escape the provider's text, keep its lines."""
    return html.escape(text).replace("\n", "<br>")


def _fd_extra_fields() -> dict:
    """FRESHDESK_EXTRA_FIELDS: a JSON object of more ticket fields, such as
    {"type": "Incident"} or {"custom_fields": {"cf_service": "Cloud"}}."""
    if not FRESHDESK_EXTRA_FIELDS_RAW.strip():
        return {}
    value = json.loads(FRESHDESK_EXTRA_FIELDS_RAW)
    if not isinstance(value, dict):
        raise ValueError("not a JSON object")
    return value


def freshdesk_ticket(row: dict) -> dict:
    n = row["payload"]
    description = (
        f"Provider: {n['provider']}\n"
        f"Region: {n['region']}\n"
        f"Status page: {n['link']}\n\n"
        f"Incident published: {n['published']}\n"
        f"Last updated: {n['updated']}\n"
        f"Detected by Skyfarer: {n['noticed']}\n\n"
        f"{n['summary']}"
    )
    ticket = {"subject": _subject(row)[:255], "description": _fd_html(description),
              "email": FRESHDESK_REQUESTER, "status": 2, "priority": int(FRESHDESK_PRIORITY),
              "source": 2, "tags": FRESHDESK_TAGS}
    if FRESHDESK_GROUP_ID_RAW.isdigit():
        ticket["group_id"] = int(FRESHDESK_GROUP_ID_RAW)
    ticket.update(_fd_extra_fields())
    return ticket


def freshdesk_note(row: dict) -> dict:
    n = row["payload"]
    count = n.get("update_count", 1)
    heading = (f"{count} new updates from {n['provider']}" if count > 1
               else f"New update from {n['provider']}")
    return {"body": _fd_html(f"{heading} (published {n['published']})\n{n['link']}\n\n"
                             f"{n['title']}\n\n{n['summary']}"), "private": True}


def _fd_closing_note(row: dict) -> dict:
    n = row["payload"]
    text = (f"{n['provider']} reports this incident resolved "
            f"(feed updated {n['updated']}, detected {n['noticed']}).\n"
            f"{n['link']}\n\n{n['summary']}")
    if not FRESHDESK_RESOLVE:
        text += "\n\nLeft open for manual review and closure."
    return {"body": _fd_html(text), "private": True}


def send_freshdesk(row: dict) -> Optional[dict]:
    """Returns {"ref": id, "number": "#id"} when a ticket is created."""
    base = f"{FRESHDESK_URL}/api/v2/tickets"
    if row["event"] == "opened":
        resp = _request("POST", base, json=freshdesk_ticket(row), **_fd_kwargs())
        _fd_check(resp)
        ticket_id = resp.json().get("id")
        if not ticket_id:
            raise PermanentFailure("no ticket id in the response")
        return {"ref": str(ticket_id), "number": f"#{ticket_id}"}

    ticket_id = row.get("ticket_ref")
    if not ticket_id:
        raise PermanentFailure("incident has no Freshdesk ticket")
    note = freshdesk_note(row) if row["event"] == "updated" else _fd_closing_note(row)
    resp = _request("POST", f"{base}/{ticket_id}/notes", json=note, **_fd_kwargs())
    _fd_check(resp)
    if row["event"] == "resolved" and FRESHDESK_RESOLVE:
        resp = _request("PUT", f"{base}/{ticket_id}",
                        json={"status": int(FRESHDESK_RESOLVED_STATUS)}, **_fd_kwargs())
        _fd_check(resp)
    return None


# ─── Pushover ───────────────────────────────────────────────────────────────

def pushover_message(row: dict) -> dict:
    n = row["payload"]
    message = {
        "token": PUSHOVER_TOKEN,
        "user": PUSHOVER_USER,
        "title": f"{row['event'].capitalize()}: [{n['provider']}] {n['region']}"[:250],
        "message": f"{n['title']}\n\n{n['summary']}"[:1024],
        "url": n["link"][:512],
        "url_title": "Status page",
        "priority": 0,
    }
    if row["event"] == "opened":
        message["priority"] = int(PUSHOVER_PRIORITY)
        if message["priority"] == 2:  # emergency: required by the API
            message["retry"] = 60
            message["expire"] = 3600
    return message


def send_pushover(row: dict) -> None:
    resp = _request("POST", PUSHOVER_API_URL, data=pushover_message(row))
    # Pushover's rule: a 4xx, 429 included, won't succeed on retry, and
    # repeating them can get the address blocked.
    _check(resp, retry=())


# ─── PagerDuty ──────────────────────────────────────────────────────────────

def pagerduty_event(row: dict) -> dict:
    n = row["payload"]
    # A resolve must carry the same key as its trigger.
    dedup_key = f"skyfarer-{row['incident_id']}"
    if row["event"] == "resolved":
        return {"routing_key": PAGERDUTY_ROUTING_KEY, "event_action": "resolve",
                "dedup_key": dedup_key}
    return {
        "routing_key": PAGERDUTY_ROUTING_KEY,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "client": "Skyfarer",
        "links": [{"href": n["link"], "text": f"{n['provider']} status page"}],
        "payload": {
            "summary": _subject(row)[:1024],
            "source": f"{n['provider']} {n['region']}",
            "severity": PAGERDUTY_SEVERITY,
            "component": n["region"],
            "group": n["provider"],
            "class": "provider-incident",
            "custom_details": {"published": n["published"], "detail": n["summary"]},
        },
    }


def send_pagerduty(row: dict) -> None:
    resp = _request("POST", PAGERDUTY_EVENTS_URL, json=pagerduty_event(row))
    _check(resp)


# ─── Microsoft Teams ────────────────────────────────────────────────────────

def teams_card(row: dict) -> dict:
    n = row["payload"]
    heading = {"opened": "Cloud incident opened", "updated": "Cloud incident updated",
               "resolved": "Cloud incident resolved"}[row["event"]]
    color = {"opened": "Attention", "updated": "Warning", "resolved": "Good"}[row["event"]]
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.2",
                "body": [
                    {"type": "TextBlock", "text": heading, "weight": "Bolder",
                     "size": "Medium", "color": color},
                    {"type": "TextBlock", "text": n["title"], "wrap": True, "weight": "Bolder"},
                    {"type": "FactSet", "facts": [
                        {"title": "Provider", "value": n["provider"]},
                        {"title": "Region", "value": n["region"]},
                        {"title": "Published", "value": n["published"]},
                    ]},
                    {"type": "TextBlock", "text": n["summary"][:1500], "wrap": True},
                ],
                "actions": [{"type": "Action.OpenUrl", "title": "Status page",
                             "url": n["link"]}],
            },
        }],
    }


def send_teams(row: dict) -> None:
    _check(_request("POST", TEAMS_WEBHOOK_URL, json=teams_card(row)))


# ─── Webhook ────────────────────────────────────────────────────────────────

WEBHOOK_FIELDS = ("event", "incident_id", "provider", "region", "title", "summary",
                  "link", "published", "updated", "noticed", "update_count")
_PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")


def webhook_values(row: dict) -> dict:
    n = row["payload"]
    values = {field: n.get(field, "") for field in WEBHOOK_FIELDS}
    values.update(event=row["event"], incident_id=row["incident_id"],
                  update_count=n.get("update_count", 0))
    return values


def webhook_headers(hook: Webhook) -> dict:
    """The webhook's extra headers: a JSON object, such as an API key."""
    if not hook.headers.strip():
        return {}
    value = json.loads(hook.headers)
    if not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values()):
        raise ValueError("not a JSON object of strings")
    return value


def webhook_body(row: dict, hook: Webhook) -> str:
    """The request body. Without a template, a JSON document with every field.
    With one, each {{field}} in the template is replaced by its value: escaped
    for use inside a JSON string when the content type is JSON (so write
    "{{title}}" with the quotes), as plain text otherwise."""
    values = webhook_values(row)
    if not hook.template:
        return json.dumps({"source": "skyfarer", **values})
    is_json = "json" in hook.content_type

    def fill(match: re.Match) -> str:
        value = values[match.group(1)]
        if isinstance(value, int) or not is_json:
            return str(value)
        return json.dumps(str(value))[1:-1]
    return _PLACEHOLDER.sub(fill, hook.template)


def webhook_errors(hook: Webhook) -> list[str]:
    """What's wrong with a webhook's settings, as messages for the person
    editing it."""
    errors = []
    if urlsplit(hook.url).scheme not in ("http", "https") or not urlsplit(hook.url).netloc:
        errors.append("The URL must start with http:// or https://")
    if hook.method not in ("POST", "PUT", "PATCH"):
        errors.append(f"The method must be POST, PUT or PATCH, not {hook.method!r}")
    unknown = [e for e in hook.events if e not in EVENTS]
    if unknown:
        errors.append(f"Events must be from {', '.join(EVENTS)}, not {', '.join(unknown)}")
    try:
        webhook_headers(hook)
    except ValueError as exc:
        errors.append(f"Extra headers must be a JSON object of strings: {exc}")
    unknown = sorted({m.group(1) for m in _PLACEHOLDER.finditer(hook.template)}
                     - set(WEBHOOK_FIELDS))
    if unknown:
        errors.append(f"The template has unknown fields: {', '.join(unknown)} "
                      f"(known: {', '.join(WEBHOOK_FIELDS)})")
    elif hook.template and "json" in hook.content_type:
        sample = {"id": 1, "incident_id": 1, "event": "opened", "payload": {
            "provider": "AWS", "region": "eu-west-2", "title": 'A "quoted" title',
            "summary": "Line one\nline two", "link": "https://example.com/",
            "published": "", "updated": "", "noticed": ""}}
        try:
            json.loads(webhook_body(sample, hook))
        except ValueError as exc:
            errors.append(f"The template doesn't make valid JSON: {exc}")
    return errors


def webhook_for(channel: str) -> Optional[Webhook]:
    return next((h for h in WEBHOOKS if h.channel == channel), None)


def send_webhook(row: dict) -> None:
    hook = webhook_for(row["channel"])
    if hook is None:
        raise PermanentFailure("webhook no longer configured")
    body = webhook_body(row, hook).encode()
    headers = {"Content-Type": hook.content_type, "User-Agent": "skyfarer",
               "X-Skyfarer-Event": row["event"],
               "X-Skyfarer-Incident": str(row["incident_id"]), **webhook_headers(hook)}
    if hook.secret:
        # The receiver recomputes this over the raw body to check the sender.
        digest = hmac.new(hook.secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Skyfarer-Signature"] = f"sha256={digest}"
    _check(_request(hook.method, hook.url, data=body, headers=headers))


# ─── SNMP traps ─────────────────────────────────────────────────────────────

def _snmp_target(target: str) -> tuple[str, int]:
    host, _, port = target.partition(":")
    return host, int(port or 162)


def snmp_varbinds(row: dict) -> list[tuple[str, object]]:
    """(OID, value) pairs for the trap. Values are str or int."""
    n = row["payload"]
    return [
        (f"{SNMP_BASE_OID}.1.1", n["provider"]),
        (f"{SNMP_BASE_OID}.1.2", n["region"][:255]),
        (f"{SNMP_BASE_OID}.1.3", n["title"][:255]),
        (f"{SNMP_BASE_OID}.1.4", n["link"][:255]),
        (f"{SNMP_BASE_OID}.1.5", row["incident_id"]),
    ]


async def _send_traps(row: dict) -> None:
    # Imported here so that only people using traps load the SNMP stack.
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData, ContextData, NotificationType, ObjectIdentity, ObjectType,
        SnmpEngine, UdpTransportTarget, send_notification)
    from pysnmp.proto.rfc1902 import Integer32, OctetString

    oid = f"{SNMP_BASE_OID}.0.{SNMP_TRAP_NUMBERS[row['event']]}"
    varbinds = [
        ObjectType(ObjectIdentity(name),
                   Integer32(value) if isinstance(value, int) else OctetString(value))
        for name, value in snmp_varbinds(row)
    ]
    engine = SnmpEngine()
    try:
        for target in SNMP_TRAP_TARGETS:
            error, *_ = await send_notification(
                engine, CommunityData(SNMP_COMMUNITY, mpModel=1),
                await UdpTransportTarget.create(_snmp_target(target)),
                ContextData(), "trap",
                NotificationType(ObjectIdentity(oid)).add_varbinds(*varbinds))
            if error:
                raise RetryLater(f"{target}: {error}")
    finally:
        engine.close_dispatcher()


def send_snmp(row: dict) -> None:
    """A trap is one UDP packet with no acknowledgement: `sent` means it left
    this host, not that a receiver got it."""
    asyncio.run(_send_traps(row))


# ─── Channels ───────────────────────────────────────────────────────────────

SENDERS: dict[str, Callable[[dict], object]] = {
    "zendesk": send_zendesk,
    "servicenow": send_servicenow,
    "jsm": send_jsm,
    "freshdesk": send_freshdesk,
    "pushover": send_pushover,
    "pagerduty": send_pagerduty,
    "teams": send_teams,
    "snmp": send_snmp,
}

# Ticketing systems keep a record of every incident, old ones and maintenance
# included, and get every event; the others are alert channels.
TICKET_CHANNELS = ("zendesk", "servicenow", "jsm", "freshdesk")

# PagerDuty alerts have no "update" action: an event would just re-trigger.
CHANNEL_EVENTS = {
    "pushover": EVENTS,
    "pagerduty": ("opened", "resolved"),
    "teams": EVENTS,
    "snmp": EVENTS,
}


def sender_for(channel: str) -> Optional[Callable[[dict], object]]:
    if channel.startswith("webhook-"):
        return SENDERS.get(channel, send_webhook)
    return SENDERS.get(channel)


def enabled_channels() -> list[str]:
    channels = []
    if ZENDESK_SUBDOMAIN and ZENDESK_EMAIL and ZENDESK_API_TOKEN:
        channels.append("zendesk")
    if SERVICENOW_URL and (SERVICENOW_TOKEN or (SERVICENOW_USER and SERVICENOW_PASSWORD)):
        channels.append("servicenow")
    if JSM_URL and JSM_EMAIL and JSM_API_TOKEN and JSM_PROJECT:
        channels.append("jsm")
    if FRESHDESK_URL and FRESHDESK_API_KEY and FRESHDESK_REQUESTER:
        channels.append("freshdesk")
    if PUSHOVER_TOKEN and PUSHOVER_USER:
        channels.append("pushover")
    if PAGERDUTY_ROUTING_KEY:
        channels.append("pagerduty")
    if TEAMS_WEBHOOK_URL:
        channels.append("teams")
    if SNMP_TRAP_TARGETS:
        channels.append("snmp")
    channels += [h.channel for h in WEBHOOKS if h.url]
    return channels


def config_errors() -> list[str]:
    """Mistakes to report before they cause a failed delivery."""
    errors = []
    if any((ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_TOKEN)) and not all(
            (ZENDESK_SUBDOMAIN, ZENDESK_EMAIL, ZENDESK_API_TOKEN)):
        errors.append("Zendesk needs a subdomain, an agent email and an API token")
    if ZD_GROUP_ID_RAW and ZD_GROUP_ID is None:
        errors.append(f"The Zendesk group ID must be a number, not {ZD_GROUP_ID_RAW!r}")
    sn_auth = SERVICENOW_TOKEN or (SERVICENOW_USER and SERVICENOW_PASSWORD)
    if (SERVICENOW_URL or SERVICENOW_USER or SERVICENOW_PASSWORD or SERVICENOW_TOKEN) and not (
            SERVICENOW_URL and sn_auth):
        errors.append("ServiceNow needs an instance and either a user with a password, "
                      "or an OAuth token")
    for name, value in (("ServiceNow impact", SERVICENOW_IMPACT),
                        ("ServiceNow urgency", SERVICENOW_URGENCY)):
        if value not in ("1", "2", "3"):
            errors.append(f"{name} must be 1, 2 or 3, not {value!r}")
    try:
        _sn_extra_fields()
    except ValueError as exc:
        errors.append(f"ServiceNow extra fields must be a JSON object: {exc}")
    jsm = (JSM_URL, JSM_EMAIL, JSM_API_TOKEN, JSM_PROJECT)
    if any(jsm) and not all(jsm):
        errors.append("Jira Service Management needs a site, an email, an API token and a project key")
    try:
        _jsm_extra_fields()
    except ValueError as exc:
        errors.append(f"Jira Service Management extra fields must be a JSON object: {exc}")
    fd = (FRESHDESK_URL, FRESHDESK_API_KEY, FRESHDESK_REQUESTER)
    if any(fd) and not all(fd):
        errors.append("Freshdesk needs a domain, an API key and a requester email")
    if FRESHDESK_REQUESTER and "@" not in FRESHDESK_REQUESTER:
        errors.append(f"The Freshdesk requester must be an email address, not {FRESHDESK_REQUESTER!r}")
    if FRESHDESK_PRIORITY not in ("1", "2", "3", "4"):
        errors.append(f"Freshdesk priority must be 1 to 4, not {FRESHDESK_PRIORITY!r}")
    if FRESHDESK_RESOLVED_STATUS not in FRESHDESK_STATUSES:
        errors.append(f"Freshdesk's resolved status must be 4 or 5, not {FRESHDESK_RESOLVED_STATUS!r}")
    if FRESHDESK_GROUP_ID_RAW and not FRESHDESK_GROUP_ID_RAW.isdigit():
        errors.append(f"The Freshdesk group ID must be a number, not {FRESHDESK_GROUP_ID_RAW!r}")
    try:
        _fd_extra_fields()
    except ValueError as exc:
        errors.append(f"Freshdesk extra fields must be a JSON object: {exc}")
    if bool(PUSHOVER_TOKEN) != bool(PUSHOVER_USER):
        errors.append("Pushover needs both an application token and a user key")
    if PUSHOVER_PRIORITY not in ("-2", "-1", "0", "1", "2"):
        errors.append(f"Pushover priority must be -2 to 2, not {PUSHOVER_PRIORITY!r}")
    if PAGERDUTY_SEVERITY not in PAGERDUTY_SEVERITIES:
        errors.append(f"PagerDuty severity must be one of {', '.join(PAGERDUTY_SEVERITIES)}, "
                      f"not {PAGERDUTY_SEVERITY!r}")
    if SNMP_TRAP_TARGETS and not SNMP_COMMUNITY:
        errors.append("SNMP traps need a community")
    for target in SNMP_TRAP_TARGETS:
        try:
            _snmp_target(target)
        except ValueError:
            errors.append(f"An SNMP receiver has a bad port: {target!r}")
    unknown = [e for e in NOTIFY_EVENTS if e not in EVENTS]
    if unknown:
        errors.append(f"Alert events must be from {', '.join(EVENTS)}, not {', '.join(unknown)}")
    for hook in WEBHOOKS:
        errors += [f"Webhook {hook.name!r}: {e}" for e in webhook_errors(hook)]
    return errors


# ─── Queue ──────────────────────────────────────────────────────────────────

def enqueue(conn, incident_id: int, event: str, payload: dict, *, alert: bool = True) -> None:
    """Queue a notice for each channel that should get it. `alert` False keeps
    an incident away from the channels that interrupt people; the ticketing
    systems record everything. Those channels only hear how an incident ends
    if they heard it begin, so a suppressed incident stays silent throughout."""
    for channel in enabled_channels():
        if channel not in TICKET_CHANNELS:
            hook = webhook_for(channel)
            wanted = (hook.events or NOTIFY_EVENTS) if hook else NOTIFY_EVENTS
            if event not in wanted or event not in CHANNEL_EVENTS.get(channel, EVENTS):
                continue
            if event == "opened":
                if not alert:
                    continue
            elif not db.was_notified(conn, incident_id, channel):
                continue
        db.add_notification(conn, incident_id=incident_id, channel=channel,
                            event=event, payload=payload)


def deliver_pending() -> int:
    """Send what's due. Returns how many were sent. Each result is saved as it
    happens, so a crash partway through doesn't repeat earlier sends."""
    now = datetime.now(timezone.utc)
    with db.get_conn() as conn:
        rows = db.pending_notifications(conn)

    sent = 0
    held: set[tuple[int, str]] = set()  # keeps each incident's notices in order
    new_tickets: dict[int, int] = {}    # Zendesk tickets created during this pass
    new_refs: dict[tuple[int, str], str] = {}  # other ticketing systems' records
    for row in rows:
        key = (row["incident_id"], row["channel"])
        if key in held:
            continue
        if row["next_attempt_at"] > now:
            held.add(key)
            continue

        # `rows` was read before this pass, so a ticket opened a moment ago
        # isn't in it, and the same pass can hold that ticket's first update.
        row["ticket_id"] = row["ticket_id"] or new_tickets.get(row["incident_id"])
        row["ticket_ref"] = row.get("ticket_ref") or new_refs.get(key)

        sender = sender_for(row["channel"]) if row["channel"] in enabled_channels() else None
        try:
            if sender is None:
                raise PermanentFailure("channel no longer configured")
            result = sender(row)
        except PermanentFailure as exc:
            log.error("%s %s failed for good: %s", row["channel"], row["event"], exc)
            with db.get_conn() as conn:
                db.notification_failed(conn, row["id"], str(exc))
        except Exception as exc:
            error = str(exc) if isinstance(exc, RetryLater) else type(exc).__name__
            held.add(key)
            with db.get_conn() as conn:
                if now - row["created_at"] > timedelta(hours=NOTIFY_RETRY_HOURS):
                    log.error("%s %s gave up: %s", row["channel"], row["event"], error)
                    db.notification_failed(conn, row["id"], f"gave up: {error}")
                else:
                    log.warning("%s %s will retry: %s", row["channel"], row["event"], error)
                    delay = min(60 * 2 ** row["attempts"], 3600)
                    db.notification_retry(conn, row["id"], error,
                                          now + timedelta(seconds=delay))
        else:
            sent += 1
            log.info("%s %s sent for incident %s", row["channel"], row["event"],
                     row["incident_id"])
            with db.get_conn() as conn:
                db.notification_sent(conn, row["id"])
                if row["channel"] == "zendesk" and result:
                    db.set_ticket(conn, row["incident_id"], result)
                    new_tickets[row["incident_id"]] = result
                elif row["channel"] in TICKET_CHANNELS and result:
                    db.set_external_ticket(conn, row["incident_id"], row["channel"],
                                           ref=result["ref"], number=result["number"])
                    new_refs[key] = result["ref"]
    return sent
