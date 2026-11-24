"""
history.py
~~~~~~~~~~
Availability and SLA reporting from the incidents we've already stored.

No new table: the numbers come from incidents' own feed-reported start and end
times, and the targets are ordinary settings edited under Settings > SLA
targets. The maths here is deliberately pure so it can be tested without a
database; the dashboard supplies the rows and the stored target values.

Maintenance is listed but excluded from downtime. Overlapping incidents at one
provider are counted once, so two regions failing together don't read as twice
the outage.
"""

from __future__ import annotations

import csv
import io
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Optional

DEFAULT_TARGET = 99.90
TARGET_PREFIX = "SLA_TARGET_"

RANGES = (("30d", "30 days"), ("quarter", "Quarter"), ("year", "Year"),
          ("custom", "Custom"))
RANGE_DAYS = {"30d": 30, "quarter": 90, "year": 365}
MAX_SHOWN = 100


def target_key(provider: str) -> str:
    return TARGET_PREFIX + provider.upper()


def target_value(values: dict, provider: str) -> float:
    """A stored target as a percentage, or the default when absent/invalid."""
    raw = (values.get(target_key(provider)) or "").strip()
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_TARGET
    return value if 0 <= value <= 100 else DEFAULT_TARGET


def pct(value: float) -> str:
    return "100%" if abs(value - 100) < 0.005 else f"{value:.2f}%"


def minutes_label(minutes: float) -> str:
    if minutes < 1:
        return "<1m"
    rounded = round(minutes)
    if rounded < 60:
        return f"{rounded}m"
    hours, mins = divmod(rounded, 60)
    if hours < 48:
        return f"{hours}h {mins:02d}m"
    return f"{hours // 24}d"


def _date(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def window(range_key: str, from_date: str = "", to_date: str = "",
           now: Optional[datetime] = None) -> tuple[datetime, datetime]:
    """Half-open [start, end) window. 'to' dates are inclusive: +1 day."""
    now = now or datetime.now(timezone.utc)
    if range_key == "custom":
        start = _date(from_date) or (now - timedelta(days=RANGE_DAYS["quarter"]))
        end = _date(to_date)
        end = end + timedelta(days=1) if end else None
        if end is None or end <= start:
            end = now
        return start, end
    return now - timedelta(days=RANGE_DAYS.get(range_key, RANGE_DAYS["quarter"])), now


def _dt(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _in_region(wanted: str, regions: str) -> bool:
    """Region tags are stored as a comma-separated string; a whole-word match
    avoids 'LON' picking up 'LONDON'."""
    import re
    return bool(re.search(r"(?<![A-Za-z0-9-])" + re.escape(wanted)
                          + r"(?![A-Za-z0-9-])", regions or "", re.I))


def _interval(row: dict, start: datetime, end: datetime, now: datetime):
    """The part of an incident inside the window, or None if there is none."""
    detected = _dt(row.get("detected_at"))
    if detected is None:
        return None
    begin = max(detected, start)
    resolved = _dt(row.get("resolved_at")) if row.get("state") == "resolved" else None
    finish = resolved or now
    if finish < begin:  # scheduled work that hasn't started yet
        return None
    finish = min(finish, end)
    return (begin, finish) if finish > begin else None


def _merged_minutes(intervals: list[tuple[datetime, datetime]]) -> float:
    total = 0.0
    current: Optional[tuple[datetime, datetime]] = None
    for begin, finish in sorted(intervals):
        if current and begin <= current[1]:
            current = (current[0], max(current[1], finish))
        else:
            if current:
                total += (current[1] - current[0]).total_seconds() / 60
            current = (begin, finish)
    if current:
        total += (current[1] - current[0]).total_seconds() / 60
    return total


def _months(start: datetime, end: datetime) -> list[str]:
    keys = []
    cursor = start.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    last = end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    while cursor <= last:
        keys.append(cursor.strftime("%Y-%m"))
        cursor = (cursor + timedelta(days=32)).replace(day=1)
    return keys


def _month_of(value: datetime) -> datetime:
    return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next_month(value: datetime) -> datetime:
    return (_month_of(value) + timedelta(days=32)).replace(day=1)


def monthly(items: list[dict], start: datetime, end: datetime, target: float) -> list[dict]:
    """Downtime per month, splitting incidents that cross a month boundary."""
    buckets = OrderedDict((key, 0.0) for key in _months(start, end))
    for item in items:
        if item["maintenance"]:
            continue
        cursor, finish = item["begin"], item["end"]
        while cursor < finish:
            stop = min(_next_month(cursor), finish)
            key = cursor.strftime("%Y-%m")
            if key in buckets:
                buckets[key] += (stop - cursor).total_seconds() / 60
            cursor = stop
    peak = max(buckets.values(), default=0) or 1
    out = []
    for key, value in buckets.items():
        allowed = (_next_month(datetime.strptime(key, "%Y-%m").replace(tzinfo=timezone.utc))
                   - datetime.strptime(key, "%Y-%m").replace(tzinfo=timezone.utc)).total_seconds() / 60
        allowed *= (100 - target) / 100
        out.append({"key": key,
                    "label": datetime.strptime(key, "%Y-%m").strftime("%b %y"),
                    "minutes": round(value),
                    "height": max(4, round(80 * value / peak)) if value else 4,
                    "tone": "bad" if value > allowed else "warn" if value else ""})
    return out


def build(rows: list[dict], start: datetime, end: datetime, targets: dict, *,
          provider: str = "all", region: str = "all",
          now: Optional[datetime] = None) -> dict:
    """Turn incident rows into everything the History page needs.

    `targets` maps provider name to its SLA percentage. Providers in it are the
    ones in view, so the availability average and error budget cover the same
    set as the table, including providers with no incidents in this window.
    """
    now = now or end
    span_minutes = max((end - start).total_seconds() / 60, 0)
    items = []
    for row in rows:
        name = row["provider"]
        if provider != "all" and name != provider:
            continue
        if region != "all" and not _in_region(region, row.get("region") or ""):
            continue
        interval = _interval(row, start, end, now)
        if not interval:
            continue
        begin, finish = interval
        maintenance = bool(row.get("is_maintenance"))
        ongoing = row.get("state") == "open" and not maintenance
        notes = []
        if _dt(row.get("detected_at")) < start:
            notes.append("Started before this window")
        if maintenance:
            notes.append("Excluded from downtime")
        elif ongoing:
            notes.append("Ongoing")
        elapsed = (finish - begin).total_seconds() / 60
        items.append({
            "provider": name, "region": row.get("region") or "",
            "title": row.get("title") or "", "link": row.get("link") or "",
            "begin": begin, "end": finish, "minutes": elapsed,
            "duration": minutes_label(elapsed),
            "kind": "maintenance" if maintenance else "ongoing" if ongoing else "incident",
            "maintenance": maintenance, "notes": "; ".join(notes),
            "started_before": _dt(row.get("detected_at")) < start,
        })
    items.sort(key=lambda i: i["begin"], reverse=True)

    summaries = []
    total_downtime = 0.0
    intervals_by_provider: dict[str, list] = {}
    for item in items:
        if not item["maintenance"]:
            intervals_by_provider.setdefault(item["provider"], []).append((item["begin"], item["end"]))
    for name, target in targets.items():
        if provider != "all" and name != provider:
            continue
        own = [i for i in items if i["provider"] == name]
        downtime = _merged_minutes(intervals_by_provider.get(name, []))
        total_downtime += downtime
        availability = 100 - 100 * downtime / span_minutes if span_minutes else 100.0
        n_incidents = sum(1 for i in own if not i["maintenance"])
        n_maintenance = sum(1 for i in own if i["maintenance"])
        if not n_incidents and n_maintenance:
            status, tone = "Maintenance only", "info"
        elif availability + 1e-9 >= target:
            status, tone = "Within target", "ok"
        else:
            status, tone = "Below target", "bad"
        summaries.append({
            "provider": name, "regions": ", ".join(sorted({r for i in own
                                                           for r in i["region"].split(",") if r.strip()})),
            "incidents": n_incidents, "maintenance": n_maintenance,
            "downtime": downtime, "downtime_label": minutes_label(downtime),
            "availability": availability, "availability_label": pct(availability),
            "target": target, "target_label": pct(target), "status": status, "tone": tone,
        })
    summaries.sort(key=lambda s: s["provider"])

    targets_in_view = [t for p, t in targets.items() if provider == "all" or p == provider]
    target = min(targets_in_view, default=DEFAULT_TARGET)
    n_providers = len(targets_in_view)
    budget = span_minutes * (100 - target) / 100 * n_providers
    availability = (100 - 100 * total_downtime / (span_minutes * n_providers)
                    if span_minutes and n_providers else 100.0)
    used = 100 * total_downtime / budget if budget else 0.0
    faults = [i for i in items if not i["maintenance"]]
    longest = max(faults, key=lambda i: i["minutes"]) if faults else None

    return {
        "start": start, "end": end,
        "items": items, "shown": items[:MAX_SHOWN],
        "incident_count": len(faults), "maintenance_count": len(items) - len(faults),
        "downtime": total_downtime, "downtime_label": minutes_label(total_downtime),
        "availability": availability, "availability_label": pct(availability),
        "target": target, "target_label": pct(target),
        "budget": budget, "budget_label": minutes_label(budget),
        "used": used, "used_label": f"{used:.0f}%",
        "longest": longest,
        "providers": summaries, "months": monthly(items, start, end, target),
        "n_providers": n_providers,
    }


CSV_COLUMNS = ("Started (UTC)", "Ended (UTC)", "Provider", "Region", "Incident",
               "Type", "Duration (min)", "Notes", "Link")


def _cell(text: str) -> str:
    """Provider text such as titles is untrusted: stop a spreadsheet reading a
    leading = + - @ as a formula."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def csv_export(report: dict) -> str:
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for item in report["items"]:
        writer.writerow([
            item["begin"].strftime("%Y-%m-%d %H:%M"),
            item["end"].strftime("%Y-%m-%d %H:%M"),
            _cell(item["provider"]), _cell(item["region"]), _cell(item["title"]),
            item["kind"], f"{item['minutes']:.1f}", item["notes"], _cell(item["link"]),
        ])
    return out.getvalue()
