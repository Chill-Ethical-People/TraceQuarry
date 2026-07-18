from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


SYSLOG_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
APACHE_RE = re.compile(r"^\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}$")
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def to_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_epoch(value: str | int | float) -> str | None:
    try:
        ts = int(float(value))
    except (TypeError, ValueError):
        return None
    if ts <= 0:
        return None
    return to_utc_iso(datetime.fromtimestamp(ts, tz=timezone.utc))


def parse_iso(value: str) -> str | None:
    text = value.strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        return to_utc_iso(datetime.fromisoformat(normalized))
    except ValueError:
        pass
    try:
        return to_utc_iso(parsedate_to_datetime(text))
    except Exception:
        return None


def parse_syslog(value: str, year: int | None = None, timezone_name: str = "UTC") -> str | None:
    match = SYSLOG_RE.match(value)
    if not match:
        return None
    now = datetime.now(timezone.utc)
    try:
        tz = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        tz = timezone.utc
    dt = datetime(year or now.year, MONTHS[match.group("mon")], int(match.group("day")),
                  *[int(part) for part in match.group("time").split(":")], tzinfo=tz)
    return to_utc_iso(dt)


def parse_apache(value: str) -> str | None:
    text = value.strip()
    if not APACHE_RE.match(text):
        return None
    try:
        return to_utc_iso(datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        return None


def parse_last_style(month: str, day: str, time_value: str, year: int | None, timezone_name: str = "UTC") -> str | None:
    if month not in MONTHS:
        return None
    now = datetime.now(timezone.utc)
    try:
        tz = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        tz = timezone.utc
    hour, minute = [int(part) for part in time_value.split(":", 1)]
    dt = datetime(year or now.year, MONTHS[month], int(day), hour, minute, tzinfo=tz)
    return to_utc_iso(dt)


def parse_any(value: str, year: int | None = None, timezone_name: str = "UTC") -> str | None:
    return parse_iso(value) or parse_apache(value) or parse_syslog(value, year=year, timezone_name=timezone_name)
