"""Фільтрація JSONL-журналу за типом/категорією, користувачем, IP, статусом і часом."""
import json
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional


def parse_time(s: Optional[str]) -> Optional[datetime]:
    """ISO-8601 ('2026-11-25T20:00:00Z') або відносний час ('15m', '2h', '1d')."""
    if not s:
        return None
    s = s.strip()
    if s[-1] in "smhd" and s[:-1].isdigit():
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[s[-1]]
        return datetime.now(timezone.utc) - timedelta(seconds=int(s[:-1]) * mult)
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def read_events(path: str) -> Iterator[dict]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def filter_events(events: Iterable[dict], event: str = None, category: str = None, user: str = None,
                  ip: str = None, status: int = None, level: str = None,
                  since: str = None, until: str = None) -> Iterator[dict]:
    t0, t1 = parse_time(since), parse_time(until)
    for e in events:
        if event and not str(e.get("event", "")).startswith(event):
            continue
        if category and e.get("category") != category:
            continue
        if user and e.get("user") != user:
            continue
        if ip and e.get("ip") != ip:
            continue
        if status is not None and e.get("status") != status:
            continue
        if level and e.get("level") != level.upper():
            continue
        if t0 or t1:
            try:
                ts = parse_time(e["ts"])
            except (KeyError, ValueError):
                continue
            if (t0 and ts < t0) or (t1 and ts > t1):
                continue
        yield e
