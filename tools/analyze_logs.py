"""Аналізатор журналу server/logs/app.jsonl.

Приклади:
  python tools/analyze_logs.py                         # зведення + аномалії
  python tools/analyze_logs.py --event auth.fail --user alice
  python tools/analyze_logs.py --category security --since 30m
  python tools/analyze_logs.py --status 429 --list
  python tools/analyze_logs.py --since 2026-11-25T20:00:00Z --until 2026-11-25T21:00:00Z --json
"""
import argparse
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from server.logfilter import filter_events, read_events  # noqa: E402

SUSPICIOUS = ("auth.fail", "mfa.fail", "token.invalid", "access.forbidden", "access.denied",
              "rate.limit", "lockout.start", "lockout.active", "tls.required", "token.refresh_fail")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default="server/logs/app.jsonl")
    ap.add_argument("--event", help="префікс події, напр. auth / auth.fail / rate")
    ap.add_argument("--category", help="request|auth|session|access|security|admin|error|system")
    ap.add_argument("--user"); ap.add_argument("--ip"); ap.add_argument("--status", type=int)
    ap.add_argument("--level"); ap.add_argument("--since"); ap.add_argument("--until")
    ap.add_argument("--list", action="store_true", help="вивести відфільтровані події")
    ap.add_argument("--json", action="store_true", help="вивести як JSONL")
    ap.add_argument("--threshold", type=int, default=5, help="поріг аномалій на IP/користувача")
    a = ap.parse_args()

    ev = list(filter_events(read_events(a.path), event=a.event, category=a.category, user=a.user, ip=a.ip,
                            status=a.status, level=a.level, since=a.since, until=a.until))
    if a.json:
        for e in ev:
            print(json.dumps(e, ensure_ascii=False))
        return
    if a.list:
        for e in ev:
            extra = e.get("reason") or e.get("path") or ""
            st = e.get("status", "")
            print(f"{e['ts']}  {e['level']:<7} {e['event']:<17} user={str(e.get('user')):<6} ip={e.get('ip')} {st} {extra}")
        print(f"— відібрано подій: {len(ev)}")
        return

    print(f"Подій після фільтра: {len(ev)}" + (f"  (з {ev[0]['ts']} по {ev[-1]['ts']})" if ev else ""))
    by_cat = collections.Counter(e.get("category") for e in ev)
    print("\nЗа категоріями:", ", ".join(f"{k}={v}" for k, v in by_cat.most_common()))
    by_ev = collections.Counter(e["event"] for e in ev if e["event"] != "http.request")
    print("\nТоп подій (без http.request):")
    for k, v in by_ev.most_common(12):
        print(f"  {k:<20} {v:>5}")
    st = collections.Counter(e.get("status") for e in ev if e["event"] == "http.request")
    print("\nHTTP-статуси:", ", ".join(f"{k}={v}" for k, v in sorted(st.items(), key=lambda x: str(x[0]))))
    lat = sorted(e["ms"] for e in ev if e["event"] == "http.request" and "ms" in e)
    if lat:
        print(f"Латентність обробки на сервері: p50={lat[len(lat)//2]:.2f} мс, p95={lat[int(len(lat)*0.95)]:.2f} мс")

    sus = [e for e in ev if e["event"] in SUSPICIOUS]
    print(f"\nПідозрілих подій: {len(sus)}")
    by_ip = collections.Counter(e.get("ip") for e in sus)
    by_user = collections.Counter(e.get("user") for e in sus if e.get("user"))
    print("  Топ IP-порушників  :", ", ".join(f"{k}({v})" for k, v in by_ip.most_common(5)) or "—")
    print("  Топ облік. записів :", ", ".join(f"{k}({v})" for k, v in by_user.most_common(5)) or "—")
    alerts = []
    for ip, n in by_ip.items():
        if n >= a.threshold:
            alerts.append(f"IP {ip}: {n} підозрілих подій (≥{a.threshold}) — можливий brute force/сканування")
    locks = [e for e in ev if e["event"] == "lockout.start"]
    for e in locks:
        alerts.append(f"Блокування облікового запису {e.get('user')} на {e.get('seconds')} с о {e['ts']}")
    forged = [e for e in ev if e["event"] == "token.invalid" and e.get("reason") in ("bad_signature", "bad_algorithm", "malformed")]
    if forged:
        alerts.append(f"{len(forged)} спроб підробки JWT (bad_signature/bad_algorithm/malformed)")
    esc = [e for e in ev if e["event"] == "access.forbidden"]
    if esc:
        alerts.append(f"{len(esc)} спроб доступу до адмін-функцій без прав: " + ", ".join(sorted({str(e.get('user')) for e in esc})))
    print("\nАЛЕРТИ:" if alerts else "\nАлертів немає")
    for x in alerts:
        print("  ⚠", x)


if __name__ == "__main__":
    main()
