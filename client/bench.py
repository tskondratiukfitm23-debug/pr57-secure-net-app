"""Порівняння продуктивності HTTP vs HTTPS (POST /echo-http).

Два сценарії для кожного протоколу:
  * keep-alive — одна сесія, TLS-рукостискання лише раз (типово для API-клієнтів);
  * new-conn   — нове TCP(+TLS) з'єднання на кожен запит (найгірший випадок).
Результат: p50/p95/p99, середнє, req/s -> client/bench_results.md і .csv
"""
import argparse
import csv
import os
import platform
import statistics
import time

import requests


def run(url, n, verify, keepalive, payload):
    lat = []
    s = requests.Session() if keepalive else None
    for _ in range(5):  # прогрів
        (s or requests).post(url, json={"msg": payload}, verify=verify, timeout=10)
    t0 = time.perf_counter()
    for _ in range(n):
        t = time.perf_counter()
        if keepalive:
            r = s.post(url, json={"msg": payload}, verify=verify, timeout=10)
        else:
            with requests.Session() as one:
                r = one.post(url, json={"msg": payload}, verify=verify, timeout=10,
                             headers={"Connection": "close"})
        r.raise_for_status()
        lat.append((time.perf_counter() - t) * 1000)
    total = time.perf_counter() - t0
    q = statistics.quantiles(lat, n=100)
    return {"p50": statistics.median(lat), "p95": q[94], "p99": q[98], "mean": statistics.fmean(lat),
            "rps": n / total}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("SNA_HOST", "127.0.0.1"))
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--ca", default=os.environ.get("SNA_CA", "server/certs/ca.crt"))
    ap.add_argument("--size", type=int, default=256, help="розмір повідомлення, байт")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "bench_results"))
    a = ap.parse_args()
    payload = "x" * a.size
    rows = []
    for proto, url, verify in (("HTTP", f"http://{a.host}:8080/echo-http", True),
                               ("HTTPS", f"https://{a.host}:8443/echo-http", a.ca)):
        for ka in (True, False):
            mode = "keep-alive" if ka else "new-conn"
            m = run(url, a.n, verify, ka, payload)
            rows.append({"proto": proto, "mode": mode, **m})
            print(f"{proto:<5} {mode:<10} n={a.n} p50={m['p50']:.2f}ms p95={m['p95']:.2f}ms "
                  f"p99={m['p99']:.2f}ms mean={m['mean']:.2f}ms {m['rps']:.0f} req/s")

    def find(p, mo):
        return next(r for r in rows if r["proto"] == p and r["mode"] == mo)
    lines = [f"Середовище: {platform.system()} {platform.release()}, Python {platform.python_version()}, "
             f"n={a.n}, payload={a.size} Б, host={a.host}", "",
             "| Протокол | Режим | p50, мс | p95, мс | p99, мс | Середнє, мс | req/s |",
             "|---|---|---:|---:|---:|---:|---:|"]
    for r in rows:
        lines.append(f"| {r['proto']} | {r['mode']} | {r['p50']:.2f} | {r['p95']:.2f} | {r['p99']:.2f} | "
                     f"{r['mean']:.2f} | {r['rps']:.0f} |")
    lines.append("")
    for mo in ("keep-alive", "new-conn"):
        h, s = find("HTTP", mo), find("HTTPS", mo)
        lines.append(f"- {mo}: накладні витрати TLS p50 = +{s['p50'] - h['p50']:.2f} мс "
                     f"({(s['p50'] / h['p50'] - 1) * 100:.0f} %), пропускна здатність {s['rps'] / h['rps'] * 100:.0f} % від HTTP")
    with open(a.out + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    with open(a.out + ".csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows([{k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items()} for r in rows])
    print("\n".join(lines[-2:]))
    print(f"→ {a.out}.md, {a.out}.csv")


if __name__ == "__main__":
    main()
