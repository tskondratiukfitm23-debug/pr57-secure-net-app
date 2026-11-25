"""Пасивний «підслуховувач» на шляху (on-path observer) для демонстрації різниці HTTP vs HTTPS.

Ретранслює TCP LISTEN -> TARGET і записує в лог усе, що бачить у каналі (як tcpdump -A).
  python tools/tap.py --listen 127.0.0.10:9080 --target 127.0.0.10:8080 --out /tmp/tap80.txt
Лише для лабораторного стенду.
"""
import argparse
import socket
import threading


def pump(src, dst, out, tag, lock):
    while True:
        try:
            data = src.recv(65536)
        except OSError:
            break
        if not data:
            break
        with lock, open(out, "a", encoding="utf-8") as f:
            text = "".join(chr(b) if 32 <= b < 127 or b in (10, 13) else "." for b in data)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                pass
            f.write(f"--- {tag} {len(data)} bytes ---\n{text}\n")
        try:
            dst.sendall(data)
        except OSError:
            break
    for s in (src, dst):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    lh, lp = a.listen.rsplit(":", 1)
    th, tp = a.target.rsplit(":", 1)
    lock = threading.Lock()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lh, int(lp)))
    srv.listen(16)
    while True:
        c, _ = srv.accept()
        t = socket.create_connection((th, int(tp)))
        threading.Thread(target=pump, args=(c, t, a.out, "client->server", lock), daemon=True).start()
        threading.Thread(target=pump, args=(t, c, a.out, "server->client", lock), daemon=True).start()


if __name__ == "__main__":
    main()
