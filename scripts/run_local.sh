#!/usr/bin/env bash
# Локальний стенд із двома "вузлами" на loopback-адресах:
#   сервер 127.0.0.10 (HTTP 8080 / HTTPS 8443), клієнт ходить з 127.0.0.20
set -euo pipefail
cd "$(dirname "$0")/.."
SRV=${SRV_IP:-127.0.0.10}
export JWT_SECRET=${JWT_SECRET:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')}
[ -f server/certs/server.crt ] || bash server/scripts/gencerts.sh "$SRV"
[ -f server/users.json ] || python3 -m server.scripts.create_users --reset
uvicorn server.app:app --host "$SRV" --port 8080 --no-access-log > /tmp/sna-http.log 2>&1 &
echo $! > /tmp/sna-http.pid
uvicorn server.app:app --host "$SRV" --port 8443 --no-access-log \
  --ssl-keyfile server/certs/server.key --ssl-certfile server/certs/server.crt > /tmp/sna-https.log 2>&1 &
echo $! > /tmp/sna-https.pid
sleep 2
echo "HTTP  : http://$SRV:8080   HTTPS : https://$SRV:8443"
