#!/usr/bin/env bash
# Власний CA (RSA-4096) -> серверний сертифікат (ECDSA P-256) з SAN.
# Використання: bash server/scripts/gencerts.sh [додаткові IP через кому]
#   приклад: bash server/scripts/gencerts.sh 172.28.0.10,192.168.56.10
set -euo pipefail
EXTRA_IPS="${1:-}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$OUT"
cd "$OUT"
umask 077

SAN="DNS:localhost,DNS:server,DNS:secure-server,IP:127.0.0.1"
IFS=',' read -ra IPS <<< "$EXTRA_IPS"
for ip in "${IPS[@]}"; do [ -n "$ip" ] && SAN="$SAN,IP:$ip"; done

# 1) Кореневий CA
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -key ca.key -sha256 -days 1825 \
  -subj "/C=UA/O=Kubg PR5-7 Demo/CN=SecureNetApp Demo Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.crt

# 2) Серверний ключ ECDSA P-256 + CSR
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/C=UA/O=Kubg PR5-7 Demo/CN=secure-server" -out server.csr

# 3) Підпис CA (398 днів — максимум для публічних сертифікатів)
cat > server.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$SAN
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 398 -sha256 -extfile server.ext 2>/dev/null
rm -f server.csr server.ext
chmod 600 ca.key server.key
chmod 644 ca.crt server.crt

openssl verify -CAfile ca.crt server.crt
echo "SAN: $SAN"
echo "Certificates generated in $OUT"
