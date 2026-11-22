#!/bin/sh
set -eu

host=${1:-localhost}
output=${2:-certs/local}
case "$host" in
    ''|*[!A-Za-z0-9.-]*) echo "Use a DNS hostname as the first argument" >&2; exit 2 ;;
esac

umask 077
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
trap 'exit 1' HUP INT TERM

openssl req -x509 -newkey rsa:2048 -nodes -days 7 -sha256 \
    -subj "/CN=QUIC PaaS test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$temp/ca.key" -out "$temp/ca.crt"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$host" \
    -keyout "$temp/server.key" -out "$temp/server.csr"
cat >"$temp/extensions" <<CONFIG
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$host
CONFIG
openssl x509 -req -in "$temp/server.csr" -days 7 -sha256 \
    -CA "$temp/ca.crt" -CAkey "$temp/ca.key" -CAcreateserial \
    -extfile "$temp/extensions" -out "$temp/server.crt"
mkdir "$output"
cp "$temp/ca.crt" "$temp/server.crt" "$temp/server.key" "$output/"
# These files can be mounted individually and read by the non-root container user.
# Keep the output directory private on the host.
chmod 0444 "$output/ca.crt" "$output/server.key" "$output/server.crt"
