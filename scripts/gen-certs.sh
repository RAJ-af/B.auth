#!/bin/sh
set -eu
cd /certs
[ -s rootCA.pem ] && [ -s server.crt ] && echo "certs exist, skipping" && exit 0

apk add -q openssl >/dev/null 2>&1

openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
  -keyout rootCA.key -out rootCA.pem -subj "/CN=Sovereign Mail Dev CA"

cat > server.ext <<'EOF'
subjectAltName=DNS:localhost,DNS:keycloak,DNS:dovecot,DNS:postfix,DNS:rspamd,DNS:mail.sovereign.mail,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=mail.sovereign.mail"
openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile server.ext
chmod 644 rootCA.pem server.crt; chmod 600 server.key rootCA.key
echo "CA + server cert generated"