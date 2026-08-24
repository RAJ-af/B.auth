#!/usr/bin/env bash
# Generate the DKIM signing key for MAIL_DOMAIN (selector "default") inside the
# dkim_keys volume and write docs/dns-records.txt with the DNS records to apply
# at real-domain cutover. Idempotent: an existing key short-circuits keygen,
# but dns-records.txt is regenerated on every run.
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
# dkim_keygen runs inside the rspamd container, so it must be up. In the
# clean-room quickstart the core stage starts only cert-init/openldap/postgres/
# keycloak, so start rspamd here if the caller hasn't already.
docker compose up -d rspamd
for _ in $(seq 1 30); do
  docker compose exec -T rspamd true 2>/dev/null && break
  sleep 1
done
# The rspamd image runs as uid 11333 (_rspamd); the dkim_keys volume starts
# root-owned, so create the target dir and hand it to _rspamd first.
docker compose exec -T --user root rspamd sh -c \
  'mkdir -p /var/lib/rspamd/dkim && chown -R _rspamd:_rspamd /var/lib/rspamd/dkim'
if docker compose exec -T rspamd test -f /var/lib/rspamd/dkim/default.private.key; then
  echo "DKIM key exists"; else
  docker compose exec -T rspamd rspamadm dkim_keygen -d "${MAIL_DOMAIN}" -s default \
    -k /var/lib/rspamd/dkim/default.private.key > /tmp/dkim_out.txt
fi

# Emit the DKIM TXT record. Preferred source is the record file written by
# rspamadm dkim_keygen; rspamd 3.9 does not create default.public.dns.txt, so
# fall back to extracting the public key from the private key with openssl and
# wrapping it per DKIM TXT-record syntax. Only PUBLIC material is ever printed;
# the private key stays inside the dkim_keys volume.
emit_dkim_record() {
  local from_file pub_b64
  from_file="$(docker compose exec -T rspamd sh -c 'tr -d "\n" < /var/lib/rspamd/dkim/default.public.dns.txt' 2>/dev/null || true)"
  if [ -n "${from_file}" ]; then
    printf '%s\n' "${from_file}"
    return
  fi
  pub_b64="$(docker compose exec -T rspamd sh -c \
    'openssl rsa -in /var/lib/rspamd/dkim/default.private.key -pubout -outform DER 2>/dev/null | base64 -w0')"
  echo "default._domainkey.${MAIL_DOMAIN}. IN TXT \"v=DKIM1;k=rsa;p=${pub_b64}\""
}

{
  echo "# DNS records for ${MAIL_DOMAIN} (apply at real-domain cutover)"
  echo "# SPF:"
  echo "${MAIL_DOMAIN}. IN TXT \"v=spf1 ip4:<VPS_IP> -all\""
  echo "# DMARC:"
  echo "_dmarc.${MAIL_DOMAIN}. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@${MAIL_DOMAIN}\""
  echo "# DKIM (selector: default):"
  emit_dkim_record
} > docs/dns-records.txt
cat docs/dns-records.txt
