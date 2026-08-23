#!/bin/sh
set -eu
: "${KC_INTROSPECTION_SECRET:?KC_INTROSPECTION_SECRET must be set}"
mkdir -p /etc/dovecot/conf.d /var/mail/vhosts
chown -R vmail:vmail /var/mail/vhosts || true
sed "s|__KC_INTROSPECTION_SECRET__|${KC_INTROSPECTION_SECRET}|g" \
  /templates/90-oauth2.conf.template > /etc/dovecot/dovecot-oauth2.conf.ext
chmod 600 /etc/dovecot/dovecot-oauth2.conf.ext
exec "$@"
