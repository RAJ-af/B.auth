#!/bin/sh
set -eu
export MAIL_DOMAIN="${MAIL_DOMAIN:?}" COMPOSE_SUBNET="${COMPOSE_SUBNET:?}"
# envsubst scoped to exactly these two vars so Postfix's own $-expansions
# ($myhostname etc.) survive template rendering untouched.
envsubst '${MAIL_DOMAIN} ${COMPOSE_SUBNET}' < /main.cf.template > /etc/postfix/main.cf
# '|' delimiter: COMPOSE_SUBNET is a CIDR (contains '/'), which would break s///
sed "s|__COMPOSE_SUBNET__|${COMPOSE_SUBNET}|" /master.cf > /etc/postfix/master.cf
exec "$@"
