#!/bin/sh
# rspamd entrypoint wrapper: render dkim_signing.conf from $COMPOSE_SUBNET /
# $MAIL_DOMAIN, then exec the real command as the image's _rspamd user.
#
# The stock rspamd image pins USER=11333 (_rspamd), which can write nowhere
# under /etc/rspamd, so the wrapper runs as root (compose sets user: "0:0"),
# writes the rendered file into override.d (loads AFTER local.d), and drops
# back to the same uid/gid the image would have used before exec'ing CMD.
set -eu

: "${COMPOSE_SUBNET:?COMPOSE_SUBNET is required to render dkim_signing.conf}"
: "${MAIL_DOMAIN:?MAIL_DOMAIN is required to render dkim_signing.conf}"

sed -e "s|__COMPOSE_SUBNET__|${COMPOSE_SUBNET}|" \
    -e "s|__MAIL_DOMAIN__|${MAIL_DOMAIN}|" \
    /templates/dkim_signing.conf.template > /etc/rspamd/override.d/dkim_signing.conf

# 11333 = _rspamd in rspamd/rspamd images (matches the image's own USER pin).
exec setpriv --reuid=11333 --regid=11333 --clear-groups "$@"
