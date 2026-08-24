#!/bin/sh
set -eu
export MAIL_DOMAIN="${MAIL_DOMAIN:?}" COMPOSE_SUBNET="${COMPOSE_SUBNET:?}"
# envsubst scoped to exactly these two vars so Postfix's own $-expansions
# ($myhostname etc.) survive template rendering untouched.
envsubst '${MAIL_DOMAIN} ${COMPOSE_SUBNET}' < /main.cf.template > /etc/postfix/main.cf
# '|' delimiter: COMPOSE_SUBNET is a CIDR (contains '/'), which would break s///
sed "s|__COMPOSE_SUBNET__|${COMPOSE_SUBNET}|" /master.cf > /etc/postfix/master.cf

# Debian's own instance prep (used by every init system): syncs
# /etc/resolv.conf & co into the chroot jail (/var/spool/postfix/etc) so
# chrooted daemons (smtpd, lmtp) resolve compose DNS names. 'postfix
# start-fg' does NOT do this, leaving DNS broken inside the jail.
/usr/lib/postfix/configure-instance.sh

# Chrooted smtpd opens /certs/server.* through the jail, i.e. at
# /var/spool/postfix/certs/, and runs as the unprivileged 'postfix' user --
# so the staged key copy must be readable by it. Originals on the read-only
# certs volume stay untouched (root-owned 0600).
mkdir -p /var/spool/postfix/certs
cp /certs/server.crt /certs/server.key /var/spool/postfix/certs/
chown postfix:postfix /var/spool/postfix/certs/server.crt /var/spool/postfix/certs/server.key
chmod 0400 /var/spool/postfix/certs/server.key /var/spool/postfix/certs/server.crt

exec "$@"
