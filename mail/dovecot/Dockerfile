# The official dovecot/dovecot image is built WITHOUT --with-oauth2: the oauth2
# passdb is absent and every oauth2_* setting dies with "Unknown setting".
# Debian's packaged Dovecot (2.3.x) ships oauth2 support compiled in.
FROM debian:bookworm-20260803-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    dovecot-core dovecot-lmtpd gettext-base && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 5000 vmail && useradd -u 5000 -g 5000 -d /var/mail/vhosts -M vmail
COPY entrypoint.sh /entrypoint-custom.sh
# dovecot.conf is bind-mounted read-only by docker-compose.yml (it lives in
# config/dovecot/, outside this build context; a repo-root context would leak .env).
ENTRYPOINT ["/entrypoint-custom.sh"]
CMD ["dovecot", "-F"]
