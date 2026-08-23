FROM dovecot/dovecot:2.3.21
RUN apt-get update && apt-get install -y --no-install-recommends gettext-base && rm -rf /var/lib/apt/lists/*
RUN groupadd -g 5000 vmail && useradd -u 5000 -g 5000 -d /var/mail/vhosts -M vmail
COPY entrypoint.sh /entrypoint-custom.sh
# dovecot.conf is bind-mounted read-only by docker-compose.yml (it lives in
# config/dovecot/, outside this build context; a repo-root context would leak .env).
ENTRYPOINT ["/entrypoint-custom.sh"]
CMD ["dovecot", "-F"]
