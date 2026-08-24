FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      postfix swaks gettext-base ca-certificates && rm -rf /var/lib/apt/lists/*
COPY main.cf.template master.cf entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["postfix", "start-fg"]
