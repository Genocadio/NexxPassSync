FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    postgresql16-client \
    gzip \
    coreutils \
    findutils \
    curl \
    ca-certificates

COPY backup.sh /usr/local/bin/backup.sh
RUN chmod +x /usr/local/bin/backup.sh

# Run backup daily at 02:00 UTC and on container startup
RUN echo "0 2 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1" > /etc/crontabs/root

VOLUME ["/backups"]

CMD ["sh", "-c", "/usr/local/bin/backup.sh && crond -f -l 2"]
