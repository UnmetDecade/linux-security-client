# lsec - Linux unified security client
#
# The image bundles ClamAV so on-demand malware scanning works out of the box,
# YARA for signed rule-pack scanning, and Lynis so host baseline audits include
# a third-party read-only check.
# The container is the security boundary: it does NOT mount the Docker socket
# and it does NOT run ClamAV on-access (fanotify) protection. Optional container
# monitoring reads the Docker API through the separate GET-only proxy image
# (packaging/Dockerfile.proxy, docker-compose.container.yml).
FROM python:3.15-slim-bookworm

# Build-time Debian mirror override, e.g.
#   docker compose build --build-arg DEBIAN_MIRROR=http://mirrors.ustc.edu.cn
# The default remains the canonical Debian mirror.
ARG DEBIAN_MIRROR="http://deb.debian.org"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    DEBIAN_FRONTEND=noninteractive

# Block maintainer scripts from trying to start services during build: there is
# no systemd inside the image. lsec starts clamd itself via the adapter.
RUN for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources; do \
        [ -f "$f" ] || continue; \
        sed -i "s|http://deb.debian.org|${DEBIAN_MIRROR}|g; s|https://deb.debian.org|${DEBIAN_MIRROR}|g" "$f"; \
    done \
    && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod +x /usr/sbin/policy-rc.d \
    && apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 update \
    && apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=3 install -y --no-install-recommends \
        ca-certificates \
        clamav \
        clamav-daemon \
        clamav-freshclam \
        lynis \
        openssl \
        yara \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d

WORKDIR /app
COPY src/ /app/src/
COPY packaging/lsec.toml /etc/lsec/lsec.toml
COPY packaging/entrypoint.sh /usr/local/bin/lsec-entrypoint
COPY packaging/lsec /usr/local/bin/lsec

RUN chmod 0755 /usr/local/bin/lsec-entrypoint /usr/local/bin/lsec \
    && mkdir -p /data/logs /data/evidence /data/quarantine /data/secrets \
       /data/clamav /data/yara/inbox /var/lib/clamav /run/clamav /scan \
    && chmod 0700 /data/secrets /data/evidence /data/quarantine \
    && chmod 0750 /data/yara /data/yara/inbox

VOLUME ["/data", "/var/lib/clamav"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=600s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3)"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/lsec-entrypoint"]
CMD ["--config", "/etc/lsec/lsec.toml"]
