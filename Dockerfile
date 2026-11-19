# mavirank collector image: reads web server logs from a read-only bind mount,
# keeps its state (offsets, day keys, caches) in a volume and runs every 5 minutes.
# Base pinned by version and digest (python:3.13-alpine3.22, checked 2026-11-12).
FROM python:3.13-alpine3.22@sha256:e81548ac35b07a3bd4805f275107592ef458b1e893c0e04d45aedaa19416cca5

# Configuration in /etc/mavirank-collector, state in the volume /var/lib/mavirank-collector
# (XDG_* are the defaults when the configuration has no [state] dir).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MAVIRANK_COLLECTOR_CONFIG=/etc/mavirank-collector/collector.conf \
    XDG_CONFIG_HOME=/etc \
    XDG_STATE_HOME=/var/lib

COPY pyproject.toml README.md /src/
COPY mavirank_collector /src/mavirank_collector

# Non-root user; member of "adm" (gid 4, like Debian/Ubuntu) to read rotated logs owned by root:adm.
# The configuration on the host belongs to uid 10001 and stays private:
#   sudo install -d -m 0700 -o 10001 -g 0 /etc/mavirank-collector
#   sudo chown 10001:0 /etc/mavirank-collector/collector.conf && sudo chmod 600 /etc/mavirank-collector/collector.conf
# Mount only the log directory of the web server read-only (-v /var/log/nginx:/var/log/nginx:ro), not all of /var/log.
RUN pip install --no-cache-dir --no-compile --root-user-action=ignore /src \
    && rm -rf /src \
    && addgroup -S -g 10001 mavirank-collector \
    && adduser -S -D -H -u 10001 -G mavirank-collector -s /sbin/nologin -h /var/lib/mavirank-collector mavirank-collector \
    && addgroup mavirank-collector adm \
    && install -d -m 0700 -o mavirank-collector -g mavirank-collector /var/lib/mavirank-collector \
    && install -d -m 0700 -o mavirank-collector -g mavirank-collector /etc/mavirank-collector

USER mavirank-collector
VOLUME ["/var/lib/mavirank-collector"]
ENTRYPOINT ["mavirank-collector"]
# Container mode: one pass every 300 s (Retry-After and quota pauses are respected).
# Alternative for an external scheduler: `docker run --rm … mavirank-collector run`.
CMD ["run", "--every", "300"]
