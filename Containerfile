# Fauxbus — a wire-level fake of the Globus API.
#
# Two stages: build the wheel, install only the wheel.  Fauxbus has zero
# runtime dependencies, so the final image is the Python base plus one
# pure-stdlib package — no supply chain rides along into your dev stack.
#
# Named Containerfile (the OCI-neutral spelling).  Docker wants
# `-f Containerfile`, or in compose:
#   build: { context: ., dockerfile: Containerfile }

FROM python:3.13-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip wheel --no-deps --no-cache-dir --wheel-dir /dist .

# The SBOM is generated from a CLEAN venv holding only the wheel we just
# built: pointing the generator at its own environment would list the
# generator and its dependencies, polluting the receipt.  For a
# zero-dependency package the bill of materials is short on purpose —
# it is the machine-readable proof of the "no supply chain rides along"
# claim, license metadata included (CycloneDX reads MIT straight out of
# the wheel).
RUN pip install --no-cache-dir cyclonedx-bom \
    && python -m venv /sbomenv \
    && /sbomenv/bin/pip install --no-cache-dir /dist/*.whl \
    && cyclonedx-py environment /sbomenv/bin/python --of json -o /dist/sbom.json

# The final stage is Alpine, not Debian slim, and the reason is a
# scanner report rather than taste.  Fauxbus is pure stdlib with no C
# extensions, so the only thing the base image contributes is the
# interpreter and whatever the distro carries around it.  Measured with
# grype on 2026-10-10, on a fresh --pull of each:
#
#   python:3.13-slim    161 findings, 55 High — every High "wont-fix"
#                       or "not-fixed" (util-linux, perl, ncurses, glibc,
#                       gcc runtime): nothing a rebuild could ever patch,
#                       in packages Fauxbus never calls.
#   python:3.13-alpine    6 findings, 1 High — and that one is fixed in
#                       Alpine already, which the apk upgrade below picks
#                       up.  Half the size, too.
#
# The lesson worth carrying: with a pure-Python app the attack surface is
# almost entirely the distro, so the base image *is* the security
# decision.  musl versus glibc does not matter to code that never links
# against either.  The build stage stays on slim — nothing from it ships
# but the wheel and the SBOM.
FROM python:3.13-alpine

LABEL org.opencontainers.image.title="fauxbus" \
      org.opencontainers.image.description="A wire-level fake of the Globus API for E2E testing.  Independent test tool, not affiliated with Globus." \
      org.opencontainers.image.source="https://github.com/atmarx/fauxbus" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1

# The official tag is rebuilt on its own schedule, which can lag
# Alpine's security fixes by days.  Upgrading here means a rebuild picks
# up a patched package the moment Alpine ships it, rather than whenever
# the python image next gets around to it — the same reason CI builds
# with --pull.  --no-cache keeps the package index out of the image.
RUN apk upgrade --no-cache

RUN --mount=type=bind,from=build,source=/dist,target=/dist \
    pip install --no-cache-dir /dist/*.whl

# The image carries its own bill of materials — transparency travels
# with the artifact, not with a wiki page about the artifact.
COPY --from=build /dist/sbom.json /usr/share/fauxbus/sbom.json

# Unprivileged, uid matching the port — memorable, and stable for anyone
# who needs to reason about mounted-file ownership.  The group is made
# explicitly (gid 9800 too) because busybox's adduser -S otherwise files
# a system user under the shared `nogroup`.
RUN addgroup -S -g 9800 fauxbus \
    && adduser -S -u 9800 -G fauxbus -H fauxbus
COPY --chmod=755 container/entrypoint.sh /usr/local/bin/fauxbus-entrypoint
USER fauxbus

EXPOSE 9800

# The control-plane index answers without auth — the natural liveness
# probe, and what makes `depends_on: service_healthy` work in compose.
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9800/_fauxbus/', timeout=1)"]

ENTRYPOINT ["fauxbus-entrypoint"]
