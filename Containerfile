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

FROM python:3.13-slim

LABEL org.opencontainers.image.title="fauxbus" \
      org.opencontainers.image.description="A wire-level fake of the Globus API — deterministic failure on demand.  Independent test tool, not affiliated with Globus." \
      org.opencontainers.image.source="https://git.dev.xram.net/atmarx/fauxbus" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1

RUN --mount=type=bind,from=build,source=/dist,target=/dist \
    pip install --no-cache-dir /dist/*.whl

# The image carries its own bill of materials — transparency travels
# with the artifact, not with a wiki page about the artifact.
COPY --from=build /dist/sbom.json /usr/share/fauxbus/sbom.json

# Unprivileged, uid matching the port — memorable, and stable for anyone
# who needs to reason about mounted-file ownership.
RUN useradd --system --uid 9800 --no-create-home fauxbus
COPY --chmod=755 container/entrypoint.sh /usr/local/bin/fauxbus-entrypoint
USER fauxbus

EXPOSE 9800

# The control-plane index answers without auth — the natural liveness
# probe, and what makes `depends_on: service_healthy` work in compose.
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9800/_fauxbus/', timeout=1)"]

ENTRYPOINT ["fauxbus-entrypoint"]
