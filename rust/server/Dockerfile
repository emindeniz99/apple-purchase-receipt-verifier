# syntax=docker/dockerfile:1
# aprv-server image: the static musl `aprv` binary with the release's
# component precompiled and embedded, on distroless static, non-root.
#
# Build from the repository root; the component comes in as a second named
# context and must hash to COMPONENT_SHA256:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -f rust/server/Dockerfile \
#     --build-context component=DIR_WITH_aprv.component.wasm \
#     --build-arg COMPONENT_SHA256=<sha256 of aprv.component.wasm> \
#     --build-arg VERSION=<release version> --build-arg REVISION=<git sha> \
#     -t aprv-server .
#
# Run. Inside the container the server listens on 127.0.0.1:8080, so a
# published port reaches nothing until APRV_LISTEN says otherwise:
#
#   docker run --rm -e APRV_LISTEN=0.0.0.0:8080 -e APRV_TOKEN=... \
#     -p 127.0.0.1:8080:8080 aprv-server
#
# Both bases are pinned by digest (multi-arch index digests). The builder
# stage runs natively per platform (buildx with QEMU or native runners), so
# the full build precompiles for the platform's own baseline target.

# rust:1.98.1-slim-trixie
FROM rust:1.98.1-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS build
ARG COMPONENT_SHA256
ARG TARGETARCH
WORKDIR /src
# rust/ carries the server and the wire schemas its OpenAPI document bundles.
COPY rust/ rust/
COPY --from=component aprv.component.wasm /in/aprv.component.wasm
RUN test -n "$COMPONENT_SHA256" \
 && echo "$COMPONENT_SHA256  /in/aprv.component.wasm" | sha256sum -c -
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl ;; \
      arm64) echo aarch64-unknown-linux-musl ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac > /target \
 && rustup target add "$(cat /target)"
# The two-stage build: precompile with the full build, embed in the
# runtime-only static build; the script checks the result with readelf.
RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/* \
 && COMPONENT_SHA256="$COMPONENT_SHA256" CARGO_TARGET_DIR=/tmp/target \
    sh rust/server/scripts/build-static.sh /in/aprv.component.wasm "$(cat /target)" /out \
 && cp "/out/aprv-$(cat /target)" /aprv

# gcr.io/distroless/static-debian13:nonroot: no shell, no package manager,
# no libc (the binary needs none), uid 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG VERSION=unknown
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aprv-server" \
      org.opencontainers.image.description="Verifies Apple purchase receipts and App Store JWS offline by running aprv.wasm through Wasmtime; HTTP on 127.0.0.1:8080 until APRV_LISTEN is set." \
      org.opencontainers.image.source="https://github.com/emindeniz99/apple-purchase-receipt-verifier" \
      org.opencontainers.image.url="https://github.com/emindeniz99/apple-purchase-receipt-verifier/tree/main/rust/server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /aprv /usr/local/bin/aprv
USER 65532:65532
EXPOSE 8080
# Liveness GET /healthz, readiness GET /readyz. The image has no shell or
# curl, so the orchestrator probes them (the server must listen beyond
# loopback, APRV_LISTEN, for a probe from outside the container).
ENTRYPOINT ["/usr/local/bin/aprv", "serve"]
