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
# Both bases are pinned by digest (multi-arch index digests). There is no
# `# syntax=` line on purpose: BuildKit's built-in Dockerfile frontend reads
# this file, so no frontend image is pulled by a moving tag. The builder
# stage runs natively per platform (buildx with QEMU or native runners), so
# the full build precompiles for the platform's own baseline target.

# rust:1.100.0-slim-trixie, the build of 2026-11-17 (docker-library/repo-info
# 9df4f15, recorded 2026-11-17T19:53Z). The tag is rebuilt about weekly, so
# its newest digest is always inside the cooldown, and no tag names this one
# any more: image-age-check reports its age as unknown. Checked by hand as
# that warning asks: seven days old on 2026-11-24, and the index fetched by
# digest hashes to this pin and sets RUST_VERSION=1.100.0.
FROM rust:1.100.0-slim-trixie@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe AS build
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
# musl-tools: musl-gcc compiles Wasmtime's C helpers for the musl target.
RUN apt-get update && apt-get install -y --no-install-recommends binutils musl-tools && rm -rf /var/lib/apt/lists/* \
 && COMPONENT_SHA256="$COMPONENT_SHA256" CARGO_TARGET_DIR=/tmp/target \
    sh rust/server/scripts/build-static.sh /in/aprv.component.wasm "$(cat /target)" /out \
 && cp "/out/aprv-$(cat /target)" /aprv

# gcr.io/distroless/static-debian13:nonroot: no shell, no package manager,
# no libc (the binary needs none), uid 65532. Shared by the two final
# stages below, which differ only in where the binary comes from.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS runtime
ARG VERSION=unknown
ARG REVISION=unknown
LABEL org.opencontainers.image.title="aprv-server" \
      org.opencontainers.image.description="Verifies Apple purchase receipts and App Store JWS offline by running aprv.wasm through Wasmtime; HTTP on 127.0.0.1:8080 until APRV_LISTEN is set." \
      org.opencontainers.image.source="https://github.com/emindeniz99/apple-purchase-receipt-verifier" \
      org.opencontainers.image.url="https://github.com/emindeniz99/apple-purchase-receipt-verifier/tree/main/rust/server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
USER 65532:65532
EXPOSE 8080
# Liveness GET /healthz, readiness GET /readyz. The image has no shell or
# curl, so the orchestrator probes them (the server must listen beyond
# loopback, APRV_LISTEN, for a probe from outside the container).
ENTRYPOINT ["/usr/local/bin/aprv", "serve"]

# The release's image (release.yml publish-image, `--target prebuilt`): the
# static binaries the release built, attested and published as assets,
# copied in unchanged, so nothing compiles inside Docker there. The build
# context is a directory holding aprv-amd64 and aprv-arm64:
#
#   docker buildx build --platform linux/amd64,linux/arm64 --target prebuilt \
#     -f rust/server/Dockerfile DIR_WITH_aprv-amd64_AND_aprv-arm64
FROM runtime AS prebuilt
ARG TARGETARCH
COPY --chmod=0755 aprv-${TARGETARCH} /usr/local/bin/aprv

# The default: the two-stage build above, for a build from source.
FROM runtime
COPY --from=build /aprv /usr/local/bin/aprv
