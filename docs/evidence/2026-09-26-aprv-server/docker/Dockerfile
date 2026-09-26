# syntax=docker/dockerfile:1
# Spike only (2026-09-26): aprv-server variant B (runtime-only Wasmtime with
# the module precompiled at build time) in a minimal non-root image.
#
# Build (context = the server crate; the canonical module comes in as a
# second named context and is checked against its pinned SHA-256):
#   docker buildx build --platform linux/amd64 -f $EV/docker/Dockerfile \
#     --build-context module=$SCRATCH/abi/art -t aprv-server:spike $EV/server
# Run: it listens on 127.0.0.1:8080 INSIDE the container unless APRV_LISTEN
# says otherwise, so a published port reaches nothing by default:
#   docker run --rm -e APRV_LISTEN=0.0.0.0:8080 -p 127.0.0.1:8080:8080 aprv-server:spike
# Pin both base images by digest before any real use (tags here for the spike).

FROM rust:1.98.1-slim-trixie AS build
ARG WASM_SHA256=b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY --from=module aprv-abi1.wasm /module/aprv-abi1.wasm
RUN echo "$WASM_SHA256  /module/aprv-abi1.wasm" | sha256sum -c -
# 1. The full engine precompiles the module for this platform.
ENV APRV_WASM=/module/aprv-abi1.wasm
RUN cargo build --release --locked --bin aprv \
 && ./target/release/aprv precompile /module/aprv-abi1.cwasm \
 && cp target/release/aprv /module/aprv-full
# 2. The shipped binary: runtime-only Wasmtime, the .cwasm embedded, its hash pinned.
RUN APRV_CWASM=/module/aprv-abi1.cwasm \
    APRV_CWASM_SHA256="$(sha256sum /module/aprv-abi1.cwasm | cut -c1-64)" \
    cargo build --release --locked --bin aprv --no-default-features --features server,embed \
 && strip -o /aprv target/release/aprv \
 && /aprv info

# glibc + libgcc_s, no shell, no package manager, uid 65532.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /aprv /usr/local/bin/aprv
USER 65532:65532
EXPOSE 8080
# Liveness: GET /healthz; readiness: GET /readyz (no curl in this image; let
# the orchestrator probe them).
ENTRYPOINT ["/usr/local/bin/aprv", "serve"]
