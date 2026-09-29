# The clean room for tools/reproduce-wasm.sh --container (and
# reproduce-server.sh): a Debian base pinned by digest, the few tools the
# rebuild needs from Debian, and rustup at a pinned version checked by its
# published SHA-256. Everything else (wasi-sdk, OpenSSL, wasm-tools,
# wit-bindgen, rustc itself) is fetched by the ref being rebuilt, from its
# own pins, when the container runs.
#
#   docker build -t aprv-reproduce tools/reproduce
#   docker run --rm -v "$PWD/out:/out" aprv-reproduce <tag-or-ref> <expected-sha256>
#
# Linux x86_64 only, as the pinned toolchain archives are. Dependabot keeps
# the digest current.
FROM --platform=linux/amd64 debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git make perl xz-utils \
 && rm -rf /var/lib/apt/lists/*

# rustup 1.29.1; the hash is the one static.rust-lang.org publishes beside it.
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_SHA256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
 && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \
 && rm /tmp/rustup-init

RUN useradd --create-home builder && mkdir /out && chown builder /out
USER builder
WORKDIR /home/builder
COPY --chmod=0755 entrypoint.sh /usr/local/bin/aprv-reproduce
ENTRYPOINT ["/usr/local/bin/aprv-reproduce"]
