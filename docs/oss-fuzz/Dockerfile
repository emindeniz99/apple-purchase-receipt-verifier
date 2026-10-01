# Draft of projects/apple-purchase-receipt-verifier/Dockerfile for
# google/oss-fuzz. The base image brings clang, a nightly Rust and
# cargo-fuzz. OpenSSL 4.0.2 is built from source inside the cargo build by
# openssl-src (the crate's default `vendored` feature), so the image needs
# only what OpenSSL's Configure and make use: perl and make.
FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y make perl zip
RUN git clone --depth 1 https://github.com/emindeniz99/apple-purchase-receipt-verifier apple-purchase-receipt-verifier
WORKDIR $SRC/apple-purchase-receipt-verifier
COPY build.sh $SRC/
