# syntax=docker/dockerfile:1
# rust-authentication — multi-stage image (OPS-08).
#
#   docker build -t rust-authentication .
#   docker run --rm -e AUTHN_CONFIG=/etc/authn/authn.toml \
#     -v "$PWD/config/authn.toml:/etc/authn/authn.toml:ro" rust-authentication serve
#
# Stage 1 builds a release binary with the pinned toolchain; stage 2 is a
# distroless image (no shell, no package manager) running as an unprivileged
# user. TLS roots come from the image's ca-certificates; the binary uses
# rustls + ring only (no OpenSSL).
#
# Features: the defaults (passkey, sms) plus `redis`, so
# protect.rate_limit.backend = "redis" works with the published image
# (K-109; licences of the redis crates are in THIRD_PARTY_LICENSES.txt).

ARG RUST_VERSION=1.97

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
# Dependency manifests first (better layer caching).
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml deny.toml ./
COPY crates ./crates
COPY migrations ./migrations
COPY config ./config
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p authn-server --bin rust-authentication --features redis \
 && install -D -m 0755 target/release/rust-authentication /out/rust-authentication

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/rust-authentication /usr/local/bin/rust-authentication
COPY --from=build /src/config/example.toml /etc/authn/example.toml
# Third-party licence notices required for binary redistribution (LIC-01).
COPY THIRD_PARTY_LICENSES.txt /usr/share/doc/rust-authentication/THIRD_PARTY_LICENSES.txt
USER nonroot:nonroot
# K-109: the metrics listener defaults to 127.0.0.1:9090, which is not
# reachable from outside the container. Inside the image it listens on every
# interface of the container's network namespace; publish 9090 ONLY to the
# internal monitoring network, never to the internet. Disable it with
# AUTHN__SERVER__METRICS_BIND_ADDR=off (or metrics_bind_addr = "off").
ENV AUTHN__SERVER__METRICS_BIND_ADDR=0.0.0.0:9090
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/rust-authentication"]
CMD ["serve"]
