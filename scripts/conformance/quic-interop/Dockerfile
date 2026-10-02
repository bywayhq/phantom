# syntax=docker/dockerfile:1.7

FROM rust:1.99.0-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0 AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY . .
RUN cargo build --release --locked -p phantom-http --example quic-interop-client

FROM martenseemann/quic-network-simulator-endpoint@sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a

WORKDIR /phantom
COPY --from=builder /source/target/release/examples/quic-interop-client /usr/local/bin/
COPY scripts/conformance/quic-interop/run_endpoint.sh ./run_endpoint.sh
RUN chmod 0755 ./run_endpoint.sh

ENTRYPOINT ["./run_endpoint.sh"]
