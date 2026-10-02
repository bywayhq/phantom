FROM rust:1.99.0-bookworm@sha256:59037199c44290f2befcdd58dcc540164763fc296950255aaefeef096a1866b0 AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY . .
RUN cargo build --release --locked -p phantom-net --example tls_anvil_client

FROM ghcr.io/tls-attacker/tlsanvil@sha256:a8a4bb924b09453926ccb4721028c68051c7b61168829469a28f5af47df311d4

COPY --from=builder /source/target/release/examples/tls_anvil_client /adapter/phantom-tls-anvil
