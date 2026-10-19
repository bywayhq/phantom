FROM rust:1.99.1-bookworm@sha256:e12566d5abc17a0da741628782cdb504b68b8961f5bfcf677936bf3e8b32de29 AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY . .
RUN cargo build --release --locked -p phantom-net --features danger-disable-verification \
    --example tls_anvil_client

FROM ghcr.io/tls-attacker/tlsanvil@sha256:a8a4bb924b09453926ccb4721028c68051c7b61168829469a28f5af47df311d4

COPY --from=builder /source/target/release/examples/tls_anvil_client /adapter/phantom-tls-anvil
