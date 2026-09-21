FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY . .
RUN cargo build --release --locked -p phantom-net --example tls_anvil_client

FROM ghcr.io/tls-attacker/tlsanvil@sha256:29015a008c0def6e5ac495f9ac3d4d7f250dc8f7d0d393633f2f37c45245c4c2

COPY --from=builder /source/target/release/examples/tls_anvil_client /adapter/phantom-tls-anvil
