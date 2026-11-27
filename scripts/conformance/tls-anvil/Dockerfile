FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang cmake ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY . .
RUN cargo build --release --locked -p phantom-net --features danger-disable-verification \
    --example tls_anvil_client

FROM ghcr.io/tls-attacker/tlsanvil@sha256:7137ab5b38cde07c697b9950a55bb1361e367b67cb328a11f7581d6f9272042a

COPY --from=builder /source/target/release/examples/tls_anvil_client /adapter/phantom-tls-anvil
