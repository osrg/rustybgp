# Build context: workspace root.
#
# Builds the bfd-stub binary (musl static) and packages it together with
# GoBGP so one container can run both BGP (port 179) and BFD (port 3784).

FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY packet/ packet/
COPY tests/e2e/bfd/stub/ stub/

WORKDIR /build/stub
RUN cargo build --release

# ---- runtime ----
FROM alpine:3.21

ARG GOBGP_VERSION=4.6.0

RUN apk add --no-cache bash ca-certificates && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        GOARCH=amd64; \
        HASH="6d4491a85dfbaaab8d18bd6855be6b67a117a5a9670eea3ee9f7dddaf50e869c"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        GOARCH=arm64; \
        HASH="41eb71f4765b3d26fff811cc6b99a91d040c6687c5aa9fc25c7baf3472e2cd66"; \
    else echo "unsupported arch: $ARCH" && exit 1; fi && \
    wget -qO /tmp/gobgp.tar.gz \
        "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_${GOARCH}.tar.gz" && \
    echo "${HASH}  /tmp/gobgp.tar.gz" | sha256sum -c - && \
    tar xz -C /usr/local/bin gobgpd gobgp < /tmp/gobgp.tar.gz && \
    rm /tmp/gobgp.tar.gz

COPY --from=builder /build/stub/target/release/bfd-stub /usr/local/bin/bfd-stub
