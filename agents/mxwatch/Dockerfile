# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM rust:1.75-slim AS builder

# libpcap headers required for network capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -f target/release/deps/mxwatch*

# Build the real binary
COPY src ./src
RUN cargo build --release

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root (network capture requires CAP_NET_RAW at container level)
RUN useradd -r -s /sbin/nologin -u 10001 mxwatch

WORKDIR /app
COPY --from=builder /build/target/release/mxwatch /app/mxwatch

USER mxwatch

ENTRYPOINT ["/app/mxwatch"]
