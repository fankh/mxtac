# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM rust:1.75-slim AS builder

WORKDIR /build

# Cache dependencies separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -f target/release/deps/mxguard*

# Build the real binary
COPY src ./src
RUN cargo build --release

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root
RUN useradd -r -s /sbin/nologin -u 10001 mxguard

WORKDIR /app
COPY --from=builder /build/target/release/mxguard /app/mxguard
COPY config/ /app/config/

USER mxguard

ENTRYPOINT ["/app/mxguard"]
