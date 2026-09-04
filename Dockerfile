FROM rust:1.81-bookworm AS builder
WORKDIR /app
# `git` is needed by the openssl-sys crate; `ca-certificates` so reqwest
# can verify GitHub's TLS chain.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git pkg-config \
 && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src target/release/deps/zohara*
COPY templates ./templates
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime: needs `pacman` + `repo-add` to manipulate the package db.
# We use Arch Linux as the base image so `pacman` is available natively
# (no need to install it from Debian; the standard `archlinux:latest`
# image from Docker Hub has it).
FROM archlinux:latest
RUN pacman -Syu --noconfirm && pacman -S --noconfirm --needed ca-certificates
WORKDIR /app
COPY --from=builder /app/target/release/zohara-hub /usr/local/bin/zohara-hub
COPY --from=builder /app/templates /app/templates
ENV RUST_LOG=info
ENV PORT=8080
EXPOSE 8080
CMD ["/usr/local/bin/zohara-hub"]
