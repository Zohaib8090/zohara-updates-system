FROM rust:1.88-bookworm AS builder
WORKDIR /app

# Build toolchain: reqwest (default features) needs OpenSSL headers, and
# openssl-sys needs a C compiler + pkg-config.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates git pkg-config libssl-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

# ---- Dependency cache layer ----
# We compile dependencies once, against a *dummy* main.rs that touches
# every dep so cargo actually links them. When the real src/ changes,
# the `target/` cache is reused and the rebuild only re-links the
# final binary.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src templates \
    && cat > src/main.rs <<'RUST'
// dummy main that exercises every top-level dep so cargo links them
fn main() {
    let _ = std::collections::HashMap::<String, String>::new();
    // touch each crate so the linker step is non-trivial
    fn _axum() { let _ = std::any::type_name::<axum::Router>(); }
    fn _tokio() { let _ = tokio::runtime::Runtime::new().unwrap(); }
    fn _reqwest() { let _ = reqwest::Client::new(); }
    fn _askama() { let _ = askama::Template::EXT_NAME; }
    fn _jsonwebtoken() { use jsonwebtoken::{EncodingKey, Header}; let _ = EncodingKey::from_secret(b""); let _ = Header::default(); }
    fn _base64() { use base64::Engine; let _ = base64::engine::general_purpose::STANDARD.encode(&[]); }
    fn _serde() { let _ = serde_json::json!({}); }
    fn _log() { log::info!("dummy"); }
}
RUST
RUN cargo build --release \
    && rm -rf src target/release/deps/zohara_updates_system* target/release/zohara-updates-system*

# ---- Real build ----
COPY templates ./templates
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime: needs `pacman` + `repo-add` to manipulate the Arch package db.
# Arch Linux base image ships pacman natively.
FROM archlinux:latest
RUN pacman -Syu --noconfirm \
    && pacman -S --noconfirm --needed ca-certificates \
    && pacman -Scc --noconfirm
WORKDIR /app
COPY --from=builder /app/target/release/zohara-updates-system /usr/local/bin/zohara-updates-system
COPY --from=builder /app/templates /app/templates
ENV RUST_LOG=info
ENV PORT=8080
EXPOSE 8080
CMD ["/usr/local/bin/zohara-updates-system"]
