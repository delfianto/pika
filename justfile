# Pika - Non-stopping memory scanner for Wine/Proton games

set dotenv-load := false

export RUST_BACKTRACE := "1"

install_dir := env("HOME") / ".local/bin"

# List available recipes
default:
    @just --list

# Build in release mode
build:
    cargo build --release

# Build in debug mode
build-debug:
    cargo build

# Run all tests
test:
    cargo test

# Run tests with output shown
test-verbose:
    cargo test -- --nocapture

# Run a specific test by name
test-one name:
    cargo test {{name}} -- --nocapture

# Full code quality check: clippy + tests + format check
check: lint test
    @echo "All checks passed."

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Check formatting (don't modify)
fmt-check:
    cargo fmt -- --check

# Auto-format code
fmt:
    cargo fmt

# Build release and install to ~/.local/bin
install: build
    @mkdir -p {{install_dir}}
    cp target/release/pika {{install_dir}}/pika
    @echo "Installed pika to {{install_dir}}/pika"

# Uninstall from ~/.local/bin
uninstall:
    rm -f {{install_dir}}/pika
    @echo "Removed pika from {{install_dir}}"

# Clean build artifacts
clean:
    cargo clean

# Start the daemon (foreground)
serve:
    cargo run --release -- serve

# Start the daemon on stdio (for testing)
serve-stdio:
    cargo run --release -- serve --stdio

# List Wine/Proton processes
ps:
    cargo run --release -- ps

# Show CLI help
help:
    cargo run --release -- --help
