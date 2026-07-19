# pika — baseline + daemon helpers
#
# RULES → BASELINE → LAYERS → EXCEPTIONS  (never reverse that order)
# Full policy: JUST.md in this meta-repo.
#
# Copy to each binary repo as `justfile`, then:
#   1. Set knobs (`bins`, `primary`, `test_unit`, optional `test_integration`, `links`)
#   2. Leave BASELINE bodies untouched
#   3. Enable L1/L2 only if needed (links knob / uncomment L2 block)
#   4. Append EXCEPTIONS last, never shadowing baseline recipe names
#
# Out of scope: pure libraries (e.g. plex-rs) — no install/upx path.
#
# Common entrypoints:
#   just test                         safe unit gate
#   just test --verbose               same, show stdout
#   just test --integration           live/integration suite only
#   just test --run-all               unit + integration
#   just format --apply               rustfmt write
#   just format --check-only          rustfmt check (CI)
#   just full-gate                    format --check-only + lint + test
#   just build                        native release + upx
#   just build --debug                debug cargo build (no upx)
#   just install / just install --system
#
# Do NOT re-space `{{…}}` interpolations (`just --fmt` will try — reject it).

# ===========================================================================
# KNOBS — edit these per repo
# ===========================================================================

# Space-separated cargo binary names (must match [[bin]].name / package default).
# Single-bin:  bins := "zentools"
# Multi-bin:   bins := "nvprime nvprime-sys"
bins := "pika"

# Binary `run` invokes (must be one of `bins`). Single-bin: same as bins.
primary := "pika"

bin_dir := env_var("HOME") / ".local/bin"
sys_dir := "/usr/local/bin"

# L1 — Symlinks (multicall / rename compat). Empty = layer inactive.
# Space-separated "link_name:target_bin" pairs.
#   zentools:        links := "zen-epp:zentools zen-smu:zentools zen-mem:zentools"
#   frontmatter-mcp: links := "frontmatter-mcp:frontmatter"
links := ""

# Safe unit gate (`just test`). Override when bare `cargo test` is unsafe
# (e.g. llama.rs pulls live_* integration binaries).
#   default:  test_unit := "cargo test"
#   llama.rs: test_unit := "cargo test --lib --test cli --test api -- --test-threads=1"
test_unit := "cargo test"

# Integration / live suite (`just test --integration` / `--run-all`).
# Empty = those flags error (most repos). Set only when a real suite exists:
#   stash-mcp: test_integration := "cargo test integration"
#   llama.rs:  test_integration := "cargo test --test live_server"
test_integration := ""

# ===========================================================================
# BASELINE — identical across every binary repo (do not fork these bodies)
# ===========================================================================

# List available recipes
default:
    @just --list

# Build — one recipe, flags select mode:
#   just build           native-CPU release + upx (default; install depends on this)
#   just build --debug   debug profile, no upx
# Missing upx on the release path → hard fail.
# Native is scoped to this recipe only (not a global RUSTFLAGS export).
build *flags:
    #!/usr/bin/env bash
    set -euo pipefail
    debug=0
    for f in {{flags}}; do
        case "$f" in
            --debug) debug=1 ;;
            *)
                echo "build: unknown flag '$f' (want --debug or none)" >&2
                exit 1
                ;;
        esac
    done
    if [ "$debug" -eq 1 ]; then
        cargo build
        exit 0
    fi
    RUSTFLAGS="-C target-cpu=native" cargo build --release
    if ! command -v upx >/dev/null 2>&1; then
        echo "build: upx not found in PATH" >&2
        exit 1
    fi
    for b in {{bins}}; do
        path="target/release/$b"
        if [ ! -f "$path" ]; then
            echo "build: missing $path (is bins= correct?)" >&2
            exit 1
        fi
        upx -t "$path" >/dev/null 2>&1 || upx --best --lzma "$path"
        echo "compressed $path"
    done

# Run the primary binary (release) with arguments
run *args:
    cargo run --release --bin {{primary}} -- {{args}}

# Tests — one recipe, flags select the suite:
#   just test                         safe unit only (test_unit)
#   just test --verbose               unit with --nocapture
#   just test --integration           integration only (test_integration)
#   just test --run-all               unit then integration
#   just test --run-all --verbose     both, with --nocapture
# Flags may be combined except --integration with --run-all (redundant; either is fine alone).
test *flags:
    #!/usr/bin/env bash
    set -euo pipefail
    verbose=0
    integration=0
    run_all=0
    for f in {{flags}}; do
        case "$f" in
            --verbose) verbose=1 ;;
            --integration) integration=1 ;;
            --run-all) run_all=1 ;;
            *)
                echo "test: unknown flag '$f' (want --verbose, --integration, --run-all)" >&2
                exit 1
                ;;
        esac
    done
    if [ "$integration" -eq 1 ] && [ "$run_all" -eq 1 ]; then
        echo "test: use either --integration or --run-all, not both" >&2
        exit 1
    fi

    add_nocapture() {
        local cmd="$1"
        if [ "$verbose" -eq 0 ]; then
            printf '%s\n' "$cmd"
            return
        fi
        case "$cmd" in
            *" -- "*) printf '%s --nocapture\n' "$cmd" ;;
            *) printf '%s -- --nocapture\n' "$cmd" ;;
        esac
    }

    run_shell() {
        local cmd="$1"
        echo "+ $cmd"
        eval "$cmd"
    }

    unit_cmd='{{test_unit}}'
    integ_cmd='{{test_integration}}'

    if [ "$integration" -eq 0 ]; then
        run_shell "$(add_nocapture "$unit_cmd")"
    fi

    if [ "$integration" -eq 1 ] || [ "$run_all" -eq 1 ]; then
        if [ -z "$integ_cmd" ]; then
            echo "test: --integration/--run-all need test_integration knob set in justfile" >&2
            exit 1
        fi
        run_shell "$(add_nocapture "$integ_cmd")"
    fi

# Format — one recipe, flags select mode:
#   just format --apply        write (rustfmt)
#   just format --check-only   check only (CI)
#   just format                same as --apply
format *flags:
    #!/usr/bin/env bash
    set -euo pipefail
    mode=""
    for f in {{flags}}; do
        case "$f" in
            --apply)
                [ -n "$mode" ] && { echo "format: pass only one of --apply / --check-only" >&2; exit 1; }
                mode=apply
                ;;
            --check-only)
                [ -n "$mode" ] && { echo "format: pass only one of --apply / --check-only" >&2; exit 1; }
                mode=check
                ;;
            *)
                echo "format: unknown flag '$f' (want --apply or --check-only)" >&2
                exit 1
                ;;
        esac
    done
    mode="${mode:-apply}"
    if [ "$mode" = apply ]; then
        cargo fmt --all
    else
        cargo fmt --all -- --check
    fi

# Lint — warnings denied (CI gate)
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Full local gate: format check + lint + safe unit tests (mirrors CI)
full-gate:
    just format --check-only
    just lint
    just test


# Install binaries
# Install binaries into ~/.local/bin (default) or /usr/local/bin (--system, via sudo).
# L1: if `links` is non-empty, create each link_name → target_bin after the bin loop.
install *flags: build
    #!/usr/bin/env bash
    set -euo pipefail
    dir="{{bin_dir}}"
    sudo=""
    for f in {{flags}}; do
        case "$f" in
            --system) dir="{{sys_dir}}"; sudo="sudo" ;;
            *) echo "install: unknown flag '$f' (only --system is supported)" >&2; exit 1 ;;
        esac
    done
    for b in {{bins}}; do
        $sudo install -Dm755 "target/release/$b" "$dir/$b"
        echo "installed $dir/$b"
    done
    for pair in {{links}}; do
        [ -z "$pair" ] && continue
        link="${pair%%:*}"
        target="${pair#*:}"
        if [ -z "$link" ] || [ -z "$target" ] || [ "$link" = "$pair" ]; then
            echo "install: bad links entry '$pair' (want link:target)" >&2
            exit 1
        fi
        $sudo ln -sf "$target" "$dir/$link"
        echo "linked $dir/$link -> $target"
    done

# Remove installed binaries (and L1 links). Pass --system for /usr/local/bin via sudo.
uninstall *flags:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="{{bin_dir}}"
    sudo=""
    for f in {{flags}}; do
        case "$f" in
            --system) dir="{{sys_dir}}"; sudo="sudo" ;;
            *) echo "uninstall: unknown flag '$f' (only --system is supported)" >&2; exit 1 ;;
        esac
    done
    for b in {{bins}}; do
        $sudo rm -f "$dir/$b"
        echo "removed $dir/$b"
    done
    for pair in {{links}}; do
        [ -z "$pair" ] && continue
        link="${pair%%:*}"
        [ -z "$link" ] || [ "$link" = "$pair" ] && continue
        $sudo rm -f "$dir/$link"
        echo "removed $dir/$link"
    done

# Remove build artifacts
clean:
    cargo clean

# ===========================================================================
# L2 — Systemd unit + D-Bus (OPTIONAL)
# Copy/uncomment only when the repo ships unit/dbus files.
#
# Baseline `install` / `uninstall` = binaries (+ L1 links) only.
# This layer owns unit/dbus files and service lifecycle.
#
# Fixed names (do not invent install-system / install-service / remove-service):
#   setup · teardown · restart · logs · logs-recent · status · test-dbus
#
# Unit ExecStart paths must match `just install --system` ({{sys_dir}}).
# ===========================================================================
#
# unit_src := "system/nvprime.service"
# dbus_src := "system/com.github.nvprime.conf"   # empty string if none
# unit_dst := "/etc/systemd/system/nvprime.service"
# dbus_dst := "/etc/dbus-1/system.d/com.github.nvprime.conf"
# unit_name := "nvprime.service"
#
# setup:
#     #!/usr/bin/env bash
#     set -euo pipefail
#     just install --system
#     sudo install -Dm644 "{{unit_src}}" "{{unit_dst}}"
#     echo "installed {{unit_dst}}"
#     if [ -n "{{dbus_src}}" ]; then
#         sudo install -Dm644 "{{dbus_src}}" "{{dbus_dst}}"
#         echo "installed {{dbus_dst}}"
#     fi
#     sudo systemctl daemon-reload
#     sudo systemctl enable --now "{{unit_name}}"
#     systemctl status "{{unit_name}}" --no-pager
#
# teardown:
#     #!/usr/bin/env bash
#     set -euo pipefail
#     sudo systemctl disable --now "{{unit_name}}" 2>/dev/null || true
#     sudo rm -f "{{unit_dst}}"
#     echo "removed {{unit_dst}}"
#     if [ -n "{{dbus_src}}" ]; then
#         sudo rm -f "{{dbus_dst}}"
#         echo "removed {{dbus_dst}}"
#     fi
#     sudo systemctl daemon-reload
#     just uninstall --system
#
# restart:
#     sudo systemctl restart "{{unit_name}}"
#     systemctl status "{{unit_name}}" --no-pager
#
# logs:
#     journalctl -u "{{unit_name}}" -f
#
# logs-recent:
#     journalctl -u "{{unit_name}}" -n 50 --no-pager
#
# status:
#     systemctl status "{{unit_name}}" --no-pager
#
# test-dbus:
#     busctl call com.github.nvprime /com/github/nvprime com.github.nvprime.Service ping
#
# # compose-utils: script body OK; recipe names stay setup/teardown
# # setup *args:
# #     ./systemd/install.sh {{args}}

# ===========================================================================
# EXCEPTIONS — pika: in-process daemon helpers
# ===========================================================================

export RUST_BACKTRACE := "1"

serve:
    cargo run --release --bin {{primary}} -- serve

serve-stdio:
    cargo run --release --bin {{primary}} -- serve --stdio

ps:
    cargo run --release --bin {{primary}} -- ps
