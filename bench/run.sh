#!/bin/sh
# Sets up an isolated daemon and runs bench/benchmark.py against it.
#
# Needs root (to create the service account and drop into it, exactly like a real deployment)
# and Python 3. Safe to run repeatedly -- each run uses a fresh temporary directory.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "bench/run.sh must run as root (it creates a real system account, like a real install)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill "${DAEMON_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

getent group secretbae-bench >/dev/null 2>&1 || groupadd -r secretbae-bench
getent passwd secretbae-bench >/dev/null 2>&1 ||
    useradd -r -g secretbae-bench -s /usr/sbin/nologin secretbae-bench

mkdir -p "$WORK/etc" "$WORK/data"
chown secretbae-bench:secretbae-bench "$WORK/data"

cat > "$WORK/etc/config.toml" <<CFG
keyfile = "$WORK/etc/master.key"
store = "$WORK/data/store.db"
socket = "$WORK/data/sock"
resolve_socket = "$WORK/data/resolve.sock"
user = "secretbae-bench"
socket_mode = 384
CFG

cd "$REPO_ROOT"
cargo build --release -p sbae-daemon -p sbae-cli >&2
BIN="$REPO_ROOT/target/release"

TOKEN="$("$BIN/secretbaed" init "$WORK/etc/config.toml" | head -1)"
chown secretbae-bench:secretbae-bench "$WORK/data/store.db"

"$BIN/secretbaed" "$WORK/etc/config.toml" &
DAEMON_PID=$!

for _ in $(seq 1 50); do
    [ -S "$WORK/data/sock" ] && [ -S "$WORK/data/resolve.sock" ] && break
    sleep 0.1
done

export SECRETBAE_TOKEN="$TOKEN"
"$BIN/secretbae" --socket "$WORK/data/sock" put bench/warm_secret --value 'the-value-being-measured'

cat > "$WORK/profile.toml" <<PROFILE
[[env]]
name = "BENCH_VALUE"
path = "bench/warm_secret"
PROFILE

python3 "$REPO_ROOT/bench/benchmark.py" \
    --cli "$BIN/secretbae" \
    --socket "$WORK/data/sock" \
    --resolve-socket "$WORK/data/resolve.sock" \
    --token "$TOKEN" \
    --profile "$WORK/profile.toml" \
    --iterations "${ITERATIONS:-200}" \
    --out-json "${OUT_JSON:-$REPO_ROOT/bench/results.json}"
