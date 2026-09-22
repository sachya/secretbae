#!/bin/sh
# Prove that CapabilityBoundingSet in secretbaed.service is exactly right.
#
# The shipped unit once granted too few capabilities and the daemon died with a silent
# exit(1) -- no journal line, no stderr -- because the failure happened before any logging
# was set up. That class of bug is invisible from reading the source, so it is pinned here.
#
# Two directions matter, and a set that is merely "enough" fails this test:
#
#   * the full set must start the daemon, or the unit is too narrow;
#   * removing any single capability must stop it, or the unit is too broad and is granting
#     privilege the daemon does not need.
#
# setpriv --bounding-set reproduces what systemd's CapabilityBoundingSet does: for a uid 0
# process, the bounding set is what limits the capabilities granted on execve.
set -eu

DAEMON="${DAEMON:-/target/release/secretbaed}"
CLI="${CLI:-/target/release/secretbae}"

# Kept in sync with CapabilityBoundingSet in packaging/systemd/secretbaed.service.
REQUIRED="cap_setuid cap_setgid cap_chown cap_dac_override cap_fowner"

setup() {
    rm -rf /etc/secretbae /var/lib/secretbae /run/secretbae
    mkdir -p /etc/secretbae
    getent group secretbae >/dev/null 2>&1 || groupadd -r secretbae
    getent passwd secretbae >/dev/null 2>&1 ||
        useradd -r -g secretbae -s /usr/sbin/nologin secretbae
    # init runs unrestricted: this test is about the *service* unit, not about init, which an
    # operator runs by hand as root.
    "$DAEMON" init /etc/secretbae/config.toml >/tmp/token 2>/dev/null
}

# Start the daemon under `bounding` and report whether it reached the point of serving.
starts_with() {
    bounding="$1"
    rm -f /run/secretbae/sock
    setpriv --bounding-set "$bounding" -- "$DAEMON" /etc/secretbae/config.toml \
        >/tmp/daemon.log 2>&1 &
    pid=$!

    i=0
    while [ "$i" -lt 60 ]; do
        if SECRETBAE_TOKEN="$(cat /tmp/token)" "$CLI" status >/dev/null 2>&1; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        kill -0 "$pid" 2>/dev/null || break
        i=$((i + 1))
        sleep 0.25
    done

    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    return 1
}

# REQUIRED mirrors the unit file verbatim so the two can be diffed by eye; setpriv wants the
# same names without the cap_ prefix.
list_to_bounding() {
    result="-all"
    for cap in $1; do
        result="$result,+$(echo "$cap" | sed 's/^cap_//')"
    done
    echo "$result"
}

failures=0

setup
if starts_with "$(list_to_bounding "$REQUIRED")"; then
    echo "PASS  full set starts the daemon"
else
    echo "FAIL  full set does NOT start the daemon"
    sed 's/^/        /' /tmp/daemon.log
    failures=$((failures + 1))
fi

for omitted in $REQUIRED; do
    reduced=""
    for cap in $REQUIRED; do
        [ "$cap" = "$omitted" ] || reduced="$reduced $cap"
    done

    setup
    if starts_with "$(list_to_bounding "$reduced")"; then
        echo "FAIL  starts without $omitted -- the bounding set grants more than it needs"
        failures=$((failures + 1))
    else
        echo "PASS  cannot start without $omitted"
    fi
done

# LimitMEMLOCK is why CAP_IPC_LOCK is absent above. mlockall() needs that capability only to
# exceed RLIMIT_MEMLOCK, and the limit has to be lifted regardless: MCL_FUTURE keeps locking
# pages for the life of the process, while CAP_IPC_LOCK is surrendered at the privilege drop.
# Granting the capability instead of raising the limit would fix startup and leave every later
# allocation capped.
echo
setup
if ( ulimit -l 8192 2>/dev/null && starts_with "$(list_to_bounding "$REQUIRED")" ); then
    echo "FAIL  starts under systemd's 8 MiB default -- LimitMEMLOCK may be unnecessary"
    failures=$((failures + 1))
else
    echo "PASS  refuses to start under an 8 MiB memlock limit, so LimitMEMLOCK is required"
fi

setup
if starts_with "$(list_to_bounding "$REQUIRED")"; then
    echo "PASS  starts with the limit lifted and no CAP_IPC_LOCK"
else
    echo "FAIL  does not start with the limit lifted"
    sed 's/^/        /' /tmp/daemon.log
    failures=$((failures + 1))
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "capability set is exactly right: $REQUIRED"
else
    echo "$failures discrepancies"
fi
exit "$failures"
