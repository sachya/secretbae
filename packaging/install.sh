#!/bin/sh
# Linux installation script for secretbae on systemd-based distributions.
# This script is written in standard POSIX sh and executes with set -eu.
set -eu

# Ensure script is executed with root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: installation requires root privileges. Please run as root or with sudo." >&2
    exit 1
fi

echo "=== Installing secretbae ==="

# -----------------------------------------------------------------------------
# 0. Toolchain Check
# -----------------------------------------------------------------------------
# This script assumes shadow-utils' useradd/groupadd/getent (Debian, Ubuntu, Fedora, RHEL,
# CentOS, Arch, openSUSE and most other glibc, systemd-based distributions ship these by
# default). It does not support busybox's adduser/addgroup (Alpine and similar musl/OpenRC
# distributions) -- that combination is not yet supported by secretbae at all, since the
# daemon itself is only verified against glibc.
for tool in getent groupadd useradd systemctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: '$tool' not found. This installer targets systemd distributions with" >&2
        echo "       shadow-utils (Debian, Ubuntu, Fedora, RHEL, CentOS, Arch, openSUSE)." >&2
        echo "       Alpine and other musl/OpenRC distributions are not yet supported." >&2
        exit 1
    fi
done

# -----------------------------------------------------------------------------
# 1. System User and Group Creation (Idempotent)
# -----------------------------------------------------------------------------
# secretbae daemon drops privileges permanently to an unprivileged system user.
if ! getent group secretbae >/dev/null 2>&1; then
    echo "Creating system group 'secretbae'..."
    groupadd -r secretbae
else
    echo "System group 'secretbae' already exists."
fi

if ! getent passwd secretbae >/dev/null 2>&1; then
    echo "Creating system user 'secretbae'..."
    useradd -r -g secretbae -d /var/lib/secretbae -s /usr/sbin/nologin -c "secretbae daemon service" secretbae
else
    echo "System user 'secretbae' already exists."
fi

# -----------------------------------------------------------------------------
# 2. Directory Hierarchy and Permissions
# -----------------------------------------------------------------------------
# Directory: /etc/secretbae
# Mode: 0755 (rwxr-xr-x), Owner: root:root
# Rationale: `secretbae exec` runs as the application's own unprivileged user and must
# traverse this directory to read its token and profile. Confidentiality comes from
# master.key being 0400 root:root, not from hiding the directory.
# Rationale: Contains root-owned configuration and the high-entropy master keyfile.
# Restricted exclusively to root to prevent traversal, enumeration, or reading by
# any unprivileged local user (including the secretbae daemon once privileges are dropped).
echo "Configuring /etc/secretbae (mode 0755 root:root)..."
mkdir -p /etc/secretbae /etc/secretbae/tokens /etc/secretbae/profiles
chmod 0755 /etc/secretbae /etc/secretbae/tokens /etc/secretbae/profiles
chown root:root /etc/secretbae /etc/secretbae/tokens /etc/secretbae/profiles

# Directory: /var/lib/secretbae
# Mode: 0700 (rwx------), Owner: secretbae:secretbae
# Rationale: Holds the persistent SQLite store (store.db, WAL files). Restricted
# strictly to the unprivileged secretbae service account so local users cannot inspect
# ciphertext, metadata, or attempt offline SQLite manipulation.
echo "Configuring /var/lib/secretbae (mode 0700 secretbae:secretbae)..."
mkdir -p /var/lib/secretbae
chmod 0700 /var/lib/secretbae
chown secretbae:secretbae /var/lib/secretbae

# Directory: /run/secretbae
# Mode: 0750 (rwxr-x---), Owner: secretbae:secretbae
# Rationale: Contains the Unix domain socket /run/secretbae/sock (mode 0660).
# Mode 0750 permits directory traversal for members of the 'secretbae' group
# (such as application service accounts like www-data) while blocking all other
# unprivileged local users.
echo "Configuring /run/secretbae (mode 0750 secretbae:secretbae)..."
mkdir -p /run/secretbae
chmod 0750 /run/secretbae
chown secretbae:secretbae /run/secretbae

# -----------------------------------------------------------------------------
# 3. Master Keyfile Check (Refuse to Clobber)
# -----------------------------------------------------------------------------
# File: /etc/secretbae/master.key
# Mode: 0400 (r--------), Owner: root:root
# Rationale: The root keyfile is the root of trust for deriving the key-encryption key (KEK).
# Overwriting an existing keyfile would permanently orphan and destroy access to every
# secret currently encrypted in the store. Therefore, the installer must refuse to clobber it.
if [ -f /etc/secretbae/master.key ]; then
    echo "Existing keyfile /etc/secretbae/master.key detected. Preserving existing keyfile."
    chmod 0400 /etc/secretbae/master.key
    chown root:root /etc/secretbae/master.key
else
    echo "Notice: /etc/secretbae/master.key does not exist yet."
    echo "        It will be generated by the first 'secretbaed init' run."
fi

# -----------------------------------------------------------------------------
# 4. Binary Installation
# -----------------------------------------------------------------------------
# The daemon goes to /usr/sbin at 0750 and the CLI to /usr/bin at 0755, matching both the
# .deb and the unit file's ExecStart. These three must agree: a mismatch is invisible until
# systemd tries to start the service.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# The daemon is not for unprivileged users to run, so it is not on their PATH and not
# executable by them; the CLI is how they talk to it.
target_dir() {
    case "$1" in
    secretbaed) echo "/usr/sbin" ;;
    *) echo "/usr/bin" ;;
    esac
}

target_mode() {
    case "$1" in
    secretbaed) echo "0750" ;;
    *) echo "0755" ;;
    esac
}

install_binary() {
    bin_name="$1"
    src_path=""
    if [ -f "$ROOT_DIR/target/release/$bin_name" ]; then
        src_path="$ROOT_DIR/target/release/$bin_name"
    elif [ -f "$ROOT_DIR/target/debug/$bin_name" ]; then
        src_path="$ROOT_DIR/target/debug/$bin_name"
    elif [ -f "./$bin_name" ]; then
        src_path="./$bin_name"
    elif command -v "$bin_name" >/dev/null 2>&1; then
        src_path="$(command -v "$bin_name")"
    fi

    if [ -n "$src_path" ] && [ -f "$src_path" ]; then
        echo "Installing $bin_name from $src_path to $(target_dir "$bin_name")/$bin_name..."
        install -m "$(target_mode "$bin_name")" "$src_path" "$(target_dir "$bin_name")/$bin_name"
        chown root:root "$(target_dir "$bin_name")/$bin_name"
    else
        echo "Warning: binary '$bin_name' not found in build directories. Skipping binary installation."
    fi
}

install_binary "secretbaed"
install_binary "secretbae"

# -----------------------------------------------------------------------------
# 5. systemd Configuration and Service Unit
# -----------------------------------------------------------------------------
if [ -d /etc/systemd/system ]; then
    echo "Installing systemd unit /etc/systemd/system/secretbaed.service..."
    if [ -f "$SCRIPT_DIR/systemd/secretbaed.service" ]; then
        install -m 0644 "$SCRIPT_DIR/systemd/secretbaed.service" /etc/systemd/system/secretbaed.service
        chown root:root /etc/systemd/system/secretbaed.service
    fi

    # Install sysusers and tmpfiles configs if supported
    if [ -d /etc/sysusers.d ] && [ -f "$SCRIPT_DIR/systemd/secretbaed.sysusers.conf" ]; then
        install -m 0644 "$SCRIPT_DIR/systemd/secretbaed.sysusers.conf" /etc/sysusers.d/secretbaed.conf
    fi

    if [ -d /etc/tmpfiles.d ] && [ -f "$SCRIPT_DIR/systemd/secretbaed.tmpfiles.conf" ]; then
        install -m 0644 "$SCRIPT_DIR/systemd/secretbaed.tmpfiles.conf" /etc/tmpfiles.d/secretbaed.conf
    fi

    echo "Reloading systemd daemon..."
    systemctl daemon-reload || true
else
    echo "Notice: /etc/systemd/system directory not found. Skipping systemd unit installation."
fi

echo "=== secretbae installation complete ==="
