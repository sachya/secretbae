#!/bin/sh
# Build the Debian package.
#
# Run on the target architecture, or in a container of it -- the .deb carries compiled
# binaries, so cross-building needs a matching toolchain rather than just cargo.
set -eu

cargo install cargo-deb --locked
cargo build --release -p sbae-daemon -p sbae-cli
cargo deb -p sbae-daemon --no-build -o dist/

echo
echo "Built:"
ls -la dist/*.deb
