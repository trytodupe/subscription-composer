#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "ikuuu-login requires macOS." >&2
    exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$repo_root/bin"
cd "$repo_root"

nix develop "$HOME/flake/develop" -c /usr/bin/clang \
    -fobjc-arc -fno-modules -framework Cocoa -framework WebKit \
    tools/ikuuu-login.m -o bin/ikuuu-login
