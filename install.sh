#!/bin/sh
# Install codemode-mcp from GitHub Releases.
#
# One-liner (macOS on Apple silicon):
#   curl -LSfs https://github.com/praveenperera/codemode-mcp/releases/latest/download/install.sh | sh
#
# The archive is checked against the release checksum and the Developer ID
# signature before anything in it runs. The downloaded binary then installs
# itself with `codemode-mcp update`, so the binary, the Monty worker and the
# service restart follow one code path

set -eu

REPO="praveenperera/codemode-mcp"
TARGET="aarch64-apple-darwin"
# the team and identifier `service install` and the release workflow sign with
REQUIREMENT='anchor apple generic and certificate leaf[subject.OU] = "Q8UP8C53Y8" and identifier "com.avencera.codemode-mcp"'

help() {
    cat <<EOF
Install a binary release of codemode-mcp from GitHub.

Usage:
    curl -LSfs https://github.com/${REPO}/releases/latest/download/install.sh | sh
    curl -LSfs https://github.com/${REPO}/releases/latest/download/install.sh | sh -s -- --tag v0.1.0

Installs ~/.local/bin/codemode-mcp and ~/.local/share/codemode-mcp/monty, and
restarts the service if it is installed.

Options:
    -h, --help      Display this message
    --tag TAG       Release tag (default latest)
    -f, --force     Reinstall even when that release is already installed
EOF
}

say() {
    echo "install.sh: $1" >&2
}

td=""

err() {
    if [ -n "$td" ]; then
        rm -rf "$td"
    fi

    say "ERROR $1"
    exit 1
}

need() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "need $1 (command not found)"
    fi
}

tag=""
force=""

while test $# -gt 0; do
    case $1 in
        --help | -h)
            help
            exit 0
            ;;
        --tag)
            case ${2:-} in
                "" | -*) err "--tag requires a value" ;;
            esac
            tag=$2
            shift
            ;;
        --force | -f)
            force="--force"
            ;;
        *)
            err "unknown option: $1"
            ;;
    esac
    shift
done

if [ "$(uname -s)/$(uname -m)" != "Darwin/arm64" ]; then
    err "releases are built for macOS on Apple silicon only, not $(uname -s)/$(uname -m)"
fi

need curl
need tar
need shasum
need codesign
need mktemp

url="https://github.com/$REPO"

if [ -z "$tag" ]; then
    latest_url=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$url/releases/latest") \
        || err "failed to resolve the latest release of $REPO"
    case "$latest_url" in
        */releases/tag/*) ;;
        *) err "no GitHub release found for $REPO" ;;
    esac
    tag=${latest_url##*/}
fi

archive="codemode-mcp-$tag-$TARGET"
say "installing $tag"

td=$(mktemp -d 2>/dev/null || mktemp -d -t codemode-install)
curl -fsSL "$url/releases/download/$tag/$archive.tar.gz" -o "$td/$archive.tar.gz" \
    || err "$url/releases/download/$tag/$archive.tar.gz does not exist"
curl -fsSL "$url/releases/download/$tag/$archive.sha256" -o "$td/$archive.sha256" \
    || err "the checksum for $tag does not exist"
(cd "$td" && shasum -a 256 -c "$archive.sha256" > /dev/null) \
    || err "$archive.tar.gz does not match its published checksum"

tar -C "$td" -xzf "$td/$archive.tar.gz" || err "failed to extract $archive.tar.gz"
codesign --verify --strict -R "=$REQUIREMENT" "$td/codemode-mcp" \
    || err "the codemode-mcp in $tag is not signed by the expected Developer ID"

# `update` downloads and checks the release again on its own, then installs
# the binary and worker and restarts a loaded service
"$td/codemode-mcp" update --tag "$tag" $force || err "codemode-mcp update failed"

rm -rf "$td"
td=""

case ":$PATH:" in
    *:"$HOME/.local/bin":*) ;;
    *) say "warning: $HOME/.local/bin is not on PATH" ;;
esac
