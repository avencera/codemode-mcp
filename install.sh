#!/bin/sh
# Install codemode-mcp from GitHub Releases.
#
# One-liner (macOS on Apple silicon, or x86_64 Linux for a spoke):
#   curl -LSfs https://github.com/avencera/codemode-mcp/releases/latest/download/install.sh | sh
#
# The archive is checked against the release checksum and, on macOS, the
# Developer ID signature before anything in it runs. The downloaded binary then installs
# itself with `codemode-mcp update`, so the binary, the Monty worker and the
# service restart follow one code path

set -eu

REPO="avencera/codemode-mcp"
# the team and identifier `service install` and the release workflow sign with
REQUIREMENT='anchor apple generic and certificate leaf[subject.OU] = "Q8UP8C53Y8" and identifier "com.avencera.codemode-mcp"'

help() {
    cat <<EOF
Install a binary release of codemode-mcp from GitHub.

Usage:
    curl -LSfs https://github.com/${REPO}/releases/latest/download/install.sh | sh
    curl -LSfs https://github.com/${REPO}/releases/latest/download/install.sh | sh -s -- --tag v0.1.0
    curl -LSfs https://github.com/${REPO}/releases/latest/download/install.sh | sh -s -- --pair TICKET

Installs ~/.local/bin/codemode-mcp and ~/.local/share/codemode-mcp/monty, and
restarts the service if it is installed.

Options:
    -h, --help      Display this message
    --tag TAG       Release tag (default latest)
    -f, --force     Reinstall even when that release is already installed
    --pair TICKET   Then set this Mac up as a companion with a ticket from
                    \`codemode-mcp companion invite\` on the gateway Mac
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
pair=""

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
        --pair)
            # checked before installing, so a mangled paste fails fast
            case ${2:-} in
                cmcp*) ;;
                *) err "--pair requires a ticket from \`codemode-mcp companion invite\`" ;;
            esac
            pair=$2
            shift
            ;;
        *)
            err "unknown option: $1"
            ;;
    esac
    shift
done

case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)
        TARGET="aarch64-apple-darwin"
        ;;
    Linux/x86_64)
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    *)
        err "releases are built for macOS on Apple silicon and x86_64 Linux only, not $(uname -s)/$(uname -m); build from source (see docs/operations.md, \"Spokes\")"
        ;;
esac

# the companion is a macOS LaunchAgent
if [ -n "$pair" ] && [ "$TARGET" != "aarch64-apple-darwin" ]; then
    err "--pair sets up a Mac companion; on Linux, set up a spoke instead (see docs/operations.md, \"Spokes\")"
fi

need curl
need tar
need mktemp
if [ "$TARGET" = "aarch64-apple-darwin" ]; then
    need shasum
    need codesign
    sha256_check() { shasum -a 256 -c "$1"; }
else
    need sha256sum
    sha256_check() { sha256sum -c "$1"; }
fi

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
(cd "$td" && sha256_check "$archive.sha256" > /dev/null) \
    || err "$archive.tar.gz does not match its published checksum"

tar -C "$td" -xzf "$td/$archive.tar.gz" || err "failed to extract $archive.tar.gz"
# Linux releases are unsigned, so there only the checksum vouches for them
if [ "$TARGET" = "aarch64-apple-darwin" ]; then
    codesign --verify --strict -R "=$REQUIREMENT" "$td/codemode-mcp" \
        || err "the codemode-mcp in $tag is not signed by the expected Developer ID"
fi

# `update` downloads and checks the release again on its own, then installs
# the binary and worker and restarts a loaded service
"$td/codemode-mcp" update --tag "$tag" $force || err "codemode-mcp update failed"

rm -rf "$td"
td=""

case ":$PATH:" in
    *:"$HOME/.local/bin":*) ;;
    *) say "warning: $HOME/.local/bin is not on PATH" ;;
esac

# the installed, signed copy, so the companion key it creates in the login
# keychain is readable by the agent without a prompt
if [ -n "$pair" ]; then
    "$HOME/.local/bin/codemode-mcp" companion pair "$pair" \
        || err "codemode-mcp is installed, but pairing failed"
fi
