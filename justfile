[default]
list:
    @just --list

# ------------------------------------------------------------------------------
# build
# ------------------------------------------------------------------------------

[group('build')]
build:
    cargo build

[group('build')]
build-release:
    cargo build --release

# commits and pushes the bump because `release github` tags HEAD and needs it on
# origin, so `just bump minor && just release` works in one go

# Bump the Cargo.toml version, commit it as "Release vX.Y.Z" and push. Part: major | minor | patch
[group('build')]
[script('bash')]
bump part:
    set -euo pipefail

    if ! git diff --quiet HEAD -- Cargo.toml Cargo.lock; then
        echo "Cargo.toml or Cargo.lock has uncommitted changes; commit or stash them before bump" >&2
        exit 1
    fi

    current="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "codemode-mcp") | .version')"
    IFS=. read -r major minor patch <<< "${current%%[-+]*}"

    case "{{part}}" in
        major) next="$((major + 1)).0.0" ;;
        minor) next="$major.$((minor + 1)).0" ;;
        patch) next="$major.$minor.$((patch + 1))" ;;
        *)
            echo "unknown part '{{part}}'; use major, minor or patch" >&2
            exit 1
            ;;
    esac

    # only the first `version` line under [package], not dependency tables
    awk -v next_version="$next" '
        /^\[/ { in_package = ($0 == "[package]") }
        in_package && !done && /^version = / { print "version = \"" next_version "\""; done = 1; next }
        { print }
    ' Cargo.toml > Cargo.toml.tmp
    mv Cargo.toml.tmp Cargo.toml

    # refreshes the root package entry in Cargo.lock without touching dependencies
    cargo metadata --format-version 1 > /dev/null

    git add Cargo.toml Cargo.lock
    git commit --quiet -m "Release v$next"
    git push --quiet origin HEAD

    echo "Bumped $current -> $next and pushed"

# github tags the Cargo.toml version and pushes it to run the Release workflow
# (run `just bump` first); local builds, then `service install` signs and loads
# the binary and the Monty worker

# Release via GitHub Actions (default) or install a signed build here. Place: github | gh | public | local
[group('build')]
[script('bash')]
release place="github":
    set -euo pipefail

    case "{{place}}" in
        local)
            cargo build --release
            ./target/release/codemode-mcp service install
            ;;
        github | gh | public)
            if ! git diff --quiet HEAD -- Cargo.toml Cargo.lock; then
                echo "Cargo.toml or Cargo.lock has uncommitted changes; commit the version bump before release" >&2
                exit 1
            fi

            version="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "codemode-mcp") | .version')"
            tag="v$version"

            if [[ -n "$(git tag -l "$tag")" ]]; then
                echo "git tag $tag already exists locally" >&2
                exit 1
            fi

            if [[ -n "$(git ls-remote --tags origin "refs/tags/$tag")" ]]; then
                echo "git tag $tag already exists on origin" >&2
                exit 1
            fi

            # the workflow builds the tagged commit, so it has to be on origin
            git fetch --quiet origin
            if [[ -z "$(git branch -r --contains HEAD)" ]]; then
                echo "HEAD is not on any origin branch; push it before release" >&2
                exit 1
            fi

            git tag "$tag"
            git push origin "$tag"

            echo "Pushed tag $tag to origin"
            echo "Watch: gh run list --workflow Release"
            echo "Install: curl -LSfs https://github.com/avencera/codemode-mcp/releases/latest/download/install.sh | sh"
            ;;
        *)
            echo "unknown place '{{place}}'; use github, gh, public or local" >&2
            exit 1
            ;;
    esac

[private]
alias br := build-release

# ------------------------------------------------------------------------------
# test
# ------------------------------------------------------------------------------

[group('test')]
test *args="":
    cargo test {{args}}

# ------------------------------------------------------------------------------
# lint
# ------------------------------------------------------------------------------

[group('lint')]
fmt *args="":
    cargo fmt --all {{args}}

[group('lint')]
clippy:
    cargo clippy --all-targets -- -D warnings

[group('ci')]
[script('bash')]
ci:
    set -euo pipefail
    just fmt -- --check
    just clippy
    just test
