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
    cargo test --workspace {{args}}

# ------------------------------------------------------------------------------
# lint
# ------------------------------------------------------------------------------

[group('lint')]
fmt *args="":
    cargo fmt --all {{args}}

[group('lint')]
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# every `just <recipe>` the docs mention must exist, so they cannot drift
# from this file
[group('lint')]
[script('bash')]
docs-check:
    set -euo pipefail

    recipes=" $(just --summary) "
    missing=0
    while read -r recipe; do
        if [[ "$recipes" != *" $recipe "* ]]; then
            echo "docs mention \`just $recipe\`, which is not a recipe" >&2
            missing=1
        fi
    done < <(grep -rhoE '`just [a-z][a-z0-9-]*' README.md docs mobile ios --include='*.md' | sed 's/`just //' | sort -u)
    exit "$missing"

[group('ci')]
[script('bash')]
ci:
    set -euo pipefail
    just fmt -- --check
    just clippy
    just docs-check
    just test

# ------------------------------------------------------------------------------
# ios
# ------------------------------------------------------------------------------

# Build the Rust core for iOS and refresh the CompanionCore Swift package. Flags: --release --sim
[group('ios')]
ios-core *flags="":
    cargo xtask build-ios {{flags}}

# Generate ios/Companion.xcodeproj from ios/project.yml
[group('ios')]
ios-project:
    cargo xtask project

# Build, install and launch the companion on the iPhone named by IOS_DEVICE_UDID (.envrc) or --udid
[group('ios')]
ios-run *flags="":
    cargo xtask run-ios {{flags}}

# Archive a release build and upload it to TestFlight; needs ASC_API_KEY_PATH, ASC_API_KEY_ID and ASC_API_ISSUER_ID
[group('ios')]
ios-testflight:
    cargo xtask testflight
