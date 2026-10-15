//! Replace the installed binary and Monty worker from a GitHub release
//!
//! A release archive holds both, already signed in CI with the Developer ID
//! `service install` signs local builds with, so the files are swapped as
//! they are and macOS and the 1Password app keep their grants. Nothing is
//! replaced unless the archive matches its published checksum and both
//! signatures satisfy that team and the expected identifiers

use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

use crate::service::{self, ServiceError, ServicePaths};

/// GitHub repository that publishes the releases
pub const REPOSITORY: &str = "avencera/codemode-mcp";
/// The only target releases are built for, since the service is a launchd
/// agent
const TARGET: &str = "aarch64-apple-darwin";
/// Name of the Monty worker inside a release archive
const WORKER: &str = "monty";

/// Failures fetching or installing a release
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// This machine cannot run a release build
    #[error("releases are built for {TARGET} only, not {0}")]
    UnsupportedPlatform(String),
    /// A request could not be sent or read
    #[error("request to {url} failed: {source}")]
    Http {
        /// URL requested
        url: String,
        /// Underlying error
        source: reqwest::Error,
    },
    /// A URL answered with an error status
    #[error("{url} answered {status}{hint}")]
    Status {
        /// URL requested
        url: String,
        /// Status received
        status: reqwest::StatusCode,
        /// Likely cause, when one is known
        hint: &'static str,
    },
    /// The `releases/latest` redirect did not end at a tag page
    #[error("{0} did not lead to a release tag")]
    NoTag(String),
    /// The archive does not match its published checksum
    #[error("{asset} has sha256 {actual}, but the release publishes {expected}")]
    Checksum {
        /// Archive name
        asset: String,
        /// Checksum from the release
        expected: String,
        /// Checksum of the download
        actual: String,
    },
    /// The archive lacks an executable it must contain
    #[error("the release archive has no executable `{0}`")]
    MissingFile(String),
    /// An executable is unsigned or signed by someone else
    #[error("{} does not satisfy `{requirement}`: {detail}", path.display())]
    Signature {
        /// Executable checked
        path: PathBuf,
        /// Code signing requirement it failed
        requirement: String,
        /// codesign's explanation
        detail: String,
    },
    /// A file operation failed
    #[error("{action}: {source}")]
    Io {
        /// What was attempted
        action: String,
        /// Underlying error
        source: std::io::Error,
    },
    /// A command such as tar or codesign failed
    #[error(transparent)]
    Service(#[from] ServiceError),
}

fn io(action: impl Into<String>) -> impl FnOnce(std::io::Error) -> UpdateError {
    let action = action.into();

    move |source| UpdateError::Io { action, source }
}

/// Where releases come from and whose signature they must carry
#[derive(Debug, Clone)]
pub struct Source {
    /// `https://github.com/<owner>/<repo>`, without a trailing slash
    pub base_url: String,
    /// Code signing requirement every executable must meet, before its
    /// identifier is added
    pub anchor: String,
}

impl Source {
    /// The GitHub repository, signed by the team in [`service::SIGNING_IDENTITY`]
    pub fn github() -> Self {
        Self {
            base_url: format!("https://github.com/{REPOSITORY}"),
            anchor: service::team_anchor(),
        }
    }

    /// [`Source::github`], with `CODEMODE_UPDATE_BASE_URL` and
    /// `CODEMODE_UPDATE_ANCHOR` replacing its parts; the tests serve a
    /// release locally and sign it ad hoc
    pub fn from_env() -> Self {
        let mut source = Self::github();
        let set = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        if let Some(base_url) = set("CODEMODE_UPDATE_BASE_URL") {
            source.base_url = base_url.trim_end_matches('/').to_owned();
        }
        if let Some(anchor) = set("CODEMODE_UPDATE_ANCHOR") {
            source.anchor = anchor;
        }

        source
    }

    /// Tag of the latest release, read from where `releases/latest` redirects
    pub async fn latest_tag(&self, client: &reqwest::Client) -> Result<String, UpdateError> {
        let url = format!("{}/releases/latest", self.base_url);
        let response = get(client, &url).await?;
        let landed = response.url().as_str().trim_end_matches('/');

        match landed.rsplit_once("/releases/tag/") {
            Some((_, tag)) if !tag.is_empty() && !tag.contains('/') => Ok(tag.to_owned()),
            _ => Err(UpdateError::NoTag(url)),
        }
    }

    /// Archive name for `tag`
    pub fn asset(tag: &str) -> String {
        format!("{}.tar.gz", Self::archive(tag))
    }

    /// Checksum file name for `tag`, which lists every archive
    pub fn checksums(tag: &str) -> String {
        format!("{}.sha256", Self::archive(tag))
    }

    fn archive(tag: &str) -> String {
        format!("codemode-mcp-{tag}-{TARGET}")
    }

    fn download_url(&self, tag: &str, asset: &str) -> String {
        format!("{}/releases/download/{tag}/{asset}", self.base_url)
    }
}

/// Fails unless this machine can run a release build
pub fn check_platform() -> Result<(), UpdateError> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok(()),
        (os, arch) => Err(UpdateError::UnsupportedPlatform(format!("{os}/{arch}"))),
    }
}

/// The version tag (`v1.2.3`) of the binary at `path`, if it runs and says
pub fn installed_tag(path: &Path) -> Option<String> {
    let output = Command::new(path).arg("--version").output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let version = text.trim().strip_prefix("codemode-mcp ")?;

    Some(format!("v{version}"))
}

/// The numeric `(major, minor, patch)` of a tag such as `v1.2.3`; a
/// pre-release suffix is ignored
pub fn version(tag: &str) -> Option<(u64, u64, u64)> {
    let core = tag.strip_prefix('v')?.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());

    match (parts.next()?, parts.next()?, parts.next()?, parts.next()) {
        (Some(major), Some(minor), Some(patch), None) => Some((major, minor, patch)),
        _ => None,
    }
}

/// A downloaded release whose checksum and signatures passed, unpacked in a
/// temporary directory that is removed on drop
#[derive(Debug)]
pub struct Release {
    /// Release tag
    pub tag: String,
    directory: TempDir,
}

impl Release {
    /// Downloads `tag`, checks it against its published checksum, unpacks it
    /// and checks both signatures
    pub async fn fetch(
        source: &Source,
        tag: &str,
        client: &reqwest::Client,
    ) -> Result<Self, UpdateError> {
        let asset = Source::asset(tag);
        let url = source.download_url(tag, &asset);
        println!("downloading {url}");
        let archive = read(get(client, &url).await?, &url).await?;
        let sums_url = source.download_url(tag, &Source::checksums(tag));
        let sums = read(get(client, &sums_url).await?, &sums_url).await?;

        // `sha256sum` lines, `<hex>  <file>`, as the release workflow's `shasum -a 256` writes them
        let expected = String::from_utf8_lossy(&sums)
            .lines()
            .find_map(|line| {
                let (sum, file) = line.split_once(char::is_whitespace)?;
                (file.trim_start().trim_start_matches('*') == asset)
                    .then(|| sum.to_ascii_lowercase())
            })
            .unwrap_or_default();
        let actual = hex(&Sha256::digest(&archive));
        if expected != actual {
            return Err(UpdateError::Checksum {
                asset,
                expected,
                actual,
            });
        }

        let directory = TempDir::create()?;
        let path = directory.0.join(&asset);
        std::fs::write(&path, &archive).map_err(io(format!("write {}", path.display())))?;
        service::run_command(&[
            "tar".into(),
            "-xzf".into(),
            path.display().to_string(),
            "-C".into(),
            directory.0.display().to_string(),
        ])?;

        let release = Self {
            tag: tag.to_owned(),
            directory,
        };
        for name in ["codemode-mcp", WORKER] {
            release.verify(source, name)?;
        }

        Ok(release)
    }

    /// Replaces the installed binary and worker; the worker goes first, so
    /// the new binary never starts against the old worker
    pub fn install(&self, paths: &ServicePaths) -> Result<(), UpdateError> {
        replace(&self.file(WORKER), &paths.worker)?;
        replace(&self.file("codemode-mcp"), &paths.binary)?;

        Ok(())
    }

    fn file(&self, name: &str) -> PathBuf {
        self.directory.0.join(name)
    }

    fn verify(&self, source: &Source, name: &str) -> Result<(), UpdateError> {
        let path = self.file(name);
        // a symlink could point an install at any file on the machine
        let executable = std::fs::symlink_metadata(&path)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0);
        if !executable {
            return Err(UpdateError::MissingFile(name.to_owned()));
        }

        let requirement = format!(
            "{} and identifier \"{}\"",
            source.anchor,
            service::signing_identifier(Path::new(name))
        );
        let checked = Command::new("codesign")
            .args(["--verify", "--strict", "-R"])
            .arg(format!("={requirement}"))
            .arg(&path)
            .output()
            .map_err(io("run codesign"))?;
        if checked.status.success() {
            return Ok(());
        }

        Err(UpdateError::Signature {
            path,
            requirement,
            detail: String::from_utf8_lossy(&checked.stderr).trim().to_owned(),
        })
    }
}

async fn get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response, UpdateError> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|source| UpdateError::Http {
            url: url.to_owned(),
            source,
        })?;
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    Err(UpdateError::Status {
        url: url.to_owned(),
        status,
        // GitHub answers 404 rather than 403 for a private repository
        hint: if status == reqwest::StatusCode::NOT_FOUND {
            "; the release may not exist, or the repository is private"
        } else {
            ""
        },
    })
}

async fn read(response: reqwest::Response, url: &str) -> Result<Vec<u8>, UpdateError> {
    let bytes = response.bytes().await.map_err(|source| UpdateError::Http {
        url: url.to_owned(),
        source,
    })?;

    Ok(bytes.to_vec())
}

/// Copies beside the target and renames, so a running daemon keeps its old
/// inode; unlike `service install`, the copy is not re-signed
fn replace(from: &Path, to: &Path) -> Result<(), UpdateError> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(io(format!("create {}", parent.display())))?;
    }

    let temporary = to.with_extension(format!("update-{}", std::process::id()));
    let copied = std::fs::copy(from, &temporary)
        .map_err(io(format!("copy to {}", temporary.display())))
        .and_then(|_| {
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755))
                .map_err(io(format!("chmod {}", temporary.display())))
        })
        .and_then(|()| {
            std::fs::rename(&temporary, to).map_err(io(format!("rename to {}", to.display())))
        });
    if copied.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }

    copied
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug)]
struct TempDir(PathBuf);

impl TempDir {
    fn create() -> Result<Self, UpdateError> {
        let path = std::env::temp_dir().join(format!("codemode-update-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(io(format!("create {}", path.display())))?;

        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn versions_compare_numerically_and_reject_other_tags() {
        assert!(version("v0.10.0") > version("v0.9.3"));
        assert_eq!(version("v1.2.3-rc.1"), Some((1, 2, 3)));
        for tag in ["1.2.3", "v1.2", "v1.2.3.4", "vx.2.3", "latest"] {
            assert_eq!(version(tag), None, "{tag}");
        }
    }
}
