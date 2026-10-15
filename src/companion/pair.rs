//! `companion pair`: turning a ticket into this Mac's `[companion]` section

use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use iroh::EndpointId;
use serde::Serialize;

use super::{IdentityError, Role, Ticket, load_or_create, short_hostname};
use crate::config::{Config, ConfigError, expand_home};

/// Why pairing failed; nothing is written unless it succeeds
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    /// The existing config is unusable, or would be with the new section
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// This Mac's key could not be loaded or created
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The config file could not be read or written
    #[error("{action}: {source}")]
    Io {
        /// What was attempted
        action: String,
        /// Underlying error
        source: std::io::Error,
    },
    /// The section could not be rendered as TOML
    #[error("cannot render the section: {0}")]
    Render(toml::ser::Error),
}

/// How pairing ended
#[derive(Debug)]
pub enum Paired {
    /// The section was appended to the config file
    Written(Pairing),
    /// The config already has a `[companion]` section, so it was left alone
    AlreadyConfigured {
        /// The section the ticket would have produced, to merge by hand
        section: String,
    },
}

/// What the gateway's owner needs to finish pairing
#[derive(Debug)]
pub struct Pairing {
    /// The section that was appended
    pub section: String,
    /// This Mac's endpoint id
    pub id: EndpointId,
    /// This Mac's short host name, as the gateway lists it
    pub name: String,
}

impl Pairing {
    /// The block to append at the end of the gateway's config; its `addrs`
    /// line is commented out because it is only needed without discovery
    pub fn gateway_entry(&self) -> String {
        format!(
            "[[secrets.companions]]\nname = {}\nid = \"{}\"\n\
             # addrs = [\"<tailnet ip>:7678\"]   # required when discovery = false",
            toml::Value::String(self.name.clone()),
            self.id
        )
    }
}

#[derive(Serialize)]
struct Section<'a> {
    companion: SectionBody<'a>,
}

#[derive(Serialize)]
struct SectionBody<'a> {
    gateway: String,
    gateway_name: &'a str,
    allow: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_file: Option<&'a Path>,
}

fn render(ticket: &Ticket, identity_file: Option<&Path>) -> Result<String, PairError> {
    toml::to_string(&Section {
        companion: SectionBody {
            gateway: ticket.gateway.to_string(),
            gateway_name: &ticket.gateway_name,
            allow: &ticket.references,
            identity_file,
        },
    })
    .map_err(PairError::Render)
}

/// Appends a `[companion]` section for `ticket` to the config at `path`,
/// creating the file when missing, and loads or creates this Mac's key
///
/// The result is parsed before anything is written, so a config that would
/// stop loading is left as it was
pub fn pair(
    ticket: &Ticket,
    path: &Path,
    identity_file: Option<&Path>,
) -> Result<Paired, PairError> {
    let io = |action: String| move |source| PairError::Io { action, source };

    // the config is read by a LaunchAgent started elsewhere, so a relative
    // path would name a different key there
    let identity_file = absolute_identity(identity_file)?;
    let identity_file = identity_file.as_deref();
    let existing = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            }
            .into());
        }
    };
    let section = render(ticket, identity_file)?;
    if Config::parse(&existing, path)?.companion.is_some() {
        return Ok(Paired::AlreadyConfigured { section });
    }

    // a blank line apart from whatever the file ends with
    let separator = match existing.as_bytes() {
        [] => "",
        bytes if bytes.ends_with(b"\n\n") => "",
        bytes if bytes.ends_with(b"\n") => "\n",
        _ => "\n\n",
    };
    let addition = format!("{separator}{section}");
    Config::parse(&format!("{existing}{addition}"), path)?;

    let key = load_or_create(Role::Companion, identity_file)?;

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(io(format!("create {}", parent.display())))?;
    }
    std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(addition.as_bytes()))
        .map_err(io(format!("write {}", path.display())))?;

    Ok(Paired::Written(Pairing {
        section,
        id: key.public(),
        name: short_hostname(),
    }))
}

/// This Mac's companion endpoint id
pub fn companion_id(identity_file: Option<&Path>) -> Result<EndpointId, IdentityError> {
    let identity_file = absolute_identity(identity_file)?;

    Ok(load_or_create(Role::Companion, identity_file.as_deref())?.public())
}

/// `file` with `~` expanded and made absolute against the working directory
fn absolute_identity(file: Option<&Path>) -> Result<Option<PathBuf>, IdentityError> {
    file.map(|file| {
        std::path::absolute(expand_home(file)).map_err(|source| IdentityError::File {
            path: file.to_owned(),
            source,
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::Pairing;
    use crate::config::Config;

    #[test]
    fn the_gateway_entry_keeps_an_odd_host_name_inside_its_string() {
        let id = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let pairing = Pairing {
            section: String::new(),
            id,
            name: "mba\" ] [[secrets.companions]] name = \"x".to_owned(),
        };

        let config = Config::parse(&pairing.gateway_entry(), Path::new("gateway.toml"));
        let companions = config.map(|config| config.secrets.companions);
        let names: Vec<String> = companions
            .unwrap_or_default()
            .into_iter()
            .map(|peer| peer.name)
            .collect();
        assert_eq!(names, [pairing.name]);
    }
}
