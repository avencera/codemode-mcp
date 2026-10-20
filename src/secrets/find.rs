//! Finding which 1Password items match a query, for a program that does not
//! know the exact reference, and which logins are saved for a website
//!
//! `op item list` gives titles, vaults, tags, categories and websites
//! without values, so items are matched on those alone. Only the best
//! matches are opened with `op item get`, whose JSON does hold values: only
//! each field's reference, label, type, purpose and section, and each file's
//! name, are copied out of it

use std::collections::HashMap;

use companion_wire::wire::{Found, FoundField, FoundItem, MAX_FOUND_ITEMS};
use serde::Deserialize;

use super::{MAX_OP_ERROR_CHARS, OnePassword, READ_TIMEOUT, is_reference, spawn};

/// Why a find gave no items; no message holds a value
#[derive(Debug, thiserror::Error)]
pub enum FindError {
    /// `op` could not be started
    #[error("failed to start `{program}`: {source}")]
    Spawn {
        /// Program that failed
        program: String,
        /// Underlying error
        #[source]
        source: std::io::Error,
    },
    /// `op` took longer than one read may
    #[error("`op {command}` did not answer within {timeout:?}")]
    TimedOut {
        /// The subcommand
        command: &'static str,
        /// How long it was given
        timeout: std::time::Duration,
    },
    /// `op` failed or printed something that is not an item
    #[error("`op {command}` failed: {reason}")]
    Failed {
        /// The subcommand
        command: &'static str,
        /// Its first line of error output, or what was wrong with its answer
        reason: String,
    },
}

/// One entry of `op item list --format json`, which holds no values
#[derive(Deserialize)]
struct Listed {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vault: Named,
    #[serde(default)]
    urls: Vec<ListedUrl>,
}

/// One website an item is saved for
#[derive(Deserialize)]
struct ListedUrl {
    #[serde(default)]
    href: String,
}

#[derive(Default, Deserialize)]
struct Named {
    #[serde(default)]
    id: String,
    #[serde(default, alias = "label")]
    name: String,
}

/// What is read of `op item get --format json`; serde skips everything
/// else, values included
#[derive(Deserialize)]
struct Opened {
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    vault: Named,
    #[serde(default)]
    fields: Vec<OpenedField>,
    #[serde(default)]
    files: Vec<OpenedFile>,
}

#[derive(Deserialize)]
struct OpenedField {
    #[serde(default)]
    id: String,
    #[serde(default)]
    purpose: String,
    #[serde(default)]
    label: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    section: Option<Named>,
}

#[derive(Deserialize)]
struct OpenedFile {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    section: Option<Named>,
}

/// A Login item and the hosts of the websites it is saved for, as `op item
/// list` names them; never a value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedLogin {
    /// The item's ID
    pub id: String,
    /// Its title
    pub title: String,
    /// ID of the vault it is in
    pub vault_id: String,
    /// Name of that vault
    pub vault: String,
    /// Lowercase hosts of its saved websites, such as `github.com`
    pub hosts: Vec<String>,
}

/// Which field of a Login item to read
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginPart {
    /// The field 1Password fills as the username
    Username,
    /// The field 1Password fills as the password
    Password,
    /// The first one-time password field
    OneTimePassword,
}

impl OnePassword {
    /// Every Login item on this Mac, with the websites it is saved for, with
    /// no cache and no companions; the caller decides whether the owner must
    /// be asked first
    pub async fn saved_logins(&self) -> Result<Vec<SavedLogin>, FindError> {
        let list = self
            .op(
                "item list",
                &["item", "list", "--categories", "Login", "--format", "json"],
            )
            .await?;
        let listed: Vec<Listed> = serde_json::from_slice(&list).map_err(|_| FindError::Failed {
            command: "item list",
            reason: "the answer was not a JSON list of items".to_owned(),
        })?;

        Ok(listed
            .into_iter()
            .map(|item| SavedLogin {
                hosts: item
                    .urls
                    .iter()
                    .filter_map(|url| website_host(&url.href))
                    .collect(),
                id: item.id,
                title: item.title,
                vault_id: item.vault.id,
                vault: item.vault.name,
            })
            .collect())
    }

    /// The reference of `login`'s `part`, by IDs so a title shared by two
    /// items or holding a `/` cannot change which is read; `None` when the
    /// item has no such field
    pub async fn login_reference(
        &self,
        login: &SavedLogin,
        part: LoginPart,
    ) -> Result<Option<String>, FindError> {
        let vault = first_set(&login.vault_id, &login.vault);
        let json = self
            .op(
                "item get",
                &[
                    "item", "get", &login.id, "--vault", vault, "--format", "json",
                ],
            )
            .await?;
        let opened: Opened = serde_json::from_slice(&json).map_err(|_| FindError::Failed {
            command: "item get",
            reason: "the answer was not a JSON item".to_owned(),
        })?;

        Ok(login_field(&opened, part).map(|(section, field)| {
            let mut reference = format!("op://{vault}/{}", login.id);
            if let Some(section) = section {
                reference.push('/');
                reference.push_str(section);
            }
            reference.push('/');
            reference.push_str(field);

            reference
        }))
    }

    /// The items on this Mac matching each of `queries`, in order, best
    /// first, with no cache and no companions; the caller asks the owner
    /// first
    ///
    /// Each word of a query counts once when it is in an item's title,
    /// vault, tags or category, ignoring case; items matching no word are
    /// left out. At most [`MAX_FOUND_ITEMS`] are opened and answered per
    /// query. The list is read once, and an item two queries match is
    /// opened once
    pub async fn find_local_each(&self, queries: &[String]) -> Result<Vec<Found>, FindError> {
        let list = self
            .op("item list", &["item", "list", "--format", "json"])
            .await?;
        let listed: Vec<Listed> = serde_json::from_slice(&list).map_err(|_| FindError::Failed {
            command: "item list",
            reason: "the answer was not a JSON list of items".to_owned(),
        })?;

        let mut opened: HashMap<&str, FoundItem> = HashMap::new();
        let mut answers = Vec::with_capacity(queries.len());
        for query in queries {
            let best = best_matches(&listed, query);
            let more = best.len().saturating_sub(MAX_FOUND_ITEMS);
            let mut items = Vec::with_capacity(best.len().min(MAX_FOUND_ITEMS));
            for listed in best.into_iter().take(MAX_FOUND_ITEMS) {
                let item = match opened.get(listed.id.as_str()) {
                    Some(item) => item.clone(),
                    None => {
                        let item = self.open(listed).await?;
                        opened.insert(&listed.id, item.clone());

                        item
                    }
                };
                items.push(item);
            }
            answers.push(Found { items, more });
        }

        Ok(answers)
    }

    /// The item `listed` names as a find answers it, read with `op item get`
    async fn open(&self, listed: &Listed) -> Result<FoundItem, FindError> {
        let vault = first_set(&listed.vault.id, &listed.vault.name);
        let json = self
            .op(
                "item get",
                &[
                    "item", "get", &listed.id, "--vault", vault, "--format", "json",
                ],
            )
            .await?;
        let opened: Opened = serde_json::from_slice(&json).map_err(|_| FindError::Failed {
            command: "item get",
            reason: "the answer was not a JSON item".to_owned(),
        })?;

        Ok(found_item(opened, listed))
    }

    /// Runs `op` with `args` and returns what it printed; only one line of
    /// its error output is kept, cut short
    async fn op(&self, command: &'static str, args: &[&str]) -> Result<Vec<u8>, FindError> {
        let output = tokio::time::timeout(READ_TIMEOUT, spawn::output(&self.program, args, None))
            .await
            .map_err(|_| FindError::TimedOut {
                command,
                timeout: READ_TIMEOUT,
            })?
            .map_err(|error| FindError::Spawn {
                program: self.program.clone(),
                source: error.into_io(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let line = stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("no error output");

            return Err(FindError::Failed {
                command,
                reason: format!(
                    "{} ({})",
                    crate::prompt::one_line(line.trim(), MAX_OP_ERROR_CHARS),
                    output.status
                ),
            });
        }

        Ok(output.stdout)
    }
}

/// The items of `listed` matching any word of `query`, those matching more
/// words first and then by title
fn best_matches<'a>(listed: &'a [Listed], query: &str) -> Vec<&'a Listed> {
    let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let mut scored: Vec<(usize, &Listed)> = listed
        .iter()
        .map(|item| {
            let text = format!(
                "{} {} {} {}",
                item.title,
                item.vault.name,
                item.tags.join(" "),
                item.category
            )
            .to_lowercase();
            let score = words.iter().filter(|word| text.contains(*word)).count();

            (score, item)
        })
        .filter(|(score, _)| *score > 0)
        .collect();
    scored.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| left.title.to_lowercase().cmp(&right.title.to_lowercase()))
    });

    scored.into_iter().map(|(_, item)| item).collect()
}

/// The item as a find answers it: each field `op` gave a reference, and
/// each attached file, whose reference is built as 1Password documents it,
/// `op://vault/item/[section/]file`, with an ID for any name it cannot hold
fn found_item(opened: Opened, listed: &Listed) -> FoundItem {
    let vault_name = first_set(&opened.vault.name, &listed.vault.name);
    let vault_id = first_set(&opened.vault.id, &listed.vault.id);
    let title = first_set(&opened.title, &listed.title);
    let category = first_set(&opened.category, &listed.category);

    let mut fields: Vec<FoundField> = opened
        .fields
        .into_iter()
        .filter_map(|field| {
            let reference = field
                .reference
                .filter(|reference| is_reference(reference))?;

            Some(FoundField {
                reference,
                label: field.label,
                kind: field.kind.to_lowercase(),
                section: section_label(field.section.as_ref()),
            })
        })
        .collect();
    for file in opened.files {
        let mut segments = vec![segment(vault_name, vault_id), segment(title, &opened.id)];
        if let Some(section) = &file.section
            && !section.id.is_empty()
        {
            segments.push(segment(&section.name, &section.id));
        }
        segments.push(segment(&file.name, &file.id));
        let reference = format!("op://{}", segments.join("/"));
        if is_reference(&reference) {
            fields.push(FoundField {
                reference,
                label: file.name,
                kind: "file".to_owned(),
                section: section_label(file.section.as_ref()),
            });
        }
    }

    FoundItem {
        vault: vault_name.to_owned(),
        title: title.to_owned(),
        category: category.to_owned(),
        fields,
    }
}

/// The section ID, when the field is in one, and the field ID of `opened`'s
/// `part`; 1Password marks a Login's own username and password fields by
/// purpose, whatever their labels
fn login_field(opened: &Opened, part: LoginPart) -> Option<(Option<&str>, &str)> {
    let field = opened.fields.iter().find(|field| match part {
        LoginPart::Username => field.purpose.eq_ignore_ascii_case("USERNAME"),
        LoginPart::Password => field.purpose.eq_ignore_ascii_case("PASSWORD"),
        LoginPart::OneTimePassword => field.kind.eq_ignore_ascii_case("OTP"),
    })?;
    if field.id.is_empty() {
        return None;
    }
    let section = field
        .section
        .as_ref()
        .map(|section| section.id.as_str())
        .filter(|id| !id.is_empty());

    Some((section, field.id.as_str()))
}

/// The lowercase host of a saved website; 1Password keeps what the owner
/// typed, so `github.com` without a scheme counts as `https://github.com`.
/// Addresses other than web ones, such as an app's, have none
fn website_host(href: &str) -> Option<String> {
    let href = href.trim();
    // `github.com:8443` parses with `github.com` as its scheme, which a real
    // scheme such as `mailto` never holds; read either as a bare host
    let url = match reqwest::Url::parse(href) {
        Ok(url) if !url.scheme().contains('.') => url,
        _ => reqwest::Url::parse(&format!("https://{href}")).ok()?,
    };
    if !matches!(url.scheme(), "https" | "http") {
        return None;
    }

    url.host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
}

fn first_set<'a>(first: &'a str, second: &'a str) -> &'a str {
    if first.is_empty() { second } else { first }
}

fn section_label(section: Option<&Named>) -> Option<String> {
    section
        .map(|section| section.name.trim())
        .filter(|label| !label.is_empty())
        .map(str::to_owned)
}

/// `name` when a secret reference can hold it, otherwise `id`: 1Password
/// takes letters, digits, `-`, `_`, `.` and spaces in names
fn segment<'a>(name: &'a str, id: &'a str) -> &'a str {
    let plain = !name.trim().is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_. ".contains(character));
    if plain { name } else { id }
}

#[cfg(test)]
mod tests {
    use super::{Listed, LoginPart, Opened, found_item, login_field, website_host};

    #[test]
    fn an_opened_item_answers_references_and_never_its_values() -> Result<(), serde_json::Error> {
        let listed: Listed = serde_json::from_str(
            r#"{"id":"sig1","title":"Apple Signing","category":"DOCUMENT",
                "vault":{"id":"v1","name":"Personal"}}"#,
        )?;
        let opened: Opened = serde_json::from_str(
            r#"{"id":"sig1","title":"Apple Signing","category":"DOCUMENT",
                "vault":{"id":"v1","name":"Personal"},
                "fields":[
                  {"id":"password","type":"CONCEALED","label":"password",
                   "value":"hunter2-secret","reference":"op://Personal/Apple Signing/password"},
                  {"id":"notes","type":"STRING","label":"notes","value":"no reference"}],
                "files":[
                  {"id":"f1","name":"cert.p12","size":2300},
                  {"id":"f2","name":"key (old).p12","size":10,
                   "section":{"id":"s1","label":"Archive"}}]}"#,
        )?;

        let found = found_item(opened, &listed);
        let text = serde_json::to_string(&found)?;
        assert!(!text.contains("hunter2"), "{text}");
        let fields: Vec<(&str, &str)> = found
            .fields
            .iter()
            .map(|field| (field.reference.as_str(), field.kind.as_str()))
            .collect();
        // a name a reference cannot hold is replaced by its ID
        assert_eq!(
            fields,
            [
                ("op://Personal/Apple Signing/password", "concealed"),
                ("op://Personal/Apple Signing/cert.p12", "file"),
                ("op://Personal/Apple Signing/Archive/f2", "file"),
            ]
        );

        Ok(())
    }

    #[test]
    fn a_login_is_known_by_its_websites_and_its_fields_by_purpose() -> Result<(), serde_json::Error>
    {
        let listed: Listed = serde_json::from_str(
            r#"{"id":"gh1","title":"GitHub","category":"LOGIN",
                "vault":{"id":"v1","name":"Personal"},
                "urls":[{"label":"website","primary":true,"href":"https://GitHub.com/login"},
                        {"href":"gist.github.com"},{"href":"gist.github.com:8443"},
                        {"href":"androidapp://com.github.android"},
                        {"href":"mailto:me@github.com"}]}"#,
        )?;
        let hosts: Vec<String> = listed
            .urls
            .iter()
            .filter_map(|url| website_host(&url.href))
            .collect();
        assert_eq!(hosts, ["github.com", "gist.github.com", "gist.github.com"]);

        let opened: Opened = serde_json::from_str(
            r#"{"id":"gh1","fields":[
                  {"id":"login","type":"STRING","purpose":"USERNAME","label":"email"},
                  {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password"},
                  {"id":"TOTP_x1","type":"OTP","label":"one-time password",
                   "section":{"id":"add more"}}]}"#,
        )?;
        assert_eq!(
            login_field(&opened, LoginPart::Username),
            Some((None, "login"))
        );
        assert_eq!(
            login_field(&opened, LoginPart::OneTimePassword),
            Some((Some("add more"), "TOTP_x1"))
        );

        Ok(())
    }
}
