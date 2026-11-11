//! The 1Password login the `browser` builtin last used for each site

use turso::params;

use super::{Store, StoreError, now_ms};

/// One site's login: the item and the references of its fields, never a
/// value
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteLogin {
    /// The site, a registrable domain such as `github.com`
    pub site: String,
    /// The item as the owner is shown it, such as `GitHub (Personal)`
    pub item: String,
    /// The account, such as the username 1Password lists for the item
    pub account: Option<String>,
    /// The username field's reference
    pub username: Option<String>,
    /// The password field's reference
    pub password: Option<String>,
    /// The one-time password field's reference, which reads the seed
    pub code: Option<String>,
}

impl Store {
    /// Remembers `login` for its site, merging in the references it has over
    /// those already known for the same item
    pub fn put_site_login(&self, login: &SiteLogin) -> Result<(), StoreError> {
        let known = self
            .site_login(&login.site)?
            .filter(|known| known.item == login.item);
        let merged = |new: &Option<String>, old: Option<String>| new.clone().or(old);
        let (username, password, code, account) = match known {
            Some(known) => (
                merged(&login.username, known.username),
                merged(&login.password, known.password),
                merged(&login.code, known.code),
                merged(&login.account, known.account),
            ),
            None => (
                login.username.clone(),
                login.password.clone(),
                login.code.clone(),
                login.account.clone(),
            ),
        };
        self.connection().execute(
            "INSERT OR REPLACE INTO site_logins \
             (site, item, account, username_ref, password_ref, code_ref, updated_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                login.site.as_str(),
                login.item.as_str(),
                account,
                username,
                password,
                code,
                now_ms()
            ],
        )?;

        Ok(())
    }

    /// The login last used for `site`
    pub fn site_login(&self, site: &str) -> Result<Option<SiteLogin>, StoreError> {
        Ok(self.connection().query_optional(
            "SELECT site, item, account, username_ref, password_ref, code_ref \
             FROM site_logins WHERE site = ?1",
            params![site],
            |row| {
                Ok(SiteLogin {
                    site: row.get(0)?,
                    item: row.get(1)?,
                    account: row.get(2)?,
                    username: row.get(3)?,
                    password: row.get(4)?,
                    code: row.get(5)?,
                })
            },
        )?)
    }
}
