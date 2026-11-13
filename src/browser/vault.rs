//! Where a fill's value comes from, on the machine that holds 1Password:
//! the hub, or a gateway that has no hub
//!
//! While the owner is at the Mac, 1Password here finds the login saved for
//! the page's host and the value is read by reference, so a code is made
//! fresh from its seed. While they are away, the phone is asked at once for
//! the whole sign-in (see [`super::sign_in`]). A spoke's fills come here
//! too, through the hub's `browser/` routes, so a spoke's sign-ins are kept
//! apart from the hub's by [`SessionAt`]

use std::{collections::HashMap, sync::Arc};

use companion_wire::{
    mobile::{LoginField, SignIn},
    takeover::FillOffer,
    wire::{MAX_DESCRIPTION_CHARS, MAX_REASON_CHARS},
};
use iroh::EndpointId;
use zeroize::Zeroizing;

use super::{SessionAt, Source, sign_in::SignIns};
use crate::{
    companion::{Companions, ProgramAsk, ProgramRead, ProgramTarget, SignInAsk},
    config::PhonePeer,
    logins::{find_login, item_name},
    prompt,
    secrets::{LoginPart, OnePassword, Redactor},
    store::{Store, site_logins::SiteLogin},
};

/// A fill checked on its page, for which a source is found
pub struct FillAt<'a> {
    /// The session and the machine it runs on
    pub at: &'a SessionAt,
    /// The field that has focus
    pub field: LoginField,
    /// The 1Password item the agent named, if any
    pub item: Option<&'a str>,
    /// The page's host
    pub host: &'a str,
    /// The page's site
    pub site: &'a str,
}

/// The values fills read and where they come from; cheap to share
pub struct Vault {
    onepassword: OnePassword,
    redactor: Arc<Redactor>,
    store: Option<Store>,
    sign_ins: SignIns,
}

impl Vault {
    /// Reads values through `onepassword` and remembers each site's login
    /// in `store`; a password or seed read is added to `redactor`
    pub fn new(onepassword: OnePassword, redactor: Arc<Redactor>, store: Option<Store>) -> Self {
        Self {
            onepassword,
            redactor,
            store,
            sign_ins: SignIns::default(),
        }
    }

    /// The phones and the takeovers they open
    pub fn companions(&self) -> Option<&Arc<Companions>> {
        self.onepassword.companions()
    }

    /// Values typed are added here, so no server's answer shows them
    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.redactor
    }

    /// Whether 1Password on this Mac may be searched: the owner is at it, or
    /// there is no Mac to find them at
    async fn owner_here(&self) -> bool {
        match self.onepassword.on_mac() {
            Some(on_mac) => on_mac.mac.present(on_mac.config.idle()).await,
            None => true,
        }
    }

    /// The paired phones
    pub fn phones(&self) -> Vec<PhonePeer> {
        self.companions()
            .map(|companions| companions.phones())
            .unwrap_or_default()
    }

    fn site_login(&self, site: &str) -> Option<SiteLogin> {
        self.store.as_ref()?.site_login(site).ok().flatten()
    }

    /// Where `fill`'s value comes from, and what the owner is asked to
    /// approve, such as `password into github.com (browser session github)
    /// from GitHub (Personal)`
    pub async fn source(&self, fill: &FillAt<'_>) -> Result<(Source, String), String> {
        let FillAt {
            at,
            field,
            item,
            host,
            site,
        } = fill;
        let label = field.label();
        if self.owner_here().await {
            let (source, item, warning) = self.source_here(*field, *item, host, site).await?;
            let mut summary = format!("{label} into {host} ({at}) from {item}");
            if let Some(warning) = warning {
                summary.push_str("; ");
                summary.push_str(&warning);
            }

            return Ok((source, summary));
        }

        if self.phones().is_empty() {
            return Err(
                "the user is away from this Mac, so 1Password cannot be searched here, and no \
                 phone is paired to pick the login on; wait for the user"
                    .to_owned(),
            );
        }
        let known = self
            .site_login(site)
            .map(|login| match login.account {
                Some(account) => format!(" ({} · {account})", login.item),
                None => format!(" ({})", login.item),
            })
            .unwrap_or_default();

        Ok((
            Source::Phone,
            format!("{label} into {host} ({at}), from the user's phone{known}"),
        ))
    }

    /// The 1Password field for `field` on `host`, found on this Mac, with the
    /// item's name and any warning; the site's login is remembered for when
    /// the owner is away
    async fn source_here(
        &self,
        field: LoginField,
        item: Option<&str>,
        host: &str,
        site: &str,
    ) -> Result<(Source, String, Option<String>), String> {
        let (login, _, warning) = find_login(&self.onepassword, item, &[host.to_owned()])
            .await
            .map_err(|error| error.to_string())?;
        let name = item_name(&login);
        let [username, password, code] = self
            .onepassword
            .login_references(
                &login,
                [
                    LoginPart::Username,
                    LoginPart::Password,
                    LoginPart::OneTimePassword,
                ],
            )
            .await
            .map_err(|error| format!("could not open {name}: {error}"))?;
        let reference = match field {
            LoginField::Username => username.clone(),
            LoginField::Password => password.clone(),
            LoginField::Code => code.clone(),
        }
        .filter(|reference| crate::secrets::is_reference(reference))
        .ok_or_else(|| format!("{name} has no {}", field.label()))?;

        // only an item saved for the site stands for it later
        if warning.is_none()
            && let Some(store) = &self.store
        {
            let remembered = SiteLogin {
                site: site.to_owned(),
                item: name.clone(),
                account: login.account.clone(),
                username,
                password,
                code,
            };
            if let Err(error) = store.put_site_login(&remembered) {
                tracing::warn!(%error, site, "could not remember the site's login");
            }
        }

        Ok((
            Source::Item {
                reference,
                item: name.clone(),
            },
            name,
            warning,
        ))
    }

    /// The value for `field` of the sign-in to `site` in session `at`, read
    /// by reference or asked of the phone
    pub async fn value(
        &self,
        at: &SessionAt,
        field: LoginField,
        site: &str,
        source: &Source,
    ) -> Result<Zeroizing<String>, String> {
        match source {
            Source::Item { reference, .. } => self
                .onepassword
                .read_reference(reference)
                .await
                .map(Zeroizing::new)
                .map_err(|error| error.to_string()),
            Source::Phone => match self.sign_ins.take(at, site, field) {
                Some(value) => Ok(value),
                None => self.ask_phone(at, field, site).await,
            },
            // only a spoke's own fill names its hub's grant, and a spoke
            // reads it from the hub
            Source::Hub { .. } => Err("this fill's value is read on the hub".to_owned()),
        }
    }

    /// Asks the phone for the sign-in `field` belongs to: the username and
    /// password together, with the code's seed when every phone holds a
    /// sealed copy of it, or the code alone. Answers `field`'s value and
    /// keeps the others for their fills
    async fn ask_phone(
        &self,
        at: &SessionAt,
        field: LoginField,
        site: &str,
    ) -> Result<Zeroizing<String>, String> {
        let known = self.site_login(site);
        let reference = |field: LoginField| {
            known.as_ref().and_then(|login| match field {
                LoginField::Username => login.username.clone(),
                LoginField::Password => login.password.clone(),
                LoginField::Code => login.code.clone(),
            })
        };
        let phones = self.phones();
        // a code the owner enters now could expire before its page comes,
        // so it is asked with the rest only when a seed opens instead
        let sealed_seed = reference(LoginField::Code).is_some_and(|code| {
            let companions = self.companions();
            !phones.is_empty()
                && phones.iter().all(|phone| {
                    companions
                        .is_some_and(|companions| companions.phone_seal(phone.id, &code).is_some())
                })
        });
        let fields: Vec<LoginField> = match field {
            LoginField::Code => vec![LoginField::Code],
            _ if sealed_seed => vec![LoginField::Username, LoginField::Password, LoginField::Code],
            _ => vec![LoginField::Username, LoginField::Password],
        };
        let targets: Vec<ProgramTarget> = fields
            .iter()
            .map(|&field| match reference(field) {
                Some(reference) => ProgramTarget::Reference(reference),
                None => ProgramTarget::Describe(prompt::one_line(
                    &format!("{} for {site}", field.label()),
                    MAX_DESCRIPTION_CHARS,
                )),
            })
            .collect();
        // a Mac can read a reference but cannot enter a value
        let phones_only = targets
            .iter()
            .any(|target| matches!(target, ProgramTarget::Describe(_)));
        let ask = ProgramAsk {
            targets,
            reason: Some(prompt::one_line(
                &format!("sign in to {site} in {at}"),
                MAX_REASON_CHARS,
            )),
            destination: Some(format!("the {site} sign-in in {at}")),
            keep: None,
            phones_only,
            keep_scope: None,
            sign_in: Some(SignInAsk {
                sign_in: SignIn {
                    site: site.to_owned(),
                    account: known.as_ref().and_then(|login| login.account.clone()),
                    session: Some(at.session.to_string()),
                },
                fields: fields.clone(),
            }),
        };

        let read = match self.onepassword.read_for_program(&ask).await {
            Ok(ProgramRead::Values(read)) => read,
            Ok(ProgramRead::Found(_)) => {
                return Err("a Mac answered with items instead of the values".to_owned());
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut values: HashMap<LoginField, Zeroizing<String>> = HashMap::new();
        for (field, value) in fields.into_iter().zip(read.values) {
            let Some(text) = value.as_text() else {
                continue;
            };
            values.insert(field, Zeroizing::new(text.to_owned()));
            // the value's bytes are wiped as it drops
            drop(Zeroizing::new(value.into_bytes()));
        }
        let wanted = values
            .remove(&field)
            .ok_or_else(|| format!("the phone sent no {}", field.label()))?;
        self.sign_ins.hold(at, site, values);

        Ok(wanted)
    }

    /// The fills the phone `phone` could open on `site`: the remembered
    /// login's fields that it holds sealed copies of
    pub fn offers_for(&self, phone: EndpointId, site: &str) -> Vec<FillOffer> {
        let (Some(login), Some(companions)) = (self.site_login(site), self.companions()) else {
            return Vec::new();
        };

        [
            (LoginField::Username, &login.username),
            (LoginField::Password, &login.password),
            (LoginField::Code, &login.code),
        ]
        .into_iter()
        .filter_map(|(field, reference)| {
            let reference = reference.as_ref()?;
            let sealed = companions.phone_seal(phone, reference)?;

            Some(FillOffer {
                field,
                reference: reference.clone(),
                sealed,
                item: login.item.clone(),
                account: login.account.clone(),
                site: site.to_owned(),
            })
        })
        .collect()
    }
}
