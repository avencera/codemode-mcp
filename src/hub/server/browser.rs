//! A spoke's browser sessions as the hub serves them: the takeover endpoint
//! the spoke reports, its fills' sources and values, its handoffs, and the
//! fills a phone taking one of its pages over could open
//!
//! A spoke's fill is held here under a grant. `browser/source` finds the
//! value's source as a fill on the hub would, and answers the summary the
//! owner is asked, which names the spoke. The spoke's gate call for its own
//! `fill` names the grant, so the hub asks with that summary, one approval
//! per call, and binds the request to the grant. `browser/value` sends the
//! value once, only for a grant whose request the owner approved, and drops
//! the grant first. A code is made from its seed here, so a seed never
//! leaves the hub

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use companion_wire::{mobile::LoginField, takeover::BrowserMachine, wire::MAX_REASON_CHARS};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::time::Instant;

use super::{Hub, plain_name};
use crate::{
    approvals::{Verdict, random_id},
    browser::{
        CHECKED, Checked, Kind, MAX_HANDOFF_MINUTES, Machine, SessionAt, Source, login_value,
        page::SessionName, site_named, vault::FillAt,
    },
    companion::{HandoffOffer, TakeoverPhone},
    hub::{
        BrowserEndpoint, FillGrant, FillSource, FillValueAnswer, HandoffCall, HandoffReply,
        OffersAnswer, OffersCall, VouchedPhones,
    },
    prompt::one_line,
    store::{now_ms, spokes::StoredSpoke},
};

/// Most fills one spoke may have waiting on the owner at once
const MAX_FILLS_PER_SPOKE: usize = 32;
/// How long a grant outlives its approval's deadline, for a value read
/// that started just before it
const FILL_SLACK: Duration = Duration::from_secs(60);
/// Most direct addresses kept of a spoke's endpoint
const MAX_ADDRS: usize = 16;
/// Longest relay URL or page URL accepted
const MAX_URL_CHARS: usize = 2048;
/// The tool a spoke's fill is gated as
const FILL_TOOL: &str = "fill";

/// A spoke's fill whose source the hub found, waiting on the owner
#[derive(Clone)]
pub(super) struct HeldFill {
    /// The spoke's id
    spoke: String,
    at: SessionAt,
    field: LoginField,
    host: String,
    site: String,
    source: Source,
    /// What the owner is asked to approve
    summary: String,
    /// The request that asks for it, once the spoke's gate call named it,
    /// with the server it was asked for
    request: Option<(String, String)>,
    /// When it is dropped unread
    expires: Instant,
}

/// The fills spokes have found sources for, by grant id
#[derive(Default)]
pub(super) struct HeldFills(HashMap<String, HeldFill>);

impl HeldFills {
    /// Holds `fill` under a new grant id; `None` when its spoke has too
    /// many waiting
    fn hold(&mut self, fill: HeldFill) -> Option<String> {
        let now = Instant::now();
        self.0.retain(|_, held| held.expires > now);
        let waiting = self
            .0
            .values()
            .filter(|held| held.spoke == fill.spoke)
            .count();
        if waiting >= MAX_FILLS_PER_SPOKE {
            return None;
        }
        let grant = random_id();
        self.0.insert(grant.clone(), fill);

        Some(grant)
    }

    /// Spoke `spoke`'s grant `grant`, while it is held
    fn of(&self, spoke: &str, grant: &str) -> Option<&HeldFill> {
        self.0
            .get(grant)
            .filter(|held| held.spoke == spoke && held.expires > Instant::now())
    }
}

/// A spoke's gate call that names a grant, as the hub asks the owner
pub(super) struct GatedFill {
    pub grant: String,
    pub summary: String,
}

/// The arguments of a spoke's `fill` call that the grant was found for
#[derive(Deserialize)]
struct FillCall {
    session: String,
    kind: Kind,
    site: String,
    checked: Checked,
}

impl Hub {
    /// Records `spoke`'s takeover endpoint, so the phones list it, and
    /// answers the phones it may let in
    pub(super) fn report_browser(
        &self,
        spoke: &StoredSpoke,
        endpoint: BrowserEndpoint,
    ) -> VouchedPhones {
        let companions = self.gateway.companions();
        // the relay is dialed by the phone, so it must at least be one line
        let relay = endpoint.relay.filter(|relay| {
            relay.chars().count() <= MAX_URL_CHARS && one_line(relay, usize::MAX) == *relay
        });
        let addrs: Vec<SocketAddr> = endpoint.addrs.into_iter().take(MAX_ADDRS).collect();
        let machine = BrowserMachine {
            name: spoke.name.clone(),
            id: endpoint.id,
            addrs,
            relay,
        };
        companions.browser_machines().report(&spoke.id, machine);

        VouchedPhones {
            phones: companions
                .phones()
                .into_iter()
                .map(|phone| TakeoverPhone {
                    name: phone.name,
                    id: phone.id,
                })
                .collect(),
        }
    }

    /// Finds the source of `spoke`'s fill as a fill here would, naming the
    /// spoke, and holds it under a grant until the owner decides
    pub(super) async fn fill_source(&self, spoke: &StoredSpoke, fill: FillSource) -> FillGrant {
        let Some(vault) = self.gateway.vault().cloned() else {
            return FillGrant::Refused("the hub has no 1Password to fill from".to_owned());
        };
        let session = match SessionName::parse(&fill.session) {
            Ok(session) => session,
            Err(error) => return FillGrant::Refused(error.to_string()),
        };
        // the host the spoke read must be on the site it names, as a page
        // check here requires, so 1Password is searched for that site only
        let site = match site_named(&fill.site) {
            Ok(site) => site,
            Err(error) => return FillGrant::Refused(error),
        };
        if !plain_name(&fill.host) || site_named(&fill.host).as_deref() != Ok(site.as_str()) {
            return FillGrant::Refused(format!("the page's host is not on {site}"));
        }
        let at = SessionAt {
            machine: Machine::Spoke {
                id: spoke.id.clone(),
                name: spoke.name.clone(),
            },
            session,
        };
        let item = fill
            .item
            .as_deref()
            .map(|item| one_line(item, MAX_REASON_CHARS));

        let found = FillAt {
            at: &at,
            field: fill.field,
            item: item.as_deref(),
            host: &fill.host,
            site: &site,
        };
        let (source, summary) = match vault.source(&found).await {
            Ok(found) => found,
            Err(reason) => return FillGrant::Refused(reason),
        };
        let held = HeldFill {
            spoke: spoke.id.clone(),
            at,
            field: fill.field,
            host: fill.host,
            site,
            source,
            summary: summary.clone(),
            request: None,
            expires: Instant::now()
                + Duration::from_secs(self.config.approvals.timeout_secs)
                + FILL_SLACK,
        };

        match self.state().fills.hold(held) {
            Some(grant) => FillGrant::Granted { grant, summary },
            None => FillGrant::Refused(
                "too many of this machine's fills are waiting for the user; wait for them"
                    .to_owned(),
            ),
        }
    }

    /// For `spoke`'s gate call of its own `tool` with `arguments`, the grant
    /// it names and the summary the owner is asked; `Ok(None)` for a call
    /// that names none, and `Err` for one whose grant does not fit it
    pub(super) fn gated_fill(
        &self,
        spoke: &StoredSpoke,
        tool: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Option<GatedFill>, String> {
        let Some(checked) = arguments.get(CHECKED) else {
            return Ok(None);
        };
        let Ok(Checked {
            source: Source::Hub { grant },
            ..
        }) = Checked::deserialize(checked)
        else {
            return Ok(None);
        };
        let call = (tool == FILL_TOOL)
            .then(|| FillCall::deserialize(Value::Object(arguments.clone())).ok())
            .flatten()
            .ok_or("only a fill names a fill's grant")?;

        let state = self.state();
        let held = state
            .fills
            .of(&spoke.id, &grant)
            .ok_or("the hub no longer holds this fill; fill again")?;
        if held.request.is_some() {
            return Err("this fill was asked about already; fill again".to_owned());
        }
        // the owner is shown the arguments too, so they must be the fill's
        let fits = SessionName::parse(&call.session)
            .is_ok_and(|session| session == held.at.session)
            && LoginField::from(call.kind) == held.field
            && site_named(&call.site).as_deref() == Ok(held.site.as_str())
            && call.checked.host == held.host
            && call.checked.site == held.site;
        if !fits {
            return Err("the fill changed since its source was found; fill again".to_owned());
        }

        Ok(Some(GatedFill {
            grant,
            summary: held.summary.clone(),
        }))
    }

    /// Binds `grant` to request `request` for `server`, the only one that
    /// can release its value
    pub(super) fn bind_fill(&self, grant: &str, request: &str, server: &str) {
        if let Some(held) = self.state().fills.0.get_mut(grant) {
            held.request = Some((request.to_owned(), server.to_owned()));
        }
    }

    /// Drops `grant`, whose request was refused before anyone was asked
    pub(super) fn drop_fill(&self, grant: &str) {
        self.state().fills.0.remove(grant);
    }

    /// The value of `spoke`'s fill held under `grant`, once: only after the
    /// owner approved the request that named it, and while it is in time
    pub(super) async fn fill_value(&self, spoke: &StoredSpoke, grant: &str) -> FillValueAnswer {
        let Some(vault) = self.gateway.vault().cloned() else {
            return FillValueAnswer::Refused("the hub has no 1Password to fill from".to_owned());
        };
        let held = match self.approved_fill(spoke, grant) {
            Ok(held) => held,
            Err(reason) => return FillValueAnswer::Refused(reason.to_owned()),
        };

        let value = match vault
            .value(&held.at, held.field, &held.site, &held.source)
            .await
        {
            Ok(value) => value,
            Err(reason) => return FillValueAnswer::Refused(reason),
        };
        // a seed becomes a code here and is redacted with the password
        match login_value(held.field, value, vault.redactor()) {
            Ok(value) => FillValueAnswer::Value(value.to_string()),
            Err(reason) => FillValueAnswer::Refused(reason),
        }
    }

    /// Takes `spoke`'s grant `grant` when the request bound to it was
    /// approved for the spoke's `fill` and is still in time, so no value is
    /// read twice or without the owner's approval naming it
    fn approved_fill(&self, spoke: &StoredSpoke, grant: &str) -> Result<HeldFill, &'static str> {
        let held = self
            .state()
            .fills
            .of(&spoke.id, grant)
            .cloned()
            .ok_or("the hub holds no such fill; fill again")?;
        let (request, server) = held.request.as_ref().ok_or(
            "this fill was not asked of the user; a spoke's fill needs its server's `ask` policy",
        )?;

        let approved = matches!(
            self.approvals().verdict_of(request),
            Some(Some(Verdict::Approved { .. }))
        );
        let fits = self.approvals().stored(request).is_some_and(|stored| {
            stored.spoke.as_deref() == Some(spoke.id.as_str())
                && stored.server == *server
                && stored.tool == FILL_TOOL
                && stored.expires_ms.is_some_and(|expires| expires > now_ms())
        });
        if !approved || !fits {
            return Err("the user has not approved this fill");
        }
        // two reads of one grant race here, and only the first takes it
        self.state()
            .fills
            .0
            .remove(grant)
            .ok_or("this fill's value was sent already; fill again")
    }

    /// Offers `spoke`'s handoff to the phones, naming the spoke so they dial
    /// it to take the session over, until one answers on the offer or the
    /// spoke's deadline passes
    pub(super) async fn offer_handoff(
        &self,
        spoke: &StoredSpoke,
        call: HandoffCall,
    ) -> HandoffReply {
        let companions = self.gateway.companions();
        let Some(machine) = companions.browser_machines().of(&spoke.id) else {
            return HandoffReply::Refused(format!(
                "the hub has not heard from {}'s browser lately, so no phone could reach it",
                spoke.name
            ));
        };
        if companions.phones().is_empty() {
            return HandoffReply::Refused(
                "no phone is paired with the hub, so nobody can take over (`codemode-mcp \
                 companion invite` on the hub)"
                    .to_owned(),
            );
        }
        let session = match SessionName::parse(&call.session) {
            Ok(session) => session,
            Err(error) => return HandoffReply::Refused(error.to_string()),
        };
        let longest = Duration::from_secs(MAX_HANDOFF_MINUTES * 60);
        let deadline = Instant::now() + Duration::from_millis(call.expires_in_ms).min(longest);
        let offer = HandoffOffer {
            id: call.id,
            session: session.to_string(),
            reason: call
                .reason
                .map(|reason| one_line(reason.trim(), MAX_REASON_CHARS)),
            url: call.url.filter(|url| {
                url.chars().count() <= MAX_URL_CHARS && one_line(url, usize::MAX) == *url
            }),
            machine: Some(machine),
        };

        match companions.offer_handoff(&offer, deadline).await {
            Ok(answer) => HandoffReply::Answered(answer),
            // the push may still bring a phone to the spoke's takeover,
            // which answers there, so the offer stands until the deadline
            Err(error) => {
                tracing::warn!(%error, spoke = %spoke.name, "no phone took a spoke's handoff");
                tokio::time::sleep_until(deadline).await;

                HandoffReply::Refused(error.to_string())
            }
        }
    }

    /// The fills phone `call.phone`, taking over a page of `spoke` on
    /// `call.site`, could open: sealed to it, so only it can
    pub(super) fn fill_offers(&self, spoke: &StoredSpoke, call: OffersCall) -> OffersAnswer {
        let paired = self
            .gateway
            .companions()
            .phones()
            .iter()
            .any(|phone| phone.id == call.phone);
        let (true, Some(vault), Ok(site)) = (paired, self.gateway.vault(), site_named(&call.site))
        else {
            return OffersAnswer::default();
        };
        tracing::debug!(spoke = %spoke.name, %site, "a phone's takeover asked for fills");

        OffersAnswer {
            offers: vault.offers_for(call.phone, &site),
        }
    }
}
