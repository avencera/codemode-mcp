//! Reading references through a companion Mac: a real iroh companion in this
//! process, a fake `op` on each side, and a `FakeMac` for each Mac

use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};

use codemode_mcp::{
    companion::{self, CompanionHandle, Paired, Role, Ticket},
    config::Config,
    mac::{Mac, TouchId},
};
use serde_json::{Value, json};

use super::{
    harness::{FakeMac, Harness, Setup, TestResult, temp_state_dir},
    secrets::{VALUE, fake_op, reads},
    service::{codemode, files},
};

const REFERENCE: &str = "op://Dev/fixture/credential";

/// A gateway and one companion wired together over loopback
struct Rig {
    harness: Harness,
    companion: CompanionHandle,
    /// The companion's Mac
    companion_mac: Arc<FakeMac>,
    /// `op` reads the gateway made itself
    local_log: PathBuf,
    /// `op` reads the companion made
    companion_log: PathBuf,
}

/// How a rig differs from the usual one: the owner is on the companion's
/// Mac and approves, the companion allows the reference and expects this
/// gateway
struct Options<'a> {
    /// The companion's allow list
    allow: &'a [&'a str],
    /// Whether the companion expects this gateway's id
    paired: bool,
    /// How the companion's Touch ID prompt ends; `None` leaves it up
    touch: Option<TouchId>,
    /// Whether the owner counts as at the gateway's Mac
    present: bool,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            allow: &[REFERENCE],
            paired: true,
            touch: Some(TouchId::Approved),
            present: false,
        }
    }
}

impl Rig {
    async fn start(options: Options<'_>) -> Result<Option<Self>, Box<dyn Error>> {
        let Options {
            allow,
            paired,
            touch,
            present,
        } = options;
        let directory = temp_state_dir();
        std::fs::create_dir_all(&directory)?;
        let gateway_key = directory.join("gateway.key");
        let gateway_id = companion::load_or_create(Role::Gateway, Some(&gateway_key))?.public();
        let expected = if paired {
            gateway_id
        } else {
            iroh::SecretKey::generate().public()
        };

        let (companion_op, companion_log) = fake_op()?;
        let companion_mac = Arc::new(FakeMac::default());
        companion_mac.set_answer(touch);
        let text = format!(
            "[companion]\n\
             gateway = \"{expected}\"\n\
             gateway_name = \"main\"\n\
             allow = {allow}\n\
             listen = \"127.0.0.1:0\"\n\
             discovery = false\n\
             identity_file = \"{key}\"\n\
             op = \"{op}\"\n",
            allow = serde_json::to_string(allow)?,
            key = directory.join("companion.key").display(),
            op = companion_op.display(),
        );
        let config = Config::parse(&text, std::path::Path::new("companion.toml"))?;
        let Some(companion_config) = config.companion else {
            return Err("the companion section is missing".into());
        };
        let companion = companion::serve(
            companion_config,
            Some(Arc::clone(&companion_mac) as Arc<dyn Mac>),
        )
        .await?;
        let address = companion
            .bound_addrs()
            .into_iter()
            .find(|address| address.is_ipv4())
            .ok_or("the companion bound no IPv4 socket")?;

        let (local_op, local_log) = fake_op()?;
        let gateway_mac = Arc::new(FakeMac::default());
        gateway_mac.set_present(present);
        let extra = format!(
            "[secrets]\n\
             op = \"{op}\"\n\
             discovery = false\n\
             identity_file = \"{key}\"\n\
             companions = [{{ name = \"mba\", id = \"{id}\", addrs = [\"{address}\"] }}]\n\n\
             [servers.twin]\n\
             command = \"{fixture}\"\n\
             env = {{ FIXTURE_SECRET = \"{{{{ {REFERENCE} }}}}\" }}\n",
            op = local_op.display(),
            key = gateway_key.display(),
            id = companion.id(),
            fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
        );
        let harness = Harness::with(Setup {
            extra: &extra,
            mac: Some(Arc::clone(&gateway_mac)),
            ..Setup::default()
        })
        .await?;
        let Some(harness) = harness else {
            companion.shutdown().await;

            return Ok(None);
        };

        Ok(Some(Self {
            harness,
            companion,
            companion_mac,
            local_log,
            companion_log,
        }))
    }

    /// Why the `twin` server is unavailable, once it is
    async fn twin_error(&self) -> Result<String, Box<dyn Error>> {
        for _ in 0..40 {
            let report = serde_json::to_value(self.harness.app.gateway().report())?;
            let twin = report
                .as_array()
                .and_then(|servers| servers.iter().find(|server| server["name"] == "twin"));
            if let Some(error) = twin.and_then(|twin| twin["error"].as_str()) {
                return Ok(error.to_owned());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        Err("the twin server never became unavailable".into())
    }

    async fn stop(self) -> TestResult {
        self.companion.shutdown().await;

        self.harness.stop().await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_away_from_the_gateway_reads_through_the_companion() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };

    let body = rig
        .harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");

    // the gateway's own `op` never ran, and the owner was asked on the
    // companion Mac, by name
    assert_eq!(reads(&rig.local_log, REFERENCE), 0);
    assert_eq!(reads(&rig.companion_log, REFERENCE), 1);
    assert_eq!(
        rig.companion_mac.shown(),
        [format!(
            "touch_id codemode-mcp on main wants to read {REFERENCE}"
        )]
    );

    // the cancel button must not offer the gateway's approval page
    assert_eq!(rig.companion_mac.cancel_titles(), ["Deny"]);

    // `companion check` reports the length, never the value
    let (status, checked) = rig
        .harness
        .admin_json("/admin/companion/check", &json!({ "reference": REFERENCE }))
        .await?;
    assert_eq!(status, 200, "{checked}");
    assert_eq!(
        checked["companions"][0],
        json!({ "name": "mba", "result": { "ok": { "bytes": VALUE.len() } } })
    );
    assert!(!checked.to_string().contains(VALUE), "{checked}");

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reference_off_the_allow_list_is_refused_before_anyone_is_asked() -> TestResult {
    let Some(rig) = Rig::start(Options {
        allow: &["op://Dev/other/credential"],
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let error = rig.twin_error().await?;
    assert!(error.contains("mba: not_allowed"), "{error}");
    assert!(!error.contains(VALUE), "{error}");

    let (_, checked) = rig
        .harness
        .admin_json("/admin/companion/check", &json!({ "reference": REFERENCE }))
        .await?;
    let message = checked["companions"][0]["result"]["error"]["message"].as_str();
    assert!(
        message.is_some_and(|message| message.contains("not_allowed")),
        "{checked}"
    );

    assert_eq!(reads(&rig.companion_log, REFERENCE), 0);
    assert!(rig.companion_mac.shown().is_empty());
    assert_eq!(reads(&rig.local_log, REFERENCE), 0);

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_touch_id_that_is_not_approved_reads_nothing() -> TestResult {
    let Some(rig) = Rig::start(Options {
        touch: Some(TouchId::Review),
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let error = rig.twin_error().await?;
    assert!(error.contains("mba: denied"), "{error}");
    // the owner is away, so the local read was skipped and the error says so
    assert!(
        error.contains("local: skipped, the owner is away from this Mac"),
        "{error}"
    );

    assert_eq!(reads(&rig.companion_log, REFERENCE), 0);
    assert_eq!(reads(&rig.local_log, REFERENCE), 0);
    // it was asked, which is what makes the refusal a decision
    assert!(!rig.companion_mac.shown().is_empty());

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_too_large_to_send_is_refused_by_name() -> TestResult {
    const BIG: &str = "op://Dev/big/credential";
    let Some(rig) = Rig::start(Options {
        allow: &[REFERENCE, BIG],
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let (status, checked) = rig
        .harness
        .admin_json("/admin/companion/check", &json!({ "reference": BIG }))
        .await?;
    assert_eq!(status, 200, "{checked}");
    let message = checked["companions"][0]["result"]["error"]["message"]
        .as_str()
        .ok_or_else(|| format!("no error message in {checked}"))?;
    assert!(
        message.contains("the value is too large to send"),
        "{message}"
    );

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_companion_paired_with_another_gateway_does_not_answer() -> TestResult {
    let Some(rig) = Rig::start(Options {
        paired: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let error = rig.twin_error().await?;
    assert!(error.contains("mba:"), "{error}");

    assert_eq!(reads(&rig.companion_log, REFERENCE), 0);
    assert!(rig.companion_mac.shown().is_empty());

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_at_the_gateway_still_gets_the_value() -> TestResult {
    // the companion's prompt is never answered, so the value can only come
    // from the gateway's own `op`
    let Some(rig) = Rig::start(Options {
        touch: None,
        present: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let body = rig
        .harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");
    assert_eq!(reads(&rig.local_log, REFERENCE), 1);

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_that_is_given_up_takes_the_prompt_down() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };
    // the twin server read once while booting; from here on the prompt stays
    // up until the gateway hangs up
    let booted = rig.companion_mac.shown().len();
    rig.companion_mac.set_answer(None);

    let companions = Arc::clone(rig.harness.app.gateway().companions());
    let reading = tokio::spawn(async move { companions.read("mba", REFERENCE).await });
    for _ in 0..40 {
        if rig.companion_mac.shown().len() > booted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        rig.companion_mac.shown().len() > booted,
        "no prompt appeared"
    );
    reading.abort();

    let mut dismissed = false;
    for _ in 0..40 {
        dismissed = rig
            .companion_mac
            .shown()
            .iter()
            .any(|entry| entry == "dismissed");
        if dismissed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(dismissed, "{:?}", rig.companion_mac.shown());
    assert_eq!(reads(&rig.companion_log, REFERENCE), 1);

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_carries_the_gateway_and_its_references_to_a_pairing() -> TestResult {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let key = directory.join("gateway.key");
    // the servers' references must never reach the real 1Password
    let (op, _) = fake_op()?;
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\
         identity_file = \"{key}\"\n\n\
         [servers.b]\n\
         command = \"{fixture}\"\n\
         env = {{ X = \"{{{{ op://Dev/b/credential }}}}\", Y = \"{{{{ op://Dev/a/credential }}}}\" }}\n\n\
         [servers.c]\n\
         command = \"{fixture}\"\n\
         env = {{ X = \"k-{{{{ op://Dev/a/credential }}}}\" }}\n",
        op = op.display(),
        key = key.display(),
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };

    let (status, invite) = harness
        .admin_json("/admin/companion/invite", &Value::Null)
        .await?;
    assert_eq!(status, 200, "{invite}");
    assert_eq!(
        invite["gateway"],
        companion::load_or_create(Role::Gateway, Some(&key))?
            .public()
            .to_string()
    );
    assert_eq!(
        invite["references"],
        json!(["op://Dev/a/credential", "op://Dev/b/credential"])
    );
    harness.stop().await?;

    // the ticket the CLI prints pairs a second Mac, once
    let ticket: Ticket = serde_json::from_value(json!({
        "gateway": invite["gateway"],
        "gateway_name": invite["gateway_name"],
        "references": invite["references"],
    }))?;
    let ticket = Ticket::decode(&ticket.encode()?)?;
    let config = directory.join("config.toml");
    let identity = directory.join("companion.key");
    let Paired::Written(pairing) = companion::pair(&ticket, &config, Some(&identity))? else {
        return Err("a new config should be paired".into());
    };
    let paired = Config::load(&config)?
        .companion
        .ok_or("no companion section was written")?;
    assert_eq!(paired.gateway, ticket.gateway);
    assert!(paired.allows("op://Dev/a/credential"));
    assert!(!paired.allows("op://Dev/c/credential"));
    assert_eq!(
        pairing.id,
        companion::companion_id(Some(&identity))?,
        "the id printed for the gateway is the key that was stored"
    );
    assert!(matches!(
        companion::pair(&ticket, &config, Some(&identity))?,
        Paired::AlreadyConfigured { .. }
    ));

    // the block it prints is appended at the end of the gateway's config,
    // which may already list another companion
    let gateway_config = format!(
        "[secrets]\nidentity_file = \"{}\"\n\n[[secrets.companions]]\nname = \"other\"\nid = \"{}\"\n\n{}\n",
        key.display(),
        iroh::SecretKey::generate().public(),
        pairing.gateway_entry(),
    );
    let parsed = Config::parse(&gateway_config, std::path::Path::new("gateway.toml"))?;
    let listed: Vec<_> = parsed
        .secrets
        .companions
        .iter()
        .map(|peer| (peer.name.as_str(), peer.id))
        .collect();
    assert_eq!(listed[1], (pairing.name.as_str(), pairing.id));

    let _ = std::fs::remove_dir_all(&directory);

    Ok(())
}

#[test]
fn a_relative_identity_file_is_stored_as_an_absolute_path() -> TestResult {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    // a path relative to the working directory that reaches the temp
    // directory, so the test writes nothing into the checkout
    let depth = std::env::current_dir()?.components().count() - 1;
    let relative: PathBuf = std::iter::repeat_n("..", depth)
        .map(PathBuf::from)
        .chain([directory.strip_prefix("/")?.join("rel.key")])
        .collect();
    assert!(relative.is_relative());
    let ticket = Ticket {
        gateway: iroh::SecretKey::generate().public(),
        gateway_name: "main".into(),
        references: vec![REFERENCE.into()],
    };
    let config = directory.join("config.toml");

    let Paired::Written(pairing) = companion::pair(&ticket, &config, Some(&relative))? else {
        return Err("a new config should be paired".into());
    };
    let stored = Config::load(&config)?
        .companion
        .and_then(|companion| companion.identity_file)
        .ok_or("no identity_file was written")?;
    assert!(stored.is_absolute(), "{}", stored.display());
    assert_eq!(pairing.id, companion::companion_id(Some(&relative))?);
    assert_eq!(
        pairing.id,
        companion::load_or_create(Role::Companion, Some(&stored))?.public()
    );

    // a hand-written relative path is refused when the config loads
    for section in ["secrets", "companion"] {
        let text = format!(
            "[{section}]\n{gateway}identity_file = \"key.hex\"\n",
            gateway = if section == "companion" {
                format!("gateway = \"{}\"\n", ticket.gateway)
            } else {
                String::new()
            }
        );
        let error = Config::parse(&text, std::path::Path::new("config.toml"))
            .err()
            .ok_or("a relative identity_file should be refused")?;
        assert!(error.to_string().contains("absolute"), "{error}");
    }

    let _ = std::fs::remove_dir_all(&directory);

    Ok(())
}

#[test]
fn concurrent_first_runs_share_one_identity_file_key() -> TestResult {
    let directory = temp_state_dir();
    let path = directory.join("nested/race.key");

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                companion::load_or_create(Role::Gateway, Some(&path)).map(|key| key.public())
            })
        })
        .collect();
    let mut ids = Vec::new();
    for handle in handles {
        ids.push(handle.join().map_err(|_| "a creator panicked")??);
    }
    assert!(ids.windows(2).all(|pair| pair[0] == pair[1]), "{ids:?}");
    // no temp file is left beside the key
    assert_eq!(
        std::fs::read_dir(path.parent().ok_or("no parent")?)?.count(),
        1
    );

    // an empty file stays an error that names it
    let empty = directory.join("empty.key");
    std::fs::write(&empty, "")?;
    std::fs::set_permissions(&empty, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let error = companion::load_or_create(Role::Gateway, Some(&empty))
        .err()
        .ok_or("an empty key file should not load")?;
    assert!(error.to_string().contains("empty.key"), "{error}");

    let _ = std::fs::remove_dir_all(&directory);

    Ok(())
}

#[test]
fn companion_install_dry_run_shows_the_agent_and_changes_nothing() -> TestResult {
    let home = temp_state_dir();
    std::fs::create_dir_all(&home)?;
    let before = files(&home);

    let (ok, out, err) = codemode(&home, &["companion", "install", "--dry-run"])?;
    assert!(ok, "{err}");
    let home_text = home.display().to_string();
    assert!(
        out.contains(&format!(
            "{home_text}/Library/LaunchAgents/dev.praveen.codemode-mcp.companion.plist"
        )),
        "{out}"
    );
    assert!(
        out.contains("<string>companion</string>\n    <string>serve</string>"),
        "{out}"
    );
    assert!(out.contains("launchctl bootout gui/"), "{out}");
    // no Monty worker for the companion
    assert!(!out.contains("monty"), "{out}");
    assert_eq!(files(&home), before);

    let _ = std::fs::remove_dir_all(&home);

    Ok(())
}
