//! Reading references through a companion Mac: a real iroh companion in this
//! process, a fake `op` on each side, and a `FakeMac` for each Mac

use std::{error::Error, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};

use codemode_mcp::{
    companion::{
        self, CompanionHandle, InviteSecret, InviteTicket, JoinError, Joining, PairCheck, Paired,
        Role, Ticket,
    },
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
    /// The vaults the companion creates items in
    create_vaults: &'a [&'a str],
    /// Whether the companion expects this gateway's id
    paired: bool,
    /// How the companion's Touch ID prompt ends; `None` leaves it up
    touch: Option<TouchId>,
    /// Whether the owner counts as at the gateway's Mac
    present: bool,
    /// `notify.mac.enabled` on the gateway
    mac_notifications: bool,
    /// Whether the gateway's own `op` hangs instead of answering
    local_hangs: bool,
    /// Whether the companion's `op` is already authorized, so it would read
    /// without 1Password asking
    signed_in: bool,
    /// Whether the companion's notifications fail to show
    notify_fails: bool,
    /// Whether another `op` on the companion's Mac is approved each time a
    /// notification shows, so its `op` is no longer signed out
    authorized_on_notify: bool,
    /// Whether the companion's `op item create` pauses, so its answer can be lost
    slow_create: bool,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            allow: &[REFERENCE],
            create_vaults: &["Personal"],
            paired: true,
            touch: Some(TouchId::Approved),
            present: false,
            mac_notifications: true,
            local_hangs: false,
            signed_in: true,
            notify_fails: false,
            authorized_on_notify: false,
            slow_create: false,
        }
    }
}

impl Rig {
    async fn start(options: Options<'_>) -> Result<Option<Self>, Box<dyn Error>> {
        let Options {
            allow,
            create_vaults,
            paired,
            touch,
            present,
            mac_notifications,
            local_hangs,
            signed_in,
            notify_fails,
            authorized_on_notify,
            slow_create,
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

        let (companion_op, companion_log) = creating_op(signed_in, slow_create)?;
        let companion_mac = Arc::new(FakeMac::default());
        companion_mac.set_answer(touch);
        companion_mac.set_notify_fails(notify_fails);
        if authorized_on_notify {
            let directory = companion_log
                .parent()
                .ok_or("the fake op has no directory")?;
            companion_mac.set_on_notify(directory.join("authorized"));
        }
        let text = format!(
            "[companion]\n\
             gateway = \"{expected}\"\n\
             gateway_name = \"main\"\n\
             allow = {allow}\n\
             create_vaults = {create_vaults}\n\
             listen = \"127.0.0.1:0\"\n\
             discovery = false\n\
             identity_file = \"{key}\"\n\
             op = \"{op}\"\n",
            allow = serde_json::to_string(allow)?,
            create_vaults = serde_json::to_string(create_vaults)?,
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

        let (local_op, local_log) = if local_hangs {
            // the companion answers only once the local read has started, so
            // it cannot win before there is a local `op` to kill
            let (program, log) = hanging_op()?;
            companion_mac.set_answer_once(log.with_file_name("pid"));

            (program, log)
        } else {
            fake_op()?
        };
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
             env = {{ FIXTURE_SECRET = \"{{{{ {REFERENCE} }}}}\" }}\n\n\
             [notify.mac]\n\
             enabled = {mac_notifications}\n",
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

/// What the fake `op` prints for a created item: like the real one, it
/// echoes the value back
const OP_ECHOED_VALUE: &str = "echoed-by-op-secret";

/// A stand-in for `op` that serves the fixture read, lists one item titled
/// `Existing` and creates items (answering without an id for one titled
/// `No Id`, and killed by a signal for one titled `Killed`), logging each call's arguments and
/// environment and the template it was given on stdin, beside `reads.log`
///
/// Unless `signed_in`, `whoami` fails until the first read, as if that read
/// showed 1Password's prompt and was approved. With `slow_create`, `item
/// create` pauses after reading its template
fn creating_op(signed_in: bool, slow_create: bool) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let log = directory.join("reads.log");
    let program = directory.join("op");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\n\
             d='{directory}'\n\
             if [ \"$1\" = whoami ]; then\n\
               [ -e \"$d/authorized\" ] && exit 0\n\
               echo '[ERROR] account is not signed in' >&2; exit 1\n\
             fi\n\
             echo \"$*\" >> \"$d/argv.log\"\n\
             env >> \"$d/env.log\"\n\
             case \"$1 $2\" in\n\
               'read --no-newline') echo \"$3\" >> \"$d/reads.log\"\n\
                 touch \"$d/authorized\"\n\
                 [ \"$3\" = {REFERENCE} ] && printf '{VALUE}' && exit 0\n\
                 [ \"$3\" = op://Dev/big/credential ] && head -c 70000 /dev/zero | tr '\\0' a && exit 0\n\
                 echo \"[ERROR] no item matched\" >&2; exit 1 ;;\n\
               'item list') case \"$*\" in\n\
                   *--include-archive*) printf '[{{\"id\":\"old1\",\"title\":\"Existing\"}},{{\"id\":\"old2\",\"title\":\"Archived\"}}]' ;;\n\
                   *) printf '[{{\"id\":\"old1\",\"title\":\"Existing\"}}]' ;;\n\
                 esac ;;\n\
               'item create') cat > \"$d/stdin.log\"\n\
                 grep -q '\"title\":\"No Id\"' \"$d/stdin.log\" && printf '{{}}' && exit 0\n\
                 grep -q '\"title\":\"Killed\"' \"$d/stdin.log\" && kill -KILL $$\n\
                 {pause}printf '{{\"id\":\"newid123\",\"fields\":[{{\"value\":\"{OP_ECHOED_VALUE}\"}}]}}' ;;\n\
               *) exit 2 ;;\n\
             esac\n",
            directory = directory.display(),
            pause = if slow_create { "sleep 5; " } else { "" },
        ),
    )?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;
    if signed_in {
        std::fs::write(directory.join("authorized"), "")?;
    }

    Ok((program, log))
}

/// A file the fake `op` wrote beside its read log, empty when it never ran
fn op_file(log: &std::path::Path, name: &str) -> String {
    std::fs::read_to_string(log.with_file_name(name)).unwrap_or_default()
}

/// Prompts the companion Mac showed for creates, apart from the read the
/// gateway makes while booting
fn created_prompts(rig: &Rig) -> Vec<String> {
    rig.companion_mac
        .shown()
        .into_iter()
        .filter(|prompt| prompt.contains("to create in"))
        .collect()
}

const SECRET: &str = "zoho-mcp-url-secret-7f3a";

async fn create(rig: &Rig, vault: &str, title: &str) -> Result<Value, Box<dyn Error>> {
    let (status, body) = rig
        .harness
        .admin_json(
            "/admin/companion/create",
            &json!({ "vault": vault, "title": title, "value": SECRET }),
        )
        .await?;
    assert_eq!(status, 200, "{body}");
    assert!(!body.to_string().contains(SECRET), "{body}");
    assert!(!body.to_string().contains(OP_ECHOED_VALUE), "{body}");

    Ok(body)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_companion_creates_an_item_with_the_value_only_on_stdin() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };

    let body = create(&rig, "Personal", "Zoho MCP infraops").await?;
    assert_eq!(
        body,
        json!({ "created": {
            "companion": "mba",
            "id": "newid123",
            "reference": "op://Personal/Zoho MCP infraops/credential",
        } })
    );
    assert_eq!(
        created_prompts(&rig),
        ["touch_id codemode-mcp on main wants to create in Personal: \"Zoho MCP infraops\""]
    );

    // the template on stdin holds the value; nothing else `op` could see does
    let template: Value = serde_json::from_str(&op_file(&rig.companion_log, "stdin.log"))?;
    assert_eq!(template["title"], "Zoho MCP infraops");
    assert_eq!(template["category"], "API_CREDENTIAL");
    assert_eq!(template["fields"][0]["label"], "credential");
    assert_eq!(template["fields"][0]["value"], SECRET);
    let argv = op_file(&rig.companion_log, "argv.log");
    assert!(
        argv.contains("item create --vault Personal --format json -"),
        "{argv}"
    );
    assert!(!argv.contains(SECRET), "{argv}");
    assert!(!op_file(&rig.companion_log, "env.log").contains(SECRET));

    // the gateway's own `op` was not involved: it logs only what it reads,
    // and it never saw the item's arguments
    assert!(
        std::fs::read_to_string(&rig.local_log)
            .unwrap_or_default()
            .lines()
            .all(|line| line == REFERENCE)
    );

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vault_off_the_create_list_is_refused_before_anyone_is_asked() -> TestResult {
    for create_vaults in [&[][..], &["Work"][..]] {
        let Some(rig) = Rig::start(Options {
            create_vaults,
            ..Options::default()
        })
        .await?
        else {
            return Ok(());
        };

        let body = create(&rig, "Personal", "Zoho MCP infraops").await?;
        let message = body["refused"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("does not create items in Personal"),
            "{body}"
        );

        assert!(created_prompts(&rig).is_empty());
        assert!(!op_file(&rig.companion_log, "argv.log").contains("item"));

        rig.stop().await?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn creating_needs_the_owner_proof() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };

    let response = rig
        .harness
        .http
        .post(format!(
            "{}/admin/companion/create",
            rig.harness.admin_base()
        ))
        .json(&json!({ "vault": "Personal", "title": "Zoho", "value": SECRET }))
        .send()
        .await?;
    assert_eq!(response.status().as_u16(), 403);

    assert!(created_prompts(&rig).is_empty());
    assert!(!op_file(&rig.companion_log, "argv.log").contains("item"));

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn names_that_are_not_plain_ascii_are_refused_before_anyone_is_asked() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };

    let names = [
        "a/b",
        "line\nbreak",
        "-leading-dash",
        "Bank?attribute=password",
        "${HOME}",
        "say \"hi\"",
        "back\\slash",
        " leading space",
        "trailing space ",
        // Cyrillic о, which looks like the Latin one
        "Z\u{43e}ho",
    ];
    for name in names {
        for (vault, title) in [("Personal", name), (name, "Zoho")] {
            let body = create(&rig, vault, title).await?;
            let message = body["refused"]["message"].as_str().unwrap_or_default();
            assert!(message.contains("ASCII letters"), "{name:?}: {body}");
        }
    }

    assert!(created_prompts(&rig).is_empty());
    assert!(!op_file(&rig.companion_log, "argv.log").contains("item"));

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_existing_title_is_never_overwritten() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };

    // `Archived` is listed only when `--include-archive` is passed
    for title in ["Existing", "existing", "Archived"] {
        let body = create(&rig, "Personal", title).await?;
        let message = body["refused"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("already exists"), "{body}");
    }

    assert!(!op_file(&rig.companion_log, "argv.log").contains("item create"));
    assert!(op_file(&rig.companion_log, "stdin.log").is_empty());

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_that_touch_id_does_not_approve_writes_nothing() -> TestResult {
    let Some(rig) = Rig::start(Options {
        touch: Some(TouchId::Review),
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let body = create(&rig, "Personal", "Zoho MCP infraops").await?;
    let message = body["refused"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("not approved"), "{body}");
    assert!(!op_file(&rig.companion_log, "argv.log").contains("item"));

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_op_does_not_confirm_may_have_made_the_item() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };

    // `op` had the template each time, so the item may well be in the vault
    // though no id came back
    for (title, why) in [("No Id", "no item id"), ("Killed", "was stopped")] {
        let body = create(&rig, "Personal", title).await?;
        let message = body["unconfirmed"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(why), "{body}");
        assert!(message.contains("may have been created"), "{body}");
        assert!(body.get("refused").is_none(), "{body}");
    }

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_too_long_to_send_is_refused_before_anyone_is_asked() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };

    // quotes double in JSON, so this is short as text but long once escaped
    let value = "\"".repeat(20 * 1024);
    let (status, body) = rig
        .harness
        .admin_json(
            "/admin/companion/create",
            &json!({ "vault": "Personal", "title": "Huge", "value": value }),
        )
        .await?;
    assert_eq!(status, 200, "{body}");
    let message = body["refused"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("too long"), "{body}");

    assert!(created_prompts(&rig).is_empty());
    assert!(!op_file(&rig.companion_log, "argv.log").contains("item"));

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_that_loses_its_answer_may_have_made_the_item() -> TestResult {
    let Some(rig) = Rig::start(Options {
        slow_create: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    let Rig {
        harness,
        companion,
        companion_log: log,
        ..
    } = rig;
    let asking = async {
        let (status, body) = harness
            .admin_json(
                "/admin/companion/create",
                &json!({ "vault": "Personal", "title": "Zoho MCP infraops", "value": SECRET }),
            )
            .await?;
        assert_eq!(status, 200, "{body}");

        Ok::<_, Box<dyn Error>>(body)
    };
    // the companion goes away once `op item create` has started, as a lost
    // connection would
    let stopping = async {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !op_file(&log, "argv.log").contains("item create") {
            assert!(std::time::Instant::now() < deadline, "create never started");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // the hung-up connection is what matters; the detached create keeps
        // the companion's accept task busy until its own deadline
        let _ = tokio::time::timeout(Duration::from_secs(3), companion.shutdown()).await;
    };
    let (body, ()) = tokio::join!(asking, stopping);
    let body = body?;

    let message = body["unconfirmed"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("may have been created"), "{body}");
    assert!(body.get("refused").is_none(), "{body}");

    harness.stop().await
}

/// An `op` that logs the read, then its pid beside the log, then never
/// answers; the pid file appears whole and only after the log line
///
/// Like a wrapper that does not `exec` the real `op`, it leaves a child
/// holding its stdout. Once `op` is gone, killed and reaped, or after ten
/// seconds, that child writes there and records in `pipe` beside the log
/// whether anyone still had the pipe open
fn hanging_op() -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let log = directory.join("reads.log");
    let program = directory.join("op");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\n\
             echo \"$3\" >> '{log}'\n\
             (trap '' PIPE; i=0; \
               while kill -0 $$ 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done; \
               sleep 0.2; \
               if /bin/echo x 2>/dev/null; then state=open; else state=closed; fi; \
               echo $state > '{pipe}.tmp'; mv '{pipe}.tmp' '{pipe}') &\n\
             echo $$ > '{pid}.tmp'\n\
             mv '{pid}.tmp' '{pid}'\n\
             exec sleep 60\n",
            pid = directory.join("pid").display(),
            pipe = directory.join("pipe").display(),
            log = log.display(),
        ),
    )?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

    Ok((program, log))
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
async fn every_request_asks_touch_id_again() -> TestResult {
    let Some(rig) = Rig::start(Options::default()).await? else {
        return Ok(());
    };
    let check = json!({ "reference": REFERENCE });

    // the twin server reads once as it connects
    let body = rig
        .harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");

    let (status, checked) = rig
        .harness
        .admin_json("/admin/companion/check", &check)
        .await?;
    assert_eq!(status, 200, "{checked}");
    assert!(
        checked["companions"][0]["result"]["ok"].is_object(),
        "{checked}"
    );
    assert_eq!(reads(&rig.companion_log, REFERENCE), 2);

    // the same reference straight after an approval is asked again, and a
    // refusal then reads nothing
    rig.companion_mac.set_answer(Some(TouchId::Review));
    let (_, checked) = rig
        .harness
        .admin_json("/admin/companion/check", &check)
        .await?;
    let message = checked["companions"][0]["result"]["error"]["message"].as_str();
    assert!(
        message.is_some_and(|message| message.contains("denied")),
        "{checked}"
    );
    assert_eq!(reads(&rig.companion_log, REFERENCE), 2);
    assert_eq!(rig.companion_mac.cancel_titles().len(), 3);

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_out_1password_is_the_only_fingerprint_asked() -> TestResult {
    let Some(rig) = Rig::start(Options {
        signed_in: false,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let reason = format!("codemode-mcp on main wants to read {REFERENCE}");

    // 1Password's own prompt approves the first read, so the companion only
    // names it
    let body = rig
        .harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");
    assert_eq!(rig.companion_mac.shown(), [format!("notify {reason}")]);

    // once `op` is authorized it would read silently, so the companion asks
    let (status, checked) = rig
        .harness
        .admin_json("/admin/companion/check", &json!({ "reference": REFERENCE }))
        .await?;
    assert_eq!(status, 200, "{checked}");
    assert!(
        checked["companions"][0]["result"]["ok"].is_object(),
        "{checked}"
    );
    assert_eq!(
        rig.companion_mac.shown(),
        [format!("notify {reason}"), format!("touch_id {reason}")]
    );
    assert_eq!(reads(&rig.companion_log, REFERENCE), 2);

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_another_op_authorized_meanwhile_still_asks_touch_id() -> TestResult {
    // another `op` on that Mac is approved while the notification is up,
    // so 1Password will not ask for this read after all
    let Some(rig) = Rig::start(Options {
        signed_in: false,
        authorized_on_notify: true,
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };
    let reason = format!("codemode-mcp on main wants to read {REFERENCE}");

    let body = rig
        .harness
        .execute_json(r#"await twin_env(name="FIXTURE_SECRET")"#)
        .await?;
    assert_eq!(body["result"], VALUE, "{body}");
    assert_eq!(
        rig.companion_mac.shown(),
        [format!("notify {reason}"), format!("touch_id {reason}")]
    );

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_no_notification_could_name_still_asks_touch_id() -> TestResult {
    let Some(rig) = Rig::start(Options {
        signed_in: false,
        notify_fails: true,
        touch: Some(TouchId::Review),
        ..Options::default()
    })
    .await?
    else {
        return Ok(());
    };

    // with 1Password about to ask but nothing naming the reference, the
    // companion's own prompt still gates the read, and a refusal reads nothing
    let (_, checked) = rig
        .harness
        .admin_json("/admin/companion/check", &json!({ "reference": REFERENCE }))
        .await?;
    let message = checked["companions"][0]["result"]["error"]["message"].as_str();
    assert!(
        message.is_some_and(|message| message.contains("not approved")),
        "{checked}"
    );
    // the twin server's read as it connects was asked the same way
    let shown = rig.companion_mac.shown();
    let prompt = format!("touch_id codemode-mcp on main wants to read {REFERENCE}");
    assert!(
        !shown.is_empty() && shown.iter().all(|entry| *entry == prompt),
        "{shown:?}"
    );
    assert_eq!(reads(&rig.companion_log, REFERENCE), 0);

    rig.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn mac_notifications_off_still_skip_the_local_read_while_the_owner_is_away() -> TestResult {
    let Some(rig) = Rig::start(Options {
        mac_notifications: false,
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
    assert_eq!(reads(&rig.local_log, REFERENCE), 0);
    assert_eq!(reads(&rig.companion_log, REFERENCE), 1);

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
async fn a_companion_wins_while_the_gateway_looks_in_use() -> TestResult {
    // remote desktop input makes the gateway look in use while nobody can
    // answer its 1Password prompt, so its `op` hangs
    let Some(rig) = Rig::start(Options {
        present: true,
        local_hangs: true,
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
    assert_eq!(
        reads(&rig.local_log, REFERENCE),
        1,
        "the local read started"
    );
    assert_eq!(reads(&rig.companion_log, REFERENCE), 1);

    // the losing `op` is killed, not left waiting on the screen
    let pid = std::fs::read_to_string(rig.local_log.with_file_name("pid"))?;
    let mut alive = true;
    for _ in 0..40 {
        alive = std::process::Command::new("kill")
            .args(["-0", pid.trim()])
            .status()?
            .success();
        if !alive {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!alive, "the local op {} still runs", pid.trim());

    // and its output is no longer read, though a child of it still holds
    // the pipe
    let pipe = rig.local_log.with_file_name("pipe");
    for _ in 0..150 {
        if pipe.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(std::fs::read_to_string(&pipe)?.trim(), "closed");

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
         env = {{ X = \"k-{{{{ op://Dev/a/credential }}}}\" }}\n\n\
         [servers.d]\n\
         url = \"http://127.0.0.1:9/mcp\"\n\
         oauth = true\n\
         client_id = \"known\"\n\
         client_secret = \"{{{{ op://Dev/oauth/credential }}}}\"\n",
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
        json!([
            "op://Dev/a/credential",
            "op://Dev/b/credential",
            "op://Dev/oauth/credential"
        ])
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
    let Paired::Written(pairing) = companion::pair(&ticket, &config, Some(&identity), None)? else {
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
        companion::pair(&ticket, &config, Some(&identity), None)?,
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

    let Paired::Written(pairing) = companion::pair(&ticket, &config, Some(&relative), None)? else {
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

/// A gateway with no companions yet whose `twin` server uses [`REFERENCE`],
/// and the key file of its iroh identity
async fn inviting_gateway() -> Result<Option<(Harness, PathBuf)>, Box<dyn Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let key = directory.join("gateway.key");
    let (op, _) = fake_op()?;
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\
         discovery = false\n\
         identity_file = \"{key}\"\n\n\
         [servers.twin]\n\
         command = \"{fixture}\"\n\
         env = {{ FIXTURE_SECRET = \"{{{{ {REFERENCE} }}}}\" }}\n",
        op = op.display(),
        key = key.display(),
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
    );
    let gateway_mac = Arc::new(FakeMac::default());
    gateway_mac.set_present(false);
    let harness = Harness::with(Setup {
        extra: &extra,
        mac: Some(gateway_mac),
        ..Setup::default()
    })
    .await?;

    Ok(harness.map(|harness| (harness, key)))
}

/// Opens an invite on `harness` and returns its id and its ticket, pointed
/// at the gateway's loopback address
async fn open_invite(
    harness: &Harness,
    valid_secs: u64,
) -> Result<(String, InviteTicket), Box<dyn Error>> {
    let (status, opened) = harness
        .admin_json(
            "/admin/companion/invite/open",
            &json!({ "valid_secs": valid_secs }),
        )
        .await?;
    assert_eq!(status, 200, "{opened}");
    let mut ticket = InviteTicket::decode(opened["ticket"].as_str().ok_or("no ticket")?)?;
    // discovery is off, so the ticket names this Mac's addresses; the test
    // dials loopback instead
    assert!(!ticket.addrs.is_empty());
    let port = harness
        .app
        .gateway()
        .companions()
        .bound_addrs()
        .into_iter()
        .find(|addr| addr.is_ipv4())
        .ok_or("the gateway bound no IPv4 socket")?
        .port();
    ticket.addrs = vec![([127, 0, 0, 1], port).into()];

    Ok((
        opened["invite"].as_str().ok_or("no invite id")?.to_owned(),
        ticket,
    ))
}

async fn invite_status(harness: &Harness, invite: &str) -> Result<Value, Box<dyn Error>> {
    let (status, body) = harness
        .admin_json(
            "/admin/companion/invite/status",
            &json!({ "invite": invite }),
        )
        .await?;
    assert_eq!(status, 200, "{body}");

    Ok(body)
}

/// The `[[secrets.companions]]` the gateway's config file lists
fn listed(harness: &Harness) -> Result<Vec<(String, iroh::EndpointId)>, Box<dyn Error>> {
    let path = harness
        .app
        .config()
        .path()
        .ok_or("the config has no file")?;

    Ok(Config::load(path)?
        .secrets
        .companions
        .into_iter()
        .map(|peer| (peer.name, peer.id))
        .collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_lists_a_companion_once_and_checks_it_with_touch_id() -> TestResult {
    let Some((harness, gateway_key)) = inviting_gateway().await? else {
        return Ok(());
    };
    let (invite, ticket) = open_invite(&harness, 60).await?;
    assert_eq!(
        ticket.gateway,
        companion::load_or_create(Role::Gateway, Some(&gateway_key))?.public()
    );

    // the companion's agent, as `companion install` would start it
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let (companion_op, companion_log) = fake_op()?;
    let companion_mac = Arc::new(FakeMac::default());
    companion_mac.set_answer(Some(TouchId::Approved));
    let text = format!(
        "[companion]\n\
         gateway = \"{gateway}\"\n\
         allow = [\"{REFERENCE}\"]\n\
         listen = \"127.0.0.1:0\"\n\
         discovery = false\n\
         identity_file = \"{key}\"\n\
         op = \"{op}\"\n",
        gateway = ticket.gateway,
        key = directory.join("companion.key").display(),
        op = companion_op.display(),
    );
    let config = Config::parse(&text, std::path::Path::new("companion.toml"))?
        .companion
        .ok_or("the companion section is missing")?;
    let agent = companion::serve(config, Some(Arc::clone(&companion_mac) as Arc<dyn Mac>)).await?;
    let agent_addr = agent
        .bound_addrs()
        .into_iter()
        .find(|address| address.is_ipv4())
        .ok_or("the companion bound no IPv4 socket")?;

    let joining = || Joining {
        ticket: &ticket,
        id: agent.id(),
        name: "mba".to_owned(),
        addrs: vec![agent_addr],
        port: companion::DIRECT_PORT,
    };
    let joined = companion::join(joining()).await?;
    let registered = joined.registered().clone();
    assert_eq!(registered.name, "mba");
    assert_eq!(registered.references, [REFERENCE]);
    assert!(!registered.already_listed);

    // listed in the config file, but not read through until the check
    // reaches it, so a Mac whose setup fails is never asked instead of `op`
    assert_eq!(listed(&harness)?, [("mba".to_owned(), agent.id())]);
    assert!(harness.app.gateway().companions().peers().is_empty());
    assert_eq!(
        invite_status(&harness, &invite).await?["state"],
        "registered"
    );

    // the check reads through the new companion after its own Touch ID
    let check = joined.check().await?;
    assert_eq!(
        check,
        PairCheck::Read {
            reference: REFERENCE.to_owned(),
            bytes: VALUE.len(),
        }
    );
    assert_eq!(reads(&companion_log, REFERENCE), 1);
    let peers = harness.app.gateway().companions().peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].addrs, [agent_addr]);
    assert_eq!(
        companion_mac.shown(),
        [format!(
            "touch_id codemode-mcp on main wants to read {REFERENCE}"
        )]
    );
    let mut done = Value::Null;
    for _ in 0..40 {
        done = invite_status(&harness, &invite).await?;
        if done["state"] == "done" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(done["name"], "mba", "{done}");
    assert_eq!(done["check"]["read"]["bytes"], VALUE.len(), "{done}");
    assert_eq!(done["in_use"], true, "{done}");
    assert!(!done.to_string().contains(VALUE), "{done}");

    // the secret works once, even with another invite keeping pairing open
    let _other = open_invite(&harness, 60).await?;
    let reused = companion::join(joining()).await.err();
    assert!(
        matches!(&reused, Some(JoinError::Refused(message)) if message.contains("already used")),
        "{reused:?}"
    );
    assert_eq!(listed(&harness)?.len(), 1);

    agent.shutdown().await;
    let _ = std::fs::remove_dir_all(&directory);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_or_unknown_invite_lists_nothing() -> TestResult {
    let Some((harness, _)) = inviting_gateway().await? else {
        return Ok(());
    };
    let id = iroh::SecretKey::generate().public();
    let joining = |ticket| Joining {
        ticket,
        id,
        name: "mba".to_owned(),
        addrs: vec![([127, 0, 0, 1], 7678).into()],
        port: companion::DIRECT_PORT,
    };

    // the loopback check alone admits every account on the Mac, so opening
    // an invite also needs the token only the daemon's user can read
    let mode = std::fs::metadata(
        harness
            .app
            .state_dir()
            .join(codemode_mcp::admin::OWNER_TOKEN_FILE),
    )?
    .permissions()
    .mode();
    assert_eq!(mode & 0o777, 0o600);
    let open_path = "/admin/companion/invite/open";
    let open = |proof: Option<&str>| {
        let request = harness
            .http
            .post(format!("{}{open_path}", harness.admin_base()))
            // expires with the invite below, so pairing closes with it
            .json(&json!({ "valid_secs": 1 }));
        match proof {
            Some(proof) => request.header(codemode_mcp::admin::OWNER_PROOF_HEADER, proof),
            None => request,
        }
    };
    let proof = harness.owner_proof(open_path).await?;
    assert_eq!(open(Some(&proof)).send().await?.status().as_u16(), 200);
    let token = std::fs::read_to_string(
        harness
            .app
            .state_dir()
            .join(codemode_mcp::admin::OWNER_TOKEN_FILE),
    )?;
    let other_route = harness.owner_proof("/admin/companion/invite").await?;
    // no proof, the token itself (which the CLI never sends), a proof made
    // for another route, and the used proof again
    for refused in [None, Some(token.trim()), Some(&other_route), Some(&proof)] {
        let status = open(refused).send().await?.status().as_u16();
        assert_eq!(status, 403, "{refused:?}");
    }

    let (expired, short) = open_invite(&harness, 1).await?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(invite_status(&harness, &expired).await?["state"], "expired");

    // with no invite open the gateway accepts no connection at all
    let refused = companion::join(joining(&short)).await.err();
    assert!(
        matches!(refused, Some(JoinError::Unreachable(_))),
        "{refused:?}"
    );

    // another invite reopens pairing, but not for the expired secret
    let (_, open) = open_invite(&harness, 60).await?;
    let late = companion::join(joining(&short)).await.err();
    assert!(
        matches!(&late, Some(JoinError::Refused(message)) if message.contains("expired")),
        "{late:?}"
    );

    let forged = InviteTicket {
        secret: InviteSecret::generate(),
        ..open
    };
    let unknown = companion::join(joining(&forged)).await.err();
    assert!(
        matches!(&unknown, Some(JoinError::Refused(message)) if message.contains("no such invite")),
        "{unknown:?}"
    );

    assert!(listed(&harness)?.is_empty());
    assert!(harness.app.gateway().companions().peers().is_empty());

    harness.stop().await
}
