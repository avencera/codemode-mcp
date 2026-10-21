//! A hub and a spoke in one process: the spoke is trusted once on the hub,
//! calls a server the owner signed in to on the hub, has its own `ask` tool
//! approved there, and gets 1Password values the hub read, for one of its
//! own servers and for a file on its own disk

use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{Request, StatusCode},
};
use codemode_mcp::{hub, mac::TouchId};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{
    harness::{FakeMac, Harness, ORIGIN, Setup, TestResult, approval_id, temp_state_dir, text_of},
    oauth::{Client, begin_login, start_mock, wait_for_state},
    secrets::{VALUE, fake_op},
};

/// The reference the fake `op` reads as [`VALUE`]
const REFERENCE: &str = "op://Dev/fixture/credential";

/// Waits until `function` is in `harness`'s catalog
async fn wait_for_tool(harness: &Harness, function: &str) -> TestResult {
    for _ in 0..300 {
        if harness.app.gateway().catalog().get(function).is_some() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(format!("{function} never reached the catalog").into())
}

/// Runs `code` on `harness`, waiting it out when it outlasts the
/// synchronous wait, and returns the finished body
async fn finished(harness: &Harness, body: Value) -> Result<Value, Box<dyn Error>> {
    if body["status"] != "pending" {
        return Ok(body);
    }
    let id = body["execution_id"].as_str().ok_or("no execution id")?;
    let done = harness.wait_done(id).await?;

    Ok(serde_json::from_str(&text_of(&done))?)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_spoke_uses_the_hubs_sign_ins_approvals_and_secrets() -> TestResult {
    let mock = start_mock(Client::Known).await?;
    let (op, _) = fake_op()?;
    // the owner sits at the hub Mac and every Touch ID prompt approves
    let hub_mac = Arc::new(FakeMac::default());
    hub_mac.set_present(true);
    hub_mac.set_answer(Some(TouchId::Approved));
    let hub_extra = format!(
        "[secrets]\nop = \"{op}\"\n\n\
         [servers.known]\nurl = \"{base}/mcp\"\noauth = true\n\
         client_id = \"known-client\"\nclient_secret = \"known-secret\"\n\
         tools.hello.policy = \"ask\"\ntools.hello.grant = \"per_call\"\n",
        op = op.display(),
        base = mock.base,
    );
    let Some(hub) = Harness::with(Setup {
        notify: true,
        mac: Some(Arc::clone(&hub_mac)),
        extra: &hub_extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let mut passkey = hub.enroll_passkey().await?;

    // the owner signs in once, on the hub
    wait_for_state(&hub, "known", "needs_login").await?;
    let (callback, _) = begin_login(&hub, &mock, "known").await?;
    assert_eq!(hub.http.get(&callback).send().await?.status().as_u16(), 200);
    wait_for_state(&hub, "known", "connected").await?;
    wait_for_tool(&hub, "known_hello").await?;

    // the spoke has its own fixture, with `add` asking, and leaves the
    // hub's out, which has the same name. Its `vault` server needs a
    // 1Password value, which only the hub can read
    let hub_port = hub.server.local_addr().port();
    let spoke_extra = format!(
        "[hub]\nhost = \"127.0.0.1:{hub_port}\"\nexclude = [\"fixture\"]\n\n\
         [servers.secrets]\nbuiltin = \"secrets\"\n\n\
         [servers.vault]\ncommand = \"{fixture}\"\n\
         env = {{ FIXTURE_SECRET = \"{{{{ {REFERENCE} }}}}\" }}\n",
        fixture = env!("CARGO_BIN_EXE_codemode-fixture"),
    );
    let Some(spoke) = Harness::with(Setup {
        server: "tools.add.policy = \"ask\"",
        extra: &spoke_extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let name = spoke
        .app
        .gateway()
        .hub()
        .ok_or("the spoke has no hub")?
        .machine()
        .name
        .clone();

    // first contact asks the owner, by Touch ID at the hub, to trust it
    spoke.app.connect_hub(Duration::from_secs(5)).await?;
    wait_for_tool(&spoke, "known_hello").await?;
    assert!(
        hub_mac
            .shown()
            .iter()
            .any(|prompt| prompt.contains("Trust") && prompt.contains(&name)),
        "{:?}",
        hub_mac.shown()
    );
    let spokes = hub.app.hub().ok_or("the hub has no spokes")?;
    let trusted = spokes.spokes();
    assert_eq!(trusted.len(), 1, "{trusted:?}");
    assert_eq!(trusted[0].name, name);
    // the spoke's id from another tailnet address is not the spoke
    let elsewhere = hub::server::router(Arc::clone(spokes))
        .layer(MockConnectInfo(SocketAddr::from(([100, 64, 9, 9], 40000))))
        .oneshot(
            Request::get(format!("{}/catalog", hub::API))
                .header(hub::SPOKE_HEADER, &trusted[0].id)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(elsewhere.status(), StatusCode::FORBIDDEN);
    // the hub's fixture stayed out: `add` is the spoke's own, which asks
    let catalog = spoke.app.gateway().catalog();
    let add = catalog.get("fixture_add").ok_or("no fixture_add")?;
    assert_eq!(add.policy, codemode_mcp::policy::Policy::Ask);

    // `vault` waited for the trust, then the owner gave it the value once,
    // on the hub
    wait_for_tool(&spoke, "vault_env").await?;
    let body = spoke
        .execute_body("await vault_env(name=\"FIXTURE_SECRET\")")
        .await?;
    let body = finished(&spoke, body).await?;
    assert_eq!(body["result"], VALUE, "{body}");
    assert!(
        hub_mac
            .shown()
            .iter()
            .any(|prompt| prompt.contains(REFERENCE)
                && prompt.contains("vault")
                && prompt.contains(&name)),
        "{:?}",
        hub_mac.shown()
    );

    // a tool of the hub's signed-in server runs on the hub, under the hub's
    // policy: it asks there, and Touch ID approves the call the hub holds.
    // The token never reaches the spoke
    let called = spoke.execute_body("await known_hello()").await?;
    let called = finished(&spoke, called).await?;
    assert_eq!(called["result"], "hello", "{called}");
    assert!(!spoke.state_holds("tok-"));
    assert!(
        hub_mac
            .shown()
            .iter()
            .any(|prompt| prompt.contains("known.hello") && prompt.contains(&name)),
        "{:?}",
        hub_mac.shown()
    );

    // the spoke's own `ask` tool is approved on the hub, which names the
    // spoke; the execution parks meanwhile and resumes on the verdict
    hub_mac.set_answer(None);
    let pending = spoke
        .execute_body("int(await fixture_add(a=1, b=2))")
        .await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let link = pending["approval_url"].as_str().unwrap_or_default();
    assert!(link.starts_with(ORIGIN), "the hub's page: {pending}");
    let id = approval_id(&pending)?;
    // asked at the hub Mac first, naming the spoke and its client
    let asker = format!("{name} · harness-client");
    let prompt = hub_mac
        .shown()
        .into_iter()
        .find(|prompt| prompt.contains("fixture.add"))
        .ok_or("no prompt for fixture.add")?;
    assert!(prompt.contains(&asker), "{prompt}");
    let (status, approved) = hub.approve_with_passkey(&mut passkey, &id, "once").await?;
    assert_eq!(status, 200, "{approved}");
    let done = finished(&spoke, pending).await?;
    assert_eq!(done["result"], 3, "{done}");

    // write_env reads on the hub and writes on the spoke's disk; the agent
    // sees only the name
    hub_mac.set_answer(Some(TouchId::Approved));
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let directory = std::fs::canonicalize(&directory)?;
    let file = directory.join("app.secrets.env");
    let code = format!(
        "await secrets_write_env(path=\"{path}\", vars={{\"TOKEN\": \"{REFERENCE}\"}}, \
         reason=\"deploy\")",
        path = file.display()
    );
    let body = spoke.execute_body(&code).await?;
    let done = finished(&spoke, body).await?;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["result"]["added"], json!(["TOKEN"]), "{done}");
    assert!(!done.to_string().contains(VALUE), "{done}");
    assert_eq!(std::fs::read_to_string(&file)?, format!("TOKEN={VALUE}\n"));
    // the hub's prompt said where the value goes
    let destination = format!("{name}:{}", file.display());
    assert!(
        hub_mac
            .shown()
            .iter()
            .any(|prompt| prompt.contains(&destination)),
        "{:?}",
        hub_mac.shown()
    );

    let _ = std::fs::remove_dir_all(&directory);
    spoke.stop().await?;
    hub.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_spoke_execution_parked_on_the_hub_survives_restarts_of_both() -> TestResult {
    let hub_mac = Arc::new(FakeMac::default());
    hub_mac.set_present(true);
    hub_mac.set_answer(Some(TouchId::Approved));
    let Some(hub) = Harness::with(Setup {
        notify: true,
        mac: Some(Arc::clone(&hub_mac)),
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let mut passkey = hub.enroll_passkey().await?;
    let hub_address = hub.server.local_addr();

    // not sensitive, so the parked execution and both copies of its
    // request are kept on disk
    let spoke_extra = format!(
        "[hub]\nhost = \"127.0.0.1:{}\"\nexclude = [\"fixture\"]\n",
        hub_address.port()
    );
    let Some(spoke) = Harness::with(Setup {
        server: "tools.add.policy = \"ask\"\nsensitive = false",
        extra: &spoke_extra,
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    spoke.app.connect_hub(Duration::from_secs(5)).await?;
    let trusted_spokes = || hub.app.hub().map_or(0, |hub| hub.spokes().len());
    for _ in 0..300 {
        if trusted_spokes() == 1
            && spoke
                .app
                .gateway()
                .hub()
                .is_some_and(|hub| hub.is_trusted())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(trusted_spokes(), 1);

    hub_mac.set_answer(None);
    let pending = spoke
        .execute_body("int(await fixture_add(a=2, b=3))")
        .await?;
    assert_eq!(pending["status"], "pending", "{pending}");
    let execution = pending["execution_id"]
        .as_str()
        .ok_or("no execution id")?
        .to_owned();
    let id = approval_id(&pending)?;

    // the spoke stops and starts while the owner has not answered; its
    // execution is parked on its copy of the hub's request
    let spoke = spoke.restart(super::harness::Stop::Drain).await?;
    spoke.app.connect_hub(Duration::from_secs(5)).await?;
    // then the hub does, on the same address
    let hub = hub
        .restart_with(super::harness::Stop::Drain, |config| {
            config.listen = hub_address;
        })
        .await?;

    let (status, approved) = hub.approve_with_passkey(&mut passkey, &id, "once").await?;
    assert_eq!(status, 200, "{approved}");
    let done = spoke.wait_done(&execution).await?;
    let done: Value = serde_json::from_str(&text_of(&done))?;
    assert_eq!(done["result"], 5, "{done}");

    spoke.stop().await?;
    hub.stop().await
}
