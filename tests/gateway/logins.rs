//! The `logins` builtin: a password approved at the Mac goes into the
//! focused password field of a page on the login's site, in a browser
//! known by its code signature, and never into the script's answer

use std::sync::Arc;

use codemode_mcp::{
    logins::{Exposure, FieldKind, FocusedField, Setting},
    mac::TouchId,
};
use serde_json::json;

use super::{
    harness::{FakeMac, Harness, Setup, TestResult},
    secrets::{VALUE, fake_op, reads},
};

const REFERENCE: &str = "op://Dev/fixture/credential";
/// A password with a line break, which typing would turn into Return
const MULTILINE: &str = "op://Dev/linebreak/credential";

const FILL: &str = r#"
try:
    filled = await logins_fill(login="github", field="password")
except RuntimeError as error:
    filled = str(error)
filled
"#;

fn field(kind: FieldKind, url: &str) -> FocusedField {
    FocusedField {
        kind,
        pages: vec![url.to_owned()],
        browser: Some("Safari".to_owned()),
        exposure: Exposure::default(),
    }
}

/// A harness with a `logins` server whose `github` login has a password, on
/// `github.com` and the hosts under `github.io`
async fn logins_harness(
    mac: &Arc<FakeMac>,
) -> Result<Option<(Harness, std::path::PathBuf)>, Box<dyn std::error::Error>> {
    let (op, log) = fake_op()?;
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\n\
         [servers.logins]\n\
         builtin = \"logins\"\n\
         policy = \"ask\"\n\
         tools.fill.grant = \"per_call\"\n\
         tools.list.policy = \"allow\"\n\n\
         [logins.github]\n\
         sites = [\"github.com\", \"*.github.io\"]\n\
         password = \"{REFERENCE}\"\n\n\
         [logins.multiline]\n\
         sites = [\"github.com\"]\n\
         password = \"{MULTILINE}\"\n",
        op = op.display(),
    );
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        notify: true,
        mac: Some(Arc::clone(mac)),
        ..Setup::default()
    })
    .await?
    else {
        return Ok(None);
    };
    let _passkey = harness.enroll_passkey().await?;
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Approved));

    Ok(Some((harness, log)))
}

/// Touch ID prompts shown so far
fn prompts(mac: &FakeMac) -> Vec<String> {
    mac.shown()
        .into_iter()
        .filter(|shown| shown.starts_with("touch_id "))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_is_typed_into_its_site_and_never_returned() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some((harness, log)) = logins_harness(&mac).await? else {
        return Ok(());
    };

    let listed = harness.execute_json("await logins_list()").await?;
    assert_eq!(
        listed["result"],
        json!({"logins": [
            {"name": "github", "sites": ["github.com", "*.github.io"], "fields": ["password"]},
            {"name": "multiline", "sites": ["github.com"], "fields": ["password"]},
        ]}),
        "{listed}"
    );

    // the wrong field is refused before the owner or 1Password is asked
    mac.set_focused(field(FieldKind::Text, "https://github.com/login"));
    let refused = harness.execute_json(FILL).await?;
    let text = refused["result"].as_str().unwrap_or_default();
    assert!(text.contains("not a password field"), "{refused}");
    assert_eq!(reads(&log, REFERENCE), 0);
    assert_eq!(prompts(&mac), Vec::<String>::new());

    // the owner sees where the password would go
    mac.set_focused(field(FieldKind::Secure, "https://github.com/login"));
    let filled = harness.execute_json(FILL).await?;
    assert_eq!(
        filled["result"],
        json!({"login": "github", "field": "password", "host": "github.com"}),
        "{filled}"
    );
    assert_eq!(mac.typed(), VALUE);
    assert!(!filled.to_string().contains(VALUE), "{filled}");
    assert_eq!(reads(&log, REFERENCE), 1);
    assert!(
        prompts(&mac).first().is_some_and(|shown| shown.starts_with(
            "touch_id approve logins.fill once: password for github into github.com in Safari, \
             asked by"
        )),
        "{:?}",
        mac.shown()
    );

    // a look-alike host gets nothing, and the owner is not asked
    mac.set_focused(field(
        FieldKind::Secure,
        "https://github.com.evil.example/login",
    ));
    let phished = harness.execute_json(FILL).await?;
    let text = phished["result"].as_str().unwrap_or_default();
    assert!(text.contains("github.com.evil.example"), "{phished}");
    assert!(!phished.to_string().contains(VALUE), "{phished}");
    assert_eq!(mac.typed(), VALUE);
    assert_eq!(prompts(&mac).len(), 1);

    // a line break would press Return on the page, so none of it is typed
    mac.set_focused(field(FieldKind::Secure, "https://github.com/login"));
    let multiline = harness
        .execute_json(&FILL.replace("\"github\"", "\"multiline\""))
        .await?;
    let text = multiline["result"].as_str().unwrap_or_default();
    assert!(text.contains("control character"), "{multiline}");
    assert!(
        !multiline.to_string().contains("second-line"),
        "{multiline}"
    );
    assert_eq!(reads(&log, MULTILINE), 1);
    assert_eq!(mac.typed(), VALUE);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn only_a_verified_browser_that_scripts_cannot_drive_gets_a_login() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some((harness, log)) = logins_harness(&mac).await? else {
        return Ok(());
    };
    let page = field(FieldKind::Secure, "https://github.com/login");

    for (focused, expected) in [
        // an app whose signature is no known browser, such as one an agent
        // built to show a page of its choosing
        (
            FocusedField {
                browser: None,
                ..page.clone()
            },
            "not in a browser codemode-mcp can verify",
        ),
        (
            FocusedField {
                browser: Some("Chrome".to_owned()),
                exposure: Exposure {
                    remote_debugging: Setting::On,
                    ..Exposure::default()
                },
                ..page.clone()
            },
            "Chrome was started with remote debugging",
        ),
        (
            FocusedField {
                exposure: Exposure {
                    apple_events_javascript: Setting::On,
                    ..Exposure::default()
                },
                ..page.clone()
            },
            "Safari allows JavaScript from Apple Events",
        ),
    ] {
        mac.set_focused(focused);
        let refused = harness.execute_json(FILL).await?;
        let text = refused["result"].as_str().unwrap_or_default();
        assert!(text.contains(expected), "{refused}");
    }
    assert_eq!(reads(&log, REFERENCE), 0);
    assert_eq!(prompts(&mac), Vec::<String>::new());
    assert_eq!(mac.typed(), "");

    // a setting that could not be read is the owner's call, so they see it
    mac.set_focused(FocusedField {
        browser: Some("Chrome".to_owned()),
        exposure: Exposure {
            apple_events_javascript: Setting::Unknown,
            ..Exposure::default()
        },
        ..page
    });
    let filled = harness.execute_json(FILL).await?;
    assert_eq!(filled["result"]["host"], "github.com", "{filled}");
    assert!(
        prompts(&mac).first().is_some_and(|shown| shown.contains(
            "password for github into github.com in Chrome; could not check whether Chrome \
             allows JavaScript from Apple Events"
        )),
        "{:?}",
        mac.shown()
    );
    assert_eq!(mac.typed(), VALUE);

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_page_that_moves_while_the_owner_decides_gets_nothing() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some((harness, log)) = logins_harness(&mac).await? else {
        return Ok(());
    };

    // both hosts are the login's, but the owner approved only the first
    mac.set_focused(field(FieldKind::Secure, "https://github.com/login"));
    mac.set_focus_on_prompt(field(FieldKind::Secure, "https://me.github.io/login"));
    let moved = harness.execute_json(FILL).await?;
    let text = moved["result"].as_str().unwrap_or_default();
    assert!(
        text.contains("now on me.github.io, but the owner approved filling on github.com"),
        "{moved}"
    );
    assert!(
        prompts(&mac)
            .first()
            .is_some_and(|shown| shown.contains("into github.com in Safari")),
        "{:?}",
        mac.shown()
    );
    assert_eq!(reads(&log, REFERENCE), 0);
    assert_eq!(mac.typed(), "");

    harness.stop().await
}
