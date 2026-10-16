//! The `logins` builtin: a password approved at the Mac goes into the
//! focused password field of a page on the login's site, and never into the
//! script's answer

use std::sync::Arc;

use codemode_mcp::{
    logins::{FieldKind, FocusedField},
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
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_is_typed_into_its_site_and_never_returned() -> TestResult {
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
         sites = [\"github.com\"]\n\
         password = \"{REFERENCE}\"\n\n\
         [logins.multiline]\n\
         sites = [\"github.com\"]\n\
         password = \"{MULTILINE}\"\n",
        op = op.display(),
    );
    let mac = Arc::new(FakeMac::default());
    let Some(harness) = Harness::with(Setup {
        extra: &extra,
        notify: true,
        mac: Some(Arc::clone(&mac)),
        ..Setup::default()
    })
    .await?
    else {
        return Ok(());
    };
    let _passkey = harness.enroll_passkey().await?;
    mac.set_present(true);
    mac.set_answer(Some(TouchId::Approved));

    let listed = harness.execute_json("await logins_list()").await?;
    assert_eq!(
        listed["result"],
        json!({"logins": [
            {"name": "github", "sites": ["github.com"], "fields": ["password"]},
            {"name": "multiline", "sites": ["github.com"], "fields": ["password"]},
        ]}),
        "{listed}"
    );

    // the wrong field is refused before 1Password is asked
    mac.set_focused(field(FieldKind::Text, "https://github.com/login"));
    let refused = harness.execute_json(FILL).await?;
    let text = refused["result"].as_str().unwrap_or_default();
    assert!(text.contains("not a password field"), "{refused}");
    assert_eq!(reads(&log, REFERENCE), 0);
    assert!(
        mac.shown()
            .first()
            .is_some_and(|shown| shown.starts_with("touch_id approve logins.fill once")),
        "{:?}",
        mac.shown()
    );

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

    // a look-alike host gets nothing, though the value is known by now
    mac.set_focused(field(
        FieldKind::Secure,
        "https://github.com.evil.example/login",
    ));
    let phished = harness.execute_json(FILL).await?;
    let text = phished["result"].as_str().unwrap_or_default();
    assert!(text.contains("github.com.evil.example"), "{phished}");
    assert!(!phished.to_string().contains(VALUE), "{phished}");
    assert_eq!(mac.typed(), VALUE);

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
