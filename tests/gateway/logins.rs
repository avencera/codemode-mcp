//! The `logins` builtin: the 1Password login saved for the focused page's
//! site goes into its password field, approved at the Mac, in a browser
//! known by its code signature, and never into the script's answer

use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use codemode_mcp::{
    logins::{Exposure, FieldKind, FocusedField, Setting, totp::Totp},
    mac::TouchId,
};
use serde_json::{Value, json};

use super::{
    harness::{FakeMac, Harness, Setup, TestResult, temp_state_dir},
    secrets::{TOTP_SECRET, VALUE},
};

/// GitHub's password, by the IDs `op item get` gave
const GITHUB_PASSWORD: &str = "op://v1/gh1/password";
/// GitHub's one-time password, whose seed is [`TOTP_SECRET`]
const GITHUB_ONE_TIME: &str = "op://v1/gh1/TOTP_1";
/// The work GitLab login's password
const WORK_GITLAB: &str = "gitlab-work-password";

const FILL: &str = r#"
try:
    filled = await logins_fill(field="password")
except RuntimeError as error:
    filled = str(error)
filled
"#;

/// [`FILL`] for the item `item`
fn fill_item(item: &str) -> String {
    FILL.replace(
        "field=\"password\"",
        &format!("field=\"password\", item=\"{item}\""),
    )
}

fn field(kind: FieldKind, url: &str) -> FocusedField {
    FocusedField {
        kind,
        pages: vec![url.to_owned()],
        browser: Some("Safari".to_owned()),
        exposure: Exposure::default(),
    }
}

/// A Login item as `op item list` lists it
fn listed(id: &str, title: &str, vault: (&str, &str), urls: &[&str]) -> Value {
    json!({
        "id": id,
        "title": title,
        "category": "LOGIN",
        "vault": { "id": vault.0, "name": vault.1 },
        "additional_information": "me@example.com",
        "urls": urls.iter().map(|href| json!({ "href": href })).collect::<Vec<_>>(),
    })
}

/// The item as `op item get` opens it: a username, a password and, for
/// GitHub, a one-time password, with values the daemon must never copy out
fn opened(id: &str, one_time: bool) -> Value {
    let mut fields = vec![
        json!({"id": "username", "type": "STRING", "purpose": "USERNAME", "label": "username",
               "value": "me@example.com"}),
        json!({"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password",
               "value": "listed-value-never-copied"}),
    ];
    if one_time {
        fields.push(
            json!({"id": "TOTP_1", "type": "OTP", "label": "one-time password",
                           "value": "otpauth://never-copied"}),
        );
    }

    json!({ "id": id, "fields": fields })
}

/// A fake `op` that lists and opens the items above and reads their
/// fields, logging the third argument of every call: the reference read, or
/// the item opened
fn logins_op() -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let directory = temp_state_dir();
    std::fs::create_dir_all(&directory)?;
    let personal = ("v1", "Personal");
    let items = json!([
        listed("gh1", "GitHub", personal, &["https://github.com/login"]),
        listed("ap1", "Apple ID", personal, &["https://appleid.apple.com"]),
        listed("ml1", "Line Break", personal, &["multiline.example"]),
        listed("gl1", "GitLab", personal, &["https://gitlab.com"]),
        listed("gl2", "GitLab", ("v2", "Work"), &["https://gitlab.com"]),
    ]);
    std::fs::write(directory.join("items.json"), items.to_string())?;
    for id in ["ap1", "ml1", "gl1", "gl2"] {
        std::fs::write(
            directory.join(format!("item-{id}.json")),
            opened(id, false).to_string(),
        )?;
    }
    std::fs::write(
        directory.join("item-gh1.json"),
        opened("gh1", true).to_string(),
    )?;

    let log = directory.join("reads.log");
    let program = directory.join("op");
    std::fs::write(
        &program,
        format!(
            "#!/bin/sh\n\
             d='{directory}'\n\
             [ \"$1\" = whoami ] && exit 0\n\
             echo \"$3\" >> '{log}'\n\
             case \"$1 $2\" in\n\
               'item list') cat \"$d/items.json\" ;;\n\
               'item get') cat \"$d/item-$3.json\" ;;\n\
               'read --no-newline') case \"$3\" in\n\
                   {GITHUB_PASSWORD}|op://v1/ap1/password) printf '{VALUE}' ;;\n\
                   {GITHUB_ONE_TIME}) printf '%s' 'otpauth://totp/GitHub:me?secret={TOTP_SECRET}&issuer=GitHub' ;;\n\
                   op://v1/ml1/password) printf 'first-line\\nsecond-line' ;;\n\
                   op://v2/gl2/password) printf '{WORK_GITLAB}' ;;\n\
                   *) echo \"[ERROR] could not read secret '$3': no item matched\" >&2; exit 1 ;;\n\
                 esac ;;\n\
               *) exit 2 ;;\n\
             esac\n",
            directory = directory.display(),
            log = log.display(),
        ),
    )?;
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))?;

    Ok((program, log))
}

/// How many times the fake `op` was called with `third` as its third
/// argument
fn calls(log: &PathBuf, third: &str) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == third)
        .count()
}

/// A harness with a `logins` server, its owner at the Mac
async fn logins_harness(
    mac: &Arc<FakeMac>,
) -> Result<Option<(Harness, PathBuf)>, Box<dyn std::error::Error>> {
    let (op, log) = logins_op()?;
    let extra = format!(
        "[secrets]\n\
         op = \"{op}\"\n\n\
         [servers.logins]\n\
         builtin = \"logins\"\n\
         policy = \"ask\"\n\
         tools.fill.grant = \"per_call\"\n",
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

/// The text of a refused fill
fn refusal(answer: &Value) -> &str {
    answer["result"].as_str().unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_login_saved_for_a_site_is_typed_there_and_never_returned() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some((harness, log)) = logins_harness(&mac).await? else {
        return Ok(());
    };

    // the wrong field is refused before the owner or 1Password is asked
    mac.set_focused(field(FieldKind::Text, "https://github.com/login"));
    let refused = harness.execute_json(FILL).await?;
    assert!(
        refusal(&refused).contains("not a password field"),
        "{refused}"
    );
    assert_eq!(calls(&log, "--categories"), 0);
    assert_eq!(prompts(&mac), Vec::<String>::new());

    // the owner sees which login goes where
    mac.set_focused(field(FieldKind::Secure, "https://github.com/session"));
    let filled = harness.execute_json(FILL).await?;
    assert_eq!(
        filled["result"],
        json!({"field": "password", "host": "github.com", "item": "GitHub (Personal)"}),
        "{filled}"
    );
    assert_eq!(mac.typed(), VALUE);
    assert!(!filled.to_string().contains(VALUE), "{filled}");
    assert!(!filled.to_string().contains("never-copied"), "{filled}");
    assert_eq!(calls(&log, GITHUB_PASSWORD), 1);
    assert!(
        prompts(&mac).first().is_some_and(|shown| shown.starts_with(
            "touch_id approve logins.fill once: password into github.com in Safari from GitHub \
             (Personal), asked by"
        )),
        "{:?}",
        mac.shown()
    );

    // a look-alike host finds no login, and the owner is not asked
    mac.set_focused(field(
        FieldKind::Secure,
        "https://github.com.evil.example/login",
    ));
    let phished = harness.execute_json(FILL).await?;
    assert!(
        refusal(&phished).contains("no 1Password login is saved for evil.example"),
        "{phished}"
    );
    assert_eq!(prompts(&mac).len(), 1);

    // a sign-in frame on another host of the item's site, inside a page of
    // that site too, as Apple's is
    mac.set_focused(FocusedField {
        pages: vec![
            "https://idmsa.apple.com/appleauth/auth/signin".to_owned(),
            "https://developer.apple.com/account".to_owned(),
        ],
        ..field(FieldKind::Secure, "https://idmsa.apple.com/")
    });
    let apple = harness.execute_json(FILL).await?;
    assert_eq!(apple["result"]["host"], "idmsa.apple.com", "{apple}");
    assert_eq!(apple["result"]["item"], "Apple ID (Personal)", "{apple}");
    // but not inside a page of another site
    mac.set_focused(FocusedField {
        pages: vec![
            "https://idmsa.apple.com/appleauth/auth/signin".to_owned(),
            "https://evil.example/".to_owned(),
        ],
        ..field(FieldKind::Secure, "https://idmsa.apple.com/")
    });
    let framed = harness.execute_json(FILL).await?;
    assert!(
        refusal(&framed).contains("no 1Password login is saved"),
        "{framed}"
    );

    // a line break would press Return on the page, so none of it is typed
    mac.set_focused(field(FieldKind::Secure, "https://multiline.example/login"));
    let multiline = harness.execute_json(FILL).await?;
    assert!(
        refusal(&multiline).contains("control character"),
        "{multiline}"
    );
    assert!(
        !multiline.to_string().contains("second-line"),
        "{multiline}"
    );
    assert_eq!(mac.typed(), format!("{VALUE}{VALUE}"));

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_site_with_several_logins_or_none_needs_the_item_named() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some((harness, log)) = logins_harness(&mac).await? else {
        return Ok(());
    };

    // the agent learns which, and nothing is typed or asked
    mac.set_focused(field(FieldKind::Secure, "https://gitlab.com/users/sign_in"));
    let several = harness.execute_json(FILL).await?;
    assert!(
        refusal(&several).contains(
            "2 1Password logins are saved for gitlab.com; pass the one to use as `item`: \
             op://Personal/GitLab, op://Work/GitLab"
        ),
        "{several}"
    );
    assert_eq!(prompts(&mac), Vec::<String>::new());

    let work = harness.execute_json(&fill_item("op://Work/GitLab")).await?;
    assert_eq!(work["result"]["item"], "GitLab (Work)", "{work}");
    assert_eq!(mac.typed(), WORK_GITLAB);
    assert!(
        prompts(&mac).first().is_some_and(|shown| shown
            .contains("password into gitlab.com in Safari from GitLab (Work), asked by")),
        "{:?}",
        mac.shown()
    );

    // a site no item is saved for takes one only with the owner warned
    mac.set_focused(field(FieldKind::Secure, "https://login.newsite.example/"));
    let none = harness.execute_json(FILL).await?;
    assert!(
        refusal(&none).contains("no 1Password login is saved for newsite.example"),
        "{none}"
    );
    assert_eq!(prompts(&mac).len(), 1);
    let chosen = harness
        .execute_json(&fill_item("op://Personal/GitHub"))
        .await?;
    assert_eq!(
        chosen["result"]["host"], "login.newsite.example",
        "{chosen}"
    );
    assert!(
        prompts(&mac).get(1).is_some_and(|shown| shown.contains(
            "password into login.newsite.example in Safari from GitHub (Personal); this item is \
             NOT saved for newsite.example"
        )),
        "{:?}",
        mac.shown()
    );
    assert_eq!(calls(&log, GITHUB_PASSWORD), 1);

    let missing = harness
        .execute_json(&fill_item("op://Personal/Nothing"))
        .await?;
    assert!(
        refusal(&missing).contains("no Login item op://Personal/Nothing"),
        "{missing}"
    );

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
        assert!(refusal(&refused).contains(expected), "{refused}");
    }
    assert_eq!(calls(&log, "--categories"), 0);
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
            "password into github.com in Chrome from GitHub (Personal); could not confirm that \
             Chrome blocks JavaScript from Apple Events"
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

    // both hosts are the login's site, but the owner approved only the first
    mac.set_focused(field(FieldKind::Secure, "https://github.com/login"));
    mac.set_focus_on_prompt(field(FieldKind::Secure, "https://gist.github.com/login"));
    let moved = harness.execute_json(FILL).await?;
    assert!(
        refusal(&moved)
            .contains("now on gist.github.com, but the owner approved filling on github.com"),
        "{moved}"
    );
    assert_eq!(calls(&log, GITHUB_PASSWORD), 0);
    assert_eq!(mac.typed(), "");

    // an item the owner took for a page it is not saved for still binds
    // that page
    mac.set_focused(field(FieldKind::Secure, "https://newsite.example/"));
    mac.set_focus_on_prompt(field(FieldKind::Secure, "https://evil.example/"));
    let moved = harness
        .execute_json(&fill_item("op://Personal/GitHub"))
        .await?;
    assert!(
        refusal(&moved)
            .contains("now on evil.example, but the owner approved filling on newsite.example"),
        "{moved}"
    );

    // the same host, but in another browser, or in one whose setting could
    // no longer be read, is not what the owner was shown either
    for (moved_to, why) in [
        (
            FocusedField {
                browser: Some("Chrome".to_owned()),
                ..field(FieldKind::Secure, "https://github.com/login")
            },
            "now in Chrome, not as the owner approved in Safari",
        ),
        (
            FocusedField {
                exposure: Exposure {
                    apple_events_javascript: Setting::Unknown,
                    ..Exposure::default()
                },
                ..field(FieldKind::Secure, "https://github.com/login")
            },
            "Safari changed since the owner approved: could not confirm",
        ),
    ] {
        mac.set_focused(field(FieldKind::Secure, "https://github.com/login"));
        mac.set_focus_on_prompt(moved_to);
        let moved = harness.execute_json(FILL).await?;
        assert!(refusal(&moved).contains(why), "{moved}");
    }
    assert_eq!(calls(&log, GITHUB_PASSWORD), 0);
    assert_eq!(mac.typed(), "");

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_one_time_code_is_typed_and_its_seed_never_returned() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some((harness, log)) = logins_harness(&mac).await? else {
        return Ok(());
    };
    let totp = Totp::parse(TOTP_SECRET)?;
    let now = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    };
    let code = FILL.replace("\"password\"", "\"one_time_code\"");

    // a code goes into a text field, not the password field
    mac.set_focused(field(FieldKind::Secure, "https://github.com/session"));
    let refused = harness.execute_json(&code).await?;
    assert!(
        refusal(&refused).contains("not a one-line text field"),
        "{refused}"
    );

    // an item with no one-time password says so before the owner is asked
    mac.set_focused(field(FieldKind::Text, "https://appleid.apple.com/"));
    let none = harness.execute_json(&code).await?;
    assert!(
        refusal(&none).contains("Apple ID (Personal) has no one-time code"),
        "{none}"
    );
    assert_eq!(prompts(&mac), Vec::<String>::new());

    mac.set_focused(field(
        FieldKind::Text,
        "https://github.com/sessions/two-factor",
    ));
    let before = totp.at(now());
    let filled = harness.execute_json(&code).await?;
    let after = totp.at(now());
    assert_eq!(
        filled["result"],
        json!({"field": "one_time_code", "host": "github.com", "item": "GitHub (Personal)"}),
        "{filled}"
    );
    // the code is the seed's, for the time it was typed
    let typed = mac.typed();
    assert!(
        typed == before || typed == after,
        "{typed} not {before} or {after}"
    );
    assert!(!filled.to_string().contains(&typed), "{filled}");
    assert!(!filled.to_string().contains(TOTP_SECRET), "{filled}");
    assert_eq!(calls(&log, GITHUB_ONE_TIME), 1);
    assert!(
        prompts(&mac).first().is_some_and(|shown| shown
            .contains("one-time code into github.com in Safari from GitHub (Personal)")),
        "{:?}",
        mac.shown()
    );

    harness.stop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_owner_away_and_no_phone_a_page_finds_no_login() -> TestResult {
    let mac = Arc::new(FakeMac::default());
    let Some((harness, log)) = logins_harness(&mac).await? else {
        return Ok(());
    };
    mac.set_present(false);

    mac.set_focused(field(FieldKind::Secure, "https://github.com/login"));
    let away = harness.execute_json(FILL).await?;
    assert!(
        refusal(&away).contains("no phone is paired to pick the login on"),
        "{away}"
    );
    // 1Password on an unattended Mac is not searched
    assert_eq!(calls(&log, "--categories"), 0);

    harness.stop().await
}
