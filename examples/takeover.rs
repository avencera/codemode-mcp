//! Drives a takeover of an agent-browser session from the terminal, as the
//! phone would, without the phone or the iroh link
//!
//! ```text
//! cargo run --example takeover -- SESSION [FRAMES_DIR]
//! ```
//!
//! Each screencast image is acknowledged and the latest saved as
//! `FRAMES_DIR/latest.jpg`; page and focus changes are printed. Commands on
//! stdin, one per line, with points as fractions of the image:
//!
//! ```text
//! tap X Y | hold X Y | scroll DY | key enter|tab|backtab|backspace|escape
//! back | text WORDS | resize W H | done | cancel
//! ```
//!
//! `text` sends what follows as typed text, so use it only with test values

use std::{path::PathBuf, sync::Arc};

use codemode_mcp::{
    browser::{
        page::{AgentBrowser, SessionName},
        takeover::{self, Context},
    },
    secrets::Redactor,
};
use companion_wire::takeover::{
    GatewayFrame, GatewayMessage, Key, PhoneMessage, Point, Secret, Viewport,
};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::mpsc,
};

const PHONE: Viewport = Viewport {
    width: 390,
    height: 844,
    scale: 2.0,
};

async fn inner_width(page: &codemode_mcp::browser::page::Page) -> String {
    page.session()
        .call(
            "Runtime.evaluate",
            json!({ "expression": "`${innerWidth}x${innerHeight}`", "returnByValue": true }),
        )
        .await
        .map(|answer| answer["result"]["value"].to_string())
        .unwrap_or_else(|error| error.to_string())
}

fn point(words: &[&str]) -> Option<Point> {
    let x = words.first()?.parse().ok()?;
    let y = words.get(1)?.parse().ok()?;

    Some(Point { x, y })
}

fn command(line: &str, seq: u32) -> Option<PhoneMessage> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let (verb, rest) = words.split_first()?;
    let message = match *verb {
        "tap" => PhoneMessage::Tap {
            at: point(rest)?,
            seq,
        },
        "hold" => PhoneMessage::LongPress {
            at: point(rest)?,
            seq,
        },
        "scroll" => PhoneMessage::Scroll {
            at: Point { x: 0.5, y: 0.5 },
            dx: 0.0,
            dy: rest.first()?.parse().ok()?,
            seq,
        },
        "key" => PhoneMessage::Key {
            key: match *rest.first()? {
                "enter" => Key::Enter,
                "tab" => Key::Tab,
                "backtab" => Key::ShiftTab,
                "backspace" => Key::Backspace,
                "escape" => Key::Escape,
                _ => return None,
            },
        },
        "back" => PhoneMessage::Back,
        "text" => PhoneMessage::Text {
            text: Secret::new(line.trim_start().strip_prefix("text")?.trim().to_owned()),
        },
        "resize" => PhoneMessage::Resize {
            viewport: Viewport {
                width: rest.first()?.parse().ok()?,
                height: rest.get(1)?.parse().ok()?,
                scale: 2.0,
            },
        },
        "done" => PhoneMessage::Done,
        "cancel" => PhoneMessage::Cancel,
        _ => return None,
    };

    Some(message)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let session = SessionName::parse(&args.next().ok_or("usage: takeover SESSION [DIR]")?)?;
    let frames = PathBuf::from(
        args.next()
            .unwrap_or_else(|| "_scratch/takeover".to_owned()),
    );
    std::fs::create_dir_all(&frames)?;

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let agent_browser = AgentBrowser::find(home.as_deref());
    let page = agent_browser.open(&session).await?;
    let probe = agent_browser.open(&session).await?;
    println!("viewport before: {}", inner_width(&probe).await);

    let (to_engine, input) = mpsc::channel(64);
    let (output, mut from_engine) = mpsc::channel(8);
    let context = Context {
        offers: Box::new(|_| Vec::new()),
        handoff_over: None,
        redactor: Arc::new(Redactor::default()),
    };
    let engine = tokio::spawn(takeover::run(page, PHONE, input, output, context));

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut seq = 0;
    let mut images = 0_u64;
    loop {
        tokio::select! {
            frame = from_engine.recv() => match frame {
                Some(GatewayFrame::Screen(screen)) => {
                    seq = screen.header.seq;
                    images += 1;
                    std::fs::write(frames.join("latest.jpg"), &screen.jpeg)?;
                    if images == 1 || images.is_multiple_of(20) {
                        println!(
                            "image {images}: seq {seq}, {}x{}, {} bytes",
                            screen.header.width,
                            screen.header.height,
                            screen.jpeg.len()
                        );
                    }
                    if to_engine.send(PhoneMessage::Ack { seq }).await.is_err() {
                        break;
                    }
                }
                Some(GatewayFrame::Message(GatewayMessage::Page { url, title, focus, offers })) => {
                    println!("page: {url} ({title}); focus {focus:?}; {} offers", offers.len());
                }
                Some(GatewayFrame::Message(message)) => println!("{message:?}"),
                None => break,
            },
            line = lines.next_line() => {
                let Some(line) = line? else {
                    let _ = to_engine.send(PhoneMessage::Cancel).await;
                    continue;
                };
                match command(&line, seq) {
                    Some(message) => {
                        if to_engine.send(message).await.is_err() {
                            break;
                        }
                    }
                    None => println!("not understood: {line}"),
                }
            }
        }
    }

    let outcome = engine.await?;
    println!("outcome: {outcome:?} after {images} images");
    println!("viewport after: {}", inner_width(&probe).await);

    Ok(())
}
