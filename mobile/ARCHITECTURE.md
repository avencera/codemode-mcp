# Companion core

The Rust core of the iPhone companion app (`companion-core`). It pairs with a codemode-mcp gateway, holds the
connection to it, runs each read the gateway sends from arrival to answer, shows the handoffs agents ask for, and
runs the live takeover of a browser session on the gateway Mac or on a spoke the gateway vouches for. The SwiftUI
app in `ios/` draws
the state and does what only iOS can: the Keychain, the Secure Enclave, Face ID and push. How to use the app is
in [docs/operations.md](../docs/operations.md#approve-from-an-iphone).

## Layout

| File | What it holds |
| --- | --- |
| `ffi.rs` | Everything Swift sees: `FfiApp`, the state records, `AppAction`, `Update`, and the `Reconciler` and `Platform` callback traits |
| `app.rs` | The app actor: supervisor of the others and the only writer of `AppState` |
| `connection.rs` | The connection actor: owns the iroh endpoint and the link to the gateway |
| `request.rs` | One request actor per read |
| `handoff.rs` | The app actor's table of open handoffs and their streams |
| `takeover.rs` | The takeover actor: one live browser session |
| `pairing.rs` | Scan-to-pair, as one spawned task |
| `record.rs` | The pairing record and iroh key, kept in the Keychain through `Platform` |
| `net.rs` | Binding the endpoint, and one JSON request and answer per stream |

The wire types are in `crates/companion-wire`, shared with the gateway, so the two sides cannot drift.

## State flow

Swift creates one `FfiApp` with its `Platform`, then calls `listen_for_updates` with a `Reconciler`. From then on:

1. The UI calls `dispatch(AppAction)`. The action becomes a message to the app actor; `dispatch` never blocks.
2. The app actor changes `AppState` and sends each change as an `Update` (gateway, connection, reads, pairing,
   handoffs or takeover). A takeover's images go the same way as `Update::Screen` but are not kept in `AppState`.
   Updates go through a channel to one thread that calls `reconcile`, so Swift sees them in order and never on a
   tokio thread.
3. Swift's `AppManager` applies the update to its `@Observable` copy on the main thread; it decodes an image on
   the reconcile thread first, and reports it drawn once it is shown. It holds the reconciler
   through a `WeakReconciler`, so the core does not keep the manager alive. `state()` reads the whole state, for
   start-up.

## Actors

```
App (supervisor)
├── Connection          one while paired
├── Request × n         one per read the gateway has sent
└── Takeover            one while the owner has a browser session open
```

- **App** takes UI actions and its children's reports. Slow work (pairing, unpairing, Keychain writes) runs in a
  spawned task that reports back as a message, so the mailbox keeps moving. It allows one Face ID prompt at a
  time: an Approve or program answer made while another read is approving is queued and runs once that prompt
  ends. The UI shows the oldest read still open, or the last finished one until it is dismissed.
- **Connection** dials the gateway on the mobile ALPN with the phone's iroh key and backs off 1, 2, 4… up to 30
  seconds. Each bi-stream the gateway opens is one read; it hands the read and a responder to the app, which
  starts or updates a request actor. The stream's end tells a withdrawn read (the gateway stopped the stream:
  another source answered or it gave up) from a lost link (the gateway offers the read again after a reconnect).
  The phone dials because iOS does not let a suspended app accept connections; going to the background drops the
  link, and a push or the user brings it back.
- **Request** starts `Waiting` and expires on the gateway's deadline. The prompt names the reference, and one
  approval answers it; the phone keeps no allow list, and ignores the references the gateway names at pairing.
  The seal's `info` binds the reference, so the value Face ID opens is the one the prompt shows. Approve calls
  `Platform::open_sealed` on a blocking thread; the actor stays free, so an expiry, a withdrawal, Deny or an
  entered value can take the Face ID prompt down through `cancel_open`. A read without a sealed copy can only be
  answered with a value the owner enters; `FfiApp::answer` carries it, apart from `AppAction`, so it never sits in
  a type that derives `Debug`. An answer stays with its request until the stream reports it delivered; one made
  while the link is down, or lost with it, is sent once the gateway offers the read again, unless the read has
  expired. Approve asks the request and waits for its reply, so only one Face ID prompt starts at a time. Only
  the owner's Deny (the button, or Deny on the Face ID prompt) answers `Denied`; an interrupted, unmatched or
  unavailable Face ID answers `ReadFailed`. Either takes only this phone out of the gateway's race, so another
  device can still approve, and the gateway reports the read as denied when nobody approves and a device denied.
- **Program reads** ride the same request actor. A `PhoneProgramRequest` lists several items for a program on the
  gateway Mac: each a reference, with or without a sealed copy, or only a description. Approve opens every sealed
  item with one Face ID through `Platform::open_sealed_batch`, and `FfiApp::answer_program` carries the values
  entered for the other items, by index: `EnteredValue::Text`, or `EnteredValue::File` for a file the owner
  shared from 1Password through the app's share extension, at most `max_file_bytes()`. The answer is
  `CompanionResponse::Values` in item order, a file's bytes going as `{"base64": ...}` unless they are UTF-8. The prompt
  shows the program's destination, cleaned to one line, and its keep (at most an hour), which Face ID's reason
  names too. A program read with `sign_in` fills a login in the gateway's browser: the prompt is titled with the
  site and account (`github.com · praveenperera`) and the browser session, and each item carries its `LoginField`,
  so the app gives each entered value the matching AutoFill (username, password, or a one-time code on the number
  pad) and lays the entered fields out together, letting AutoFill fill a username and password at once.
- **Handoffs** are offered on a gateway-opened stream like reads, as `{"handoff": {...}}`, when an agent needs the
  owner for a browser step it cannot do (a passkey, a captcha). They need no actor: the app keeps them in
  `handoff.rs`, keyed by id, so one offered again after a reconnect replaces its stream and stays one card. Cancel
  answers `HandoffAnswer::Cancelled` on the stream, kept until it is delivered as a read's answer is. Take over
  opens a takeover with the handoff's id; its Done or Cancel ends the handoff on the takeover's connection, after
  which the gateway stops the handoff's stream. A stopped stream marks a handoff the owner did not answer here as
  over, and its deadline (at most two hours) as expired. A handoff for a spoke's session carries `machine`, the
  spoke's name, endpoint id and addresses, which the app keeps with the other listed machines; it is trusted as
  the gateway's word, since it arrives on the gateway's authenticated link. Its card's `host` is that machine.
- **Takeover** dials the gateway on `TAKEOVER_ALPN` from the connection actor's endpoint (the app lends it through
  `AppMsg::Endpoint`), so the gateway sees the paired phone's key. A session on a spoke (`BrowserHost::Machine`)
  is dialed the same way, at the endpoint id, relay and addresses the gateway listed for that machine; the spoke
  admits only the phones the gateway tells it are paired, and closes a takeover with `not paired` once the
  gateway stops vouching for its phone. An `OpenTakeover` naming a machine the app has not
  listed yet, such as from a link, shows Connecting, lists the gateway's sessions again and opens once the
  machine is known (`waiting_open`, which also keeps the first `Resize`), or ends as failed if the gateway no
  longer lists it. It waits for the app's first `Resize`, which
  gives the image area in points and its scale (at most 2), then opens one stream and sends `Open { session,
  handoff, viewport }`. Frames are read and written in spawned tasks that report back as messages. Each `Page`
  updates `AppState.takeover` (address, focus, fill offers without their sealed bytes); each `Screen` goes to
  Swift as `Update::Screen`, outside `AppState`, and is acknowledged with `Ack` only when Swift reports it drawn
  (`TakeoverInput::Drawn`), so the gateway sends images no faster than the phone shows them. Taps, long presses
  and scrolls name the image they were made on and give points as fractions of it. The address bar sends
  `TakeoverInput::Go` with an `https` address, which the gateway checks again and loads with `Page.navigate`. Typed text and fills go through
  `FfiApp::takeover_text` and `FfiApp::takeover_fill`, apart from `TakeoverInput`, as `companion_wire::takeover::
  Secret`, which never shows in `Debug`; text longer than the wire's limit goes in pieces. A long press in a
  focused text field offers Paste, which sends the clipboard as text; a whole value AutoFill sets is a fill of the
  field the keyboard was set up for, not of the page's focus as last heard, which may lag. Fill from 1Password without an
  offer opens a sheet with one visible field of the focused kind, for AutoFill, and sends its value as `Fill`.
  Fill from an offer
  opens its sealed copy with `Platform::open_sealed`, the seal's `info` binding the gateway and the offer's
  reference (the gateway's id on a spoke's page too, since only the gateway reads 1Password and seals), and sends the value as `Fill`.
  Its prompt names where the value goes, `OpenDestination::Page` with the session and its machine, so a fill on
  a spoke names the spoke, not the gateway that sealed it; a read's prompt names the gateway
  (`OpenDestination::Gateway`).
  For a code offer the core sends the current code, computed from the opened seed with `companion_wire::totp`,
  never the seed, so a spoke never holds it. A link that drops while the app is in the foreground is dialed again
  with the connection's backoff and opens anew; going to the background hangs up, and Done or Cancel made while
  the link is down goes right after the next `Open`. `Ended` stops the actor: Done and Cancel close the screen and
  remove their handoff's card, any other reason stays on screen until the owner closes it. Leaving
  (`CloseTakeover`) hangs up without ending anything, so the handoff can be taken over again.
- **Sessions** are listed on a takeover link of their own: `RefreshSessions` dials `TAKEOVER_ALPN` in a spawned
  task, sends `PhoneMessage::Sessions` and reads the one answer into `AppState.sessions` (running sessions
  and saved profiles), which keeps the last listing while the next loads. The gateway's answer also names
  `machines`, the spokes with a browser of their own; each gets a `MachineSessions` section, listed on a link
  of its own to that spoke, all at once, with an 8 s dial timeout, so one spoke that is down shows
  `SessionsStatus::Unreachable` while the rest list. Each gateway listing starts a new round, and a machine's
  answer from an older round is dropped. Session actions carry a `SessionHost`, the gateway or a machine by
  name, and go to that machine. `StartSession` opens a takeover whose
  `Open` carries `start`, the `https` address the gateway starts the session at; the takeover actor drops it
  once a link gets through, so a redial takes the session over as it is. `CloseSession` sends
  `PhoneMessage::CloseSession` on a listing link instead, leaving any takeover of that session first, and
  reads the list the gateway answers after the close; `RemoveSession` sends `PhoneMessage::RemoveSession`
  the same way.

A child that fails is reported to the app through supervision: a failed connection actor is restarted after a
second, a failed request marks its read failed, and a failed takeover shows as ended. A connection actor that cannot start, say because its endpoint
does not bind or the Keychain is still locked after a restart, is tried again after a second the same way. A link
that drops within ten seconds of opening counts as a failed dial, so a gateway that refuses the phone is redialed
with the same backoff.

## Values

The gateway sends each read with the value, when it has one, HPKE-sealed to the phone's Secure Enclave key (P-256, HKDF-SHA256,
AES-256-GCM; the info binds the gateway's id and the reference). The core never holds the private key: Swift opens
the value inside `open_sealed`, after Face ID, and returns the plaintext, which goes straight into the answer.
`Secret` wraps it with a redacting `Debug`, and nothing logs it. An answer over 64 KiB is refused, matching the
gateway's limit.

## Platform

`Platform` is the only way the core reaches iOS, and Swift implements it in `SystemPlatform`. The calls block;
the core makes them off the async runtime. Tests implement it in memory with a software HPKE key and a scripted
Face ID (`tests/core.rs`), and run the core against an in-process gateway.

## Building

`just ios-core` builds the static library for the device, generates the Swift bindings with `crates/uniffi_cli`,
and puts both in the `ios/CompanionCore` Swift package. `just ios-run` also builds and installs the app.
