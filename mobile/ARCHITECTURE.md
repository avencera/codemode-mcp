# Companion core

The Rust core of the iPhone companion app (`companion-core`). It pairs with a codemode-mcp gateway, holds the
connection to it, and runs each read the gateway sends from arrival to answer. The SwiftUI app in `ios/` draws
the state and does what only iOS can: the Keychain, the Secure Enclave, Face ID and push. How to use the app is
in [docs/operations.md](../docs/operations.md#approve-from-an-iphone).

## Layout

| File | What it holds |
| --- | --- |
| `ffi.rs` | Everything Swift sees: `FfiApp`, the state records, `AppAction`, `Update`, and the `Reconciler` and `Platform` callback traits |
| `app.rs` | The app actor: supervisor of the others and the only writer of `AppState` |
| `connection.rs` | The connection actor: owns the iroh endpoint and the link to the gateway |
| `request.rs` | One request actor per read |
| `pairing.rs` | Scan-to-pair, as one spawned task |
| `record.rs` | The pairing record and iroh key, kept in the Keychain through `Platform` |
| `net.rs` | Binding the endpoint, and one JSON request and answer per stream |

The wire types are in `crates/companion-wire`, shared with the gateway, so the two sides cannot drift.

## State flow

Swift creates one `FfiApp` with its `Platform`, then calls `listen_for_updates` with a `Reconciler`. From then on:

1. The UI calls `dispatch(AppAction)`. The action becomes a message to the app actor; `dispatch` never blocks.
2. The app actor changes `AppState` and sends each change as an `Update` (gateway, connection, reads or
   pairing). Updates go through a channel to one thread that calls `reconcile`, so Swift sees them in order and
   never on a tokio thread.
3. Swift's `AppManager` applies the update to its `@Observable` copy on the main thread. It holds the reconciler
   through a `WeakReconciler`, so the core does not keep the manager alive. `state()` reads the whole state, for
   start-up.

## Actors

```
App (supervisor)
├── Connection          one while paired
└── Request × n         one per read the gateway has sent
```

- **App** takes UI actions and its children's reports. Slow work (pairing, unpairing, Keychain writes) runs in a
  spawned task that reports back as a message, so the mailbox keeps moving. It allows one Face ID prompt at a
  time: Approve is ignored while another read is approving. The UI shows the oldest read still open, or the last
  finished one until it is dismissed.
- **Connection** dials the gateway on the mobile ALPN with the phone's iroh key and backs off 1, 2, 4… up to 30
  seconds. Each bi-stream the gateway opens is one read; it hands the read and a responder to the app, which
  starts or updates a request actor. The stream's end tells a withdrawn read (the gateway stopped the stream:
  another source answered or it gave up) from a lost link (the gateway offers the read again after a reconnect).
  The phone dials because iOS does not let a suspended app accept connections; going to the background drops the
  link, and a push or the user brings it back.
- **Request** starts `Waiting` and expires on the gateway's deadline. A reference off the allow list cannot be
  answered until the owner allows it; the app actor then adds it to the list in the Keychain. Approve calls
  `Platform::open_sealed` on a blocking thread; the actor stays free, so an expiry, a withdrawal, Deny or an
  entered value can take the Face ID prompt down through `cancel_open`. A read without a sealed copy can only be
  answered with a value the owner enters; `FfiApp::answer` carries it, apart from `AppAction`, so it never sits in
  a type that derives `Debug`. An answer made while the link is down is sent once the gateway offers the read
  again, unless the read has expired.

A child that fails is reported to the app through supervision: a failed connection actor is restarted after a
second, and a failed request marks its read failed.

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
