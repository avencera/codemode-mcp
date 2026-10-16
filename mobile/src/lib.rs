//! The Rust core of the codemode-mcp iPhone companion
//!
//! The phone answers its gateway's `{{ op://… }}` reads: the gateway wakes it
//! with a push, the phone dials back over iroh, and the owner approves each
//! read with Face ID, which opens a copy of the value the gateway sealed to
//! the phone's Secure Enclave key. SwiftUI renders [`ffi::AppState`] and
//! sends [`ffi::AppAction`]s; everything else happens here, in ractor
//! actors. See `ARCHITECTURE.md` beside this crate

mod app;
mod connection;
pub mod ffi;
mod net;
mod pairing;
mod record;
mod request;

uniffi::setup_scaffolding!();
