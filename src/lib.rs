//! Code Mode gateway: one MCP endpoint that fronts many upstream MCP servers
//! with search, describe and script execution

pub mod adapters;
pub mod admin;
pub mod app;
pub mod approvals;
pub mod budget;
pub mod catalog;
pub mod config;
pub mod convert;
pub mod executions;
pub mod executor;
pub mod gateway;
mod guidance;
pub mod host;
pub mod notify;
pub mod oauth;
pub mod passkeys;
pub mod policy;
pub mod search;
pub mod server;
pub mod service;
pub mod snapshot;
pub mod store;
pub mod stubs;
pub mod upstream;
pub mod usage;
pub mod web;
