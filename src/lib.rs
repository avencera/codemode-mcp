//! Code Mode gateway: one MCP endpoint that fronts many upstream MCP servers
//! with search, describe and script execution

pub mod app;
pub mod budget;
pub mod catalog;
pub mod config;
pub mod convert;
pub mod executions;
pub mod executor;
pub mod gateway;
mod guidance;
pub mod host;
pub mod policy;
pub mod search;
pub mod server;
pub mod stubs;
pub mod upstream;
