//! `tandera` — a standalone CLI client for the Tandera security platform
//! API. This crate has no dependency on the monorepo's Rust workspace; it
//! only ever talks to the Tandera HTTP API over `reqwest`, authenticated
//! with a personal access token (PAT).
//!
//! Split as a library + thin `main.rs` binary specifically so integration
//! tests (`tests/`) can drive `api`/`config`/`commands` directly against a
//! local `TcpListener` stub, without going through the `clap` CLI surface.

pub mod api;
pub mod capture;
pub mod clipboard;
pub mod commands;
pub mod config;
pub mod gates;
pub mod logbook;
pub mod models;
pub mod repl;
pub mod status;
pub(crate) mod util;
