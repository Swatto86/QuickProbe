//! Command modules — extracted from main.rs for separation of concerns.
//!
//! Each submodule groups related Tauri IPC commands and their private helpers.
//! Shared types and infrastructure live in `types`, `helpers`, and `state`.

pub(crate) mod helpers;
pub(crate) mod state;
pub(crate) mod types;

pub(crate) mod auth;
pub(crate) mod backup;
pub(crate) mod export;
pub(crate) mod health;
pub(crate) mod hosts;
pub(crate) mod launcher;
pub(crate) mod ldap;
pub(crate) mod remote;
pub(crate) mod services;
pub(crate) mod settings_cmds;
pub(crate) mod system;

// Re-exports are used by #[cfg(test)] in main.rs via `use commands::*;`
pub(crate) use helpers::*;
#[allow(unused_imports)]
pub(crate) use state::*;
#[allow(unused_imports)]
pub(crate) use types::*;

pub(crate) use auth::*;
pub(crate) use backup::*;
pub(crate) use export::*;
pub(crate) use health::*;
pub(crate) use hosts::*;
pub(crate) use launcher::*;
pub(crate) use ldap::*;
pub(crate) use remote::*;
pub(crate) use services::*;
pub(crate) use settings_cmds::*;
pub(crate) use system::*;
