//! The secretbae daemon.
//!
//! Startup order is the security design, and is fixed in [`startup`]:
//!
//! 1. Disable core dumps and lock memory -- before any key material exists in the process.
//! 2. Read the keyfile and unseal the master key, while still root.
//! 3. Bind the socket and hand it to the service account, while still root.
//! 4. Drop to that account irreversibly, and verify the drop took effect.
//! 5. Only then start serving.
//!
//! Steps 1 to 3 are the only ones that need privilege, and none of them run again afterwards.

#![cfg(unix)]
#![deny(unsafe_code)]

pub mod auth;
pub mod config;
pub mod keyfile;
pub mod maintenance;
pub mod privdrop;
pub mod routes;
pub mod server;
pub mod startup;
pub mod state;

mod error;

pub use config::Config;
pub use error::{DaemonError, Result};
pub use state::{DaemonState, SharedState};
