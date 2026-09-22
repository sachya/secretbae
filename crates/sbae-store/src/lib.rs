//! Persistence for secretbae.
//!
//! Holds ciphertext and metadata in a single SQLite file. This crate performs no
//! cryptography: it stores whatever `sbae-core` sealed and hands it back unopened, so the
//! master key never reaches the storage layer.

#![forbid(unsafe_code)]

mod error;
mod maintenance;
mod models;
mod schema;
mod secrets;
mod store;
mod tags;
mod tokens;

pub use error::{Result, StoreError};
pub use maintenance::RekeyReport;
pub use models::{
    DeleteMode, ExportedSecret, ExportedVersion, ListFilter, SecretSummary, StoredVersion,
    VersionInfo, VersionSelector, WriteMeta,
};
pub use schema::SCHEMA_VERSION;
pub use secrets::WriteSlot;
pub use store::Store;
pub use tokens::{NewToken, TokenSummary};
