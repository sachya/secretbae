//! Shared domain and wire types.
//!
//! Every value that crosses a crate or process boundary is validated here, once, at
//! construction. Downstream layers receive types that cannot be malformed, so storage,
//! policy matching and audit contain no defensive re-parsing.

#![forbid(unsafe_code)]

pub mod api;

mod capability;
mod error;
mod path;
mod tag;
mod version;

pub use capability::Capability;
pub use error::ProtoError;
pub use path::{SecretPath, MAX_PATH_LEN, MAX_SEGMENTS, MAX_SEGMENT_LEN};
pub use tag::{Tag, TagSelector, MAX_TAG_PART_LEN};
pub use version::{Version, VersionState};
