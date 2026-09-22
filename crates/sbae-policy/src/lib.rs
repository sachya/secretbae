//! Authentication and authorization.
//!
//! Two independent questions, kept in separate modules because conflating them is how
//! authorization bugs happen:
//!
//! * [`token`] -- who is calling? Token validity, expiry, revocation, and the `SO_PEERCRED`
//!   uid binding that makes a leaked token useless to another local user.
//! * [`policy`] -- may they do this? Path globs, capabilities, and deny rules.
//!
//! Nothing here performs I/O or touches the database, so every rule is decided by a pure
//! function that a test can drive directly.

#![forbid(unsafe_code)]

pub mod glob;
pub mod policy;
pub mod token;

mod error;

pub use error::{PolicyError, Result};
pub use policy::{evaluate, AccessRequest, Decision, DenyRule, PathPattern, Policy, Rule};
pub use token::{
    authenticate, issue, AuthFailure, IssuedToken, LookupPrefix, PeerCredentials, PresentedToken,
    TokenHash, TokenId, TokenRecord, TokenSecret,
};
