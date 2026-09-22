//! Token issuance and authentication.
//!
//! A token is `sbae_<prefix>_<secret>`, where both halves are independent random values in
//! unpadded base32. The prefix is an indexed lookup handle and is safe to log; the secret is
//! never stored, only its SHA-256.
//!
//! The prefix is generated separately rather than derived from the secret on purpose: a
//! derived prefix would publish part of the secret every time the prefix appeared in an
//! audit line.

use core::fmt;

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PolicyError;

const TOKEN_PREFIX: &str = "sbae_";
const PREFIX_BYTES: usize = 5;
const SECRET_BYTES: usize = 32;
/// base32 of 5 bytes.
const PREFIX_CHARS: usize = 8;
/// base32 of 32 bytes.
const SECRET_CHARS: usize = 52;

/// Primary key of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TokenId(Uuid);

impl TokenId {
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    #[must_use]
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// The public, indexed half of a token. Safe to record in an audit entry.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LookupPrefix(String);

impl LookupPrefix {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(raw: &str) -> Result<Self, PolicyError> {
        if raw.len() != PREFIX_CHARS || BASE32_NOPAD.decode(raw.as_bytes()).is_err() {
            return Err(PolicyError::MalformedToken);
        }
        Ok(Self(raw.to_owned()))
    }
}

impl fmt::Display for LookupPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for LookupPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LookupPrefix({})", self.0)
    }
}

/// SHA-256 of a token's secret half.
///
/// A plain hash rather than a password KDF is correct here: the secret is 256 bits of
/// uniform randomness, so there is no candidate space to grind through and slowing the
/// comparison would only slow the daemon.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, PolicyError> {
        bytes.try_into().map(Self).map_err(|_| PolicyError::MalformedToken)
    }

    fn of(secret: &[u8]) -> Self {
        Self(Sha256::digest(secret).into())
    }

    /// Constant-time comparison, so timing cannot be used to recover a hash byte by byte.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenHash(<redacted>)")
    }
}

/// A freshly minted token, displayed to the operator exactly once.
#[derive(ZeroizeOnDrop)]
pub struct TokenSecret(String);

impl TokenSecret {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenSecret(<redacted>)")
    }
}

/// Everything `token create` produces: the secret to show once, and the two values to store.
pub struct IssuedToken {
    pub id: TokenId,
    pub prefix: LookupPrefix,
    pub hash: TokenHash,
    pub secret: TokenSecret,
}

/// Mint a token. The plaintext exists only in the returned [`TokenSecret`].
pub fn issue() -> Result<IssuedToken, PolicyError> {
    let mut prefix_bytes = [0u8; PREFIX_BYTES];
    let mut secret_bytes = [0u8; SECRET_BYTES];
    getrandom::getrandom(&mut prefix_bytes).map_err(|_| PolicyError::Entropy)?;
    getrandom::getrandom(&mut secret_bytes).map_err(|_| PolicyError::Entropy)?;

    let prefix = LookupPrefix(BASE32_NOPAD.encode(&prefix_bytes));
    let secret = BASE32_NOPAD.encode(&secret_bytes);
    let hash = TokenHash::of(secret.as_bytes());

    let issued = IssuedToken {
        id: TokenId::generate(),
        secret: TokenSecret(format!("{TOKEN_PREFIX}{prefix}_{secret}")),
        prefix,
        hash,
    };

    secret_bytes.zeroize();
    Ok(issued)
}

/// A token as supplied by a client, already split and hashed.
pub struct PresentedToken {
    prefix: LookupPrefix,
    hash: TokenHash,
}

impl PresentedToken {
    /// Split and hash a token string. Never records the secret itself.
    pub fn parse(presented: &str) -> Result<Self, PolicyError> {
        let body = presented.trim().strip_prefix(TOKEN_PREFIX).ok_or(PolicyError::MalformedToken)?;
        let (prefix, secret) = body.split_once('_').ok_or(PolicyError::MalformedToken)?;

        if secret.len() != SECRET_CHARS || BASE32_NOPAD.decode(secret.as_bytes()).is_err() {
            return Err(PolicyError::MalformedToken);
        }

        Ok(Self { prefix: LookupPrefix::parse(prefix)?, hash: TokenHash::of(secret.as_bytes()) })
    }

    /// The handle used to find the stored record.
    #[must_use]
    pub fn prefix(&self) -> &LookupPrefix {
        &self.prefix
    }
}

/// The stored side of a token.
#[derive(Clone, Debug)]
pub struct TokenRecord {
    pub id: TokenId,
    pub prefix: LookupPrefix,
    pub hash: TokenHash,
    pub name: String,
    /// When set, the connecting process must present this uid over `SO_PEERCRED`.
    pub bound_uid: Option<u32>,
    pub expires_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// Real uid, gid and pid of the process on the other end of the Unix socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

/// Why authentication failed.
///
/// The daemon records this in the audit log but never returns it to the caller, which would
/// otherwise reveal whether a given token exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFailure {
    /// No such prefix, or the secret did not match.
    UnknownToken,
    Expired,
    Revoked,
    /// The token is valid but bound to a different local user.
    PeerMismatch { expected: u32, actual: u32 },
}

/// Check a presented token against its stored record and the caller's peer credentials.
///
/// The uid check is what makes a leaked application token useless to any other local
/// account, so it is enforced here rather than left to a caller to remember.
pub fn authenticate(
    record: &TokenRecord,
    presented: &PresentedToken,
    peer: PeerCredentials,
    now: OffsetDateTime,
) -> Result<TokenId, AuthFailure> {
    if !record.hash.matches(&presented.hash) {
        return Err(AuthFailure::UnknownToken);
    }
    if record.revoked_at.is_some_and(|at| at <= now) {
        return Err(AuthFailure::Revoked);
    }
    if record.expires_at.is_some_and(|at| at <= now) {
        return Err(AuthFailure::Expired);
    }
    if let Some(expected) = record.bound_uid {
        if expected != peer.uid {
            return Err(AuthFailure::PeerMismatch { expected, actual: peer.uid });
        }
    }

    Ok(record.id)
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    fn record(issued: &IssuedToken) -> TokenRecord {
        TokenRecord {
            id: issued.id,
            prefix: issued.prefix.clone(),
            hash: issued.hash,
            name: "test".to_owned(),
            bound_uid: None,
            expires_at: None,
            revoked_at: None,
        }
    }

    fn peer(uid: u32) -> PeerCredentials {
        PeerCredentials { uid, gid: uid, pid: 1234 }
    }

    #[test]
    fn an_issued_token_authenticates() {
        let issued = issue().unwrap();
        let presented = PresentedToken::parse(issued.secret.expose()).unwrap();
        assert_eq!(
            authenticate(&record(&issued), &presented, peer(33), OffsetDateTime::now_utc()),
            Ok(issued.id)
        );
    }

    #[test]
    fn issued_tokens_are_shaped_as_documented_and_never_repeat() {
        let a = issue().unwrap();
        let b = issue().unwrap();

        let secret = a.secret.expose();
        assert!(secret.starts_with("sbae_"));
        assert_eq!(secret.len(), TOKEN_PREFIX.len() + PREFIX_CHARS + 1 + SECRET_CHARS);
        assert_ne!(a.secret.expose(), b.secret.expose());
        assert_ne!(a.prefix, b.prefix);
    }

    /// If the prefix were derived from the secret, publishing it in an audit log would leak
    /// part of the secret.
    #[test]
    fn the_prefix_is_not_a_substring_of_the_secret_half() {
        let issued = issue().unwrap();
        let secret_half = issued.secret.expose().rsplit('_').next().unwrap();
        assert!(!secret_half.contains(issued.prefix.as_str()));
    }

    #[test]
    fn a_wrong_secret_with_a_valid_prefix_is_rejected() {
        let issued = issue().unwrap();
        let other = issue().unwrap();

        let forged = format!("sbae_{}_{}", issued.prefix, other.secret.expose().rsplit('_').next().unwrap());
        let presented = PresentedToken::parse(&forged).unwrap();

        assert_eq!(presented.prefix(), &issued.prefix, "the forgery targets the right record");
        assert_eq!(
            authenticate(&record(&issued), &presented, peer(0), OffsetDateTime::now_utc()),
            Err(AuthFailure::UnknownToken)
        );
    }

    #[test]
    fn malformed_tokens_are_rejected_before_any_lookup() {
        for raw in [
            "",
            "sbae_",
            "not-a-token",
            "sbae_SHORT_AAAA",
            "sbae_AAAAAAAA_tooshort",
            "AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(PresentedToken::parse(raw).is_err(), "should reject {raw:?}");
        }
    }

    #[test]
    fn expiry_and_revocation_are_enforced() {
        let issued = issue().unwrap();
        let presented = PresentedToken::parse(issued.secret.expose()).unwrap();
        let now = OffsetDateTime::now_utc();

        let expired = TokenRecord { expires_at: Some(now - Duration::seconds(1)), ..record(&issued) };
        assert_eq!(
            authenticate(&expired, &presented, peer(0), now),
            Err(AuthFailure::Expired)
        );

        let revoked = TokenRecord { revoked_at: Some(now - Duration::seconds(1)), ..record(&issued) };
        assert_eq!(
            authenticate(&revoked, &presented, peer(0), now),
            Err(AuthFailure::Revoked)
        );

        let valid = TokenRecord { expires_at: Some(now + Duration::hours(1)), ..record(&issued) };
        assert!(authenticate(&valid, &presented, peer(0), now).is_ok());
    }

    /// The headline local-hardening property: the token alone is not enough.
    #[test]
    fn a_bound_token_is_useless_to_another_local_user() {
        let issued = issue().unwrap();
        let presented = PresentedToken::parse(issued.secret.expose()).unwrap();
        let bound = TokenRecord { bound_uid: Some(33), ..record(&issued) };
        let now = OffsetDateTime::now_utc();

        assert!(authenticate(&bound, &presented, peer(33), now).is_ok());
        assert_eq!(
            authenticate(&bound, &presented, peer(1000), now),
            Err(AuthFailure::PeerMismatch { expected: 33, actual: 1000 })
        );
    }

    #[test]
    fn debug_never_reveals_a_token_or_its_hash() {
        let issued = issue().unwrap();
        assert_eq!(format!("{:?}", issued.secret), "TokenSecret(<redacted>)");
        assert_eq!(format!("{:?}", issued.hash), "TokenHash(<redacted>)");
        assert!(!format!("{:?}", record(&issued)).contains(issued.secret.expose()));
    }
}
