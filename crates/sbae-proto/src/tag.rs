use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ProtoError;

pub const MAX_TAG_PART_LEN: usize = 64;

/// A `key=value` label on a secret, such as `env=prod`.
///
/// Tags are metadata for organising and querying. They may narrow an authorization rule but
/// never grant one on their own -- see `sbae-policy`, where `require_tags` is only ever
/// applied as a filter on top of a path grant.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Tag {
    key: String,
    value: String,
}

impl Tag {
    pub fn new(key: &str, value: &str) -> Result<Self, ProtoError> {
        validate_part("key", key)?;
        validate_part("value", value)?;
        Ok(Self {
            key: key.to_owned(),
            value: value.to_owned(),
        })
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

fn validate_part(what: &'static str, part: &str) -> Result<(), ProtoError> {
    let reason = if part.is_empty() {
        Some("must not be empty")
    } else if part.len() > MAX_TAG_PART_LEN {
        Some("must be at most 64 characters")
    } else if !part
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.'))
    {
        // Same lowercase rule as paths: `env=Prod` and `env=prod` must not be two different
        // tags that read identically to whoever is auditing a policy.
        Some("must contain only [a-z0-9._-]")
    } else {
        None
    };

    match reason {
        Some(reason) => Err(ProtoError::InvalidTag { what, reason }),
        None => Ok(()),
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({self})")
    }
}

impl FromStr for Tag {
    type Err = ProtoError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (key, value) = raw.split_once('=').ok_or(ProtoError::InvalidTag {
            what: "tag",
            reason: "must be written as key=value",
        })?;
        Self::new(key, value)
    }
}

impl TryFrom<String> for Tag {
    type Error = ProtoError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        raw.parse()
    }
}

impl From<Tag> for String {
    fn from(tag: Tag) -> Self {
        tag.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_value_form() {
        let tag: Tag = "env=prod".parse().unwrap();
        assert_eq!(tag.key(), "env");
        assert_eq!(tag.value(), "prod");
        assert_eq!(tag.to_string(), "env=prod");
    }

    #[test]
    fn rejects_malformed_tags() {
        for raw in [
            "env",
            "=prod",
            "env=",
            "env=PROD",
            "env prod=x",
            "env=pr od",
        ] {
            assert!(raw.parse::<Tag>().is_err(), "should reject {raw:?}");
        }
    }

    /// Must be rejected outright rather than silently truncated to `conn=a`.
    #[test]
    fn rejects_a_second_equals_rather_than_truncating() {
        assert!("conn=a=b".parse::<Tag>().is_err());
    }

    #[test]
    fn serde_round_trip_revalidates() {
        let tag: Tag = "env=prod".parse().unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(serde_json::from_str::<Tag>(&json).unwrap(), tag);
        assert!(serde_json::from_str::<Tag>("\"env\"").is_err());
    }
}

/// What `tag rm` names: either a whole `key=value` pair, or just a key.
///
/// Removing by key alone is the common case -- an operator retiring `env` from a secret knows
/// the key, not necessarily which value is currently attached -- and requiring them to spell
/// out the matching value made a routine operation fail with a message about formatting.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum TagSelector {
    /// Matches every tag with this key, whatever its value.
    Key(String),
    Exact(Tag),
}

impl TagSelector {
    #[must_use]
    pub fn matches(&self, tag: &Tag) -> bool {
        match self {
            Self::Key(key) => tag.key() == key,
            Self::Exact(exact) => exact == tag,
        }
    }

    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Key(key) => key,
            Self::Exact(tag) => tag.key(),
        }
    }
}

impl fmt::Display for TagSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => f.write_str(key),
            Self::Exact(tag) => write!(f, "{tag}"),
        }
    }
}

impl fmt::Debug for TagSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TagSelector({self})")
    }
}

impl FromStr for TagSelector {
    type Err = ProtoError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.contains('=') {
            return raw.parse().map(Self::Exact);
        }
        validate_part("key", raw)?;
        Ok(Self::Key(raw.to_owned()))
    }
}

impl TryFrom<String> for TagSelector {
    type Error = ProtoError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        raw.parse()
    }
}

impl From<TagSelector> for String {
    fn from(selector: TagSelector) -> Self {
        selector.to_string()
    }
}

#[cfg(test)]
mod selector_tests {
    use super::*;

    fn tag(raw: &str) -> Tag {
        raw.parse().unwrap()
    }

    #[test]
    fn a_bare_key_selects_every_value_under_it() {
        let selector: TagSelector = "env".parse().unwrap();
        assert!(selector.matches(&tag("env=prod")));
        assert!(selector.matches(&tag("env=dev")));
        assert!(!selector.matches(&tag("app=billing")));
    }

    #[test]
    fn a_full_pair_selects_only_itself() {
        let selector: TagSelector = "env=prod".parse().unwrap();
        assert!(selector.matches(&tag("env=prod")));
        assert!(!selector.matches(&tag("env=dev")));
    }

    #[test]
    fn both_forms_round_trip_through_their_text() {
        for raw in ["env", "env=prod"] {
            let selector: TagSelector = raw.parse().unwrap();
            assert_eq!(selector.to_string(), raw);
            assert_eq!(
                serde_json::from_str::<TagSelector>(&format!("\"{raw}\"")).unwrap(),
                selector
            );
        }
    }

    #[test]
    fn malformed_selectors_are_still_rejected() {
        for raw in ["", "ENV", "env=", "=prod", "env prod", "env=a=b"] {
            assert!(raw.parse::<TagSelector>().is_err(), "should reject {raw:?}");
        }
    }
}
