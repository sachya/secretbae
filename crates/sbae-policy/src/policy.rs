//! Policy documents and access decisions.

use std::collections::BTreeSet;

use sbae_proto::{Capability, SecretPath, Tag};
use serde::{Deserialize, Serialize};

use crate::{glob, PolicyError};

/// A validated path glob. Validation happens when a policy is stored, so an unmatchable
/// pattern can never be saved and later mistaken for an effective rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PathPattern(String);

impl PathPattern {
    pub fn new(pattern: &str) -> Result<Self, PolicyError> {
        if glob::is_valid_pattern(pattern) {
            Ok(Self(pattern.to_owned()))
        } else {
            Err(PolicyError::InvalidPattern(pattern.to_owned()))
        }
    }

    #[must_use]
    pub fn matches(&self, path: &SecretPath) -> bool {
        glob::matches(&self.0, path.as_str())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PathPattern {
    type Error = PolicyError;

    fn try_from(pattern: String) -> Result<Self, Self::Error> {
        Self::new(&pattern)
    }
}

impl From<PathPattern> for String {
    fn from(pattern: PathPattern) -> Self {
        pattern.0
    }
}

/// A grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub path: PathPattern,
    pub capabilities: BTreeSet<Capability>,
    /// Additional tags the secret must carry.
    ///
    /// Only ever narrows a grant that the path already made. Tags are mutable metadata, so
    /// letting them widen access would mean anyone who can write a tag can escalate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_tags: Vec<Tag>,
}

/// A prohibition. Overrides every grant, in this policy and in any other attached to the
/// same token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRule {
    pub path: PathPattern,
    /// Absent means every capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<BTreeSet<Capability>>,
}

impl DenyRule {
    fn covers(&self, capability: Capability) -> bool {
        self.capabilities
            .as_ref()
            .is_none_or(|set| set.contains(&capability))
    }
}

/// A named set of grants and prohibitions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<DenyRule>,
}

impl Policy {
    /// Parse a policy document, rejecting unknown fields.
    ///
    /// Strict parsing matters more than convenience here: a typo in a policy must fail
    /// loudly rather than be dropped, leaving a rule the operator believes is in force.
    pub fn from_json(document: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(document).map_err(|source| PolicyError::Malformed(source.to_string()))
    }

    pub fn to_json(&self) -> Result<String, PolicyError> {
        serde_json::to_string_pretty(self)
            .map_err(|source| PolicyError::Malformed(source.to_string()))
    }
}

/// What a caller is trying to do.
pub struct AccessRequest<'a> {
    pub path: &'a SecretPath,
    pub capability: Capability,
    /// The tags currently on the secret, used to evaluate `require_tags`.
    pub tags: &'a [Tag],
}

/// The outcome of evaluating a request.
///
/// Carries the matching rule's pattern on success purely so the audit log can record which
/// grant was used; it is never returned to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow { matched: String },
    Deny,
}

impl Decision {
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }
}

/// Evaluate a request against every policy attached to a token.
///
/// Deny always wins, and is checked across all policies before any grant is considered, so
/// attaching an extra policy can never widen access past another policy's prohibition.
#[must_use]
pub fn evaluate(policies: &[Policy], request: &AccessRequest<'_>) -> Decision {
    let denied = policies
        .iter()
        .flat_map(|policy| &policy.deny)
        .any(|rule| rule.covers(request.capability) && rule.path.matches(request.path));

    if denied {
        return Decision::Deny;
    }

    policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .find(|rule| {
            rule.capabilities.contains(&request.capability)
                && rule.path.matches(request.path)
                && rule
                    .require_tags
                    .iter()
                    .all(|required| request.tags.contains(required))
        })
        .map_or(Decision::Deny, |rule| Decision::Allow {
            matched: rule.path.as_str().to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(raw: &str) -> SecretPath {
        SecretPath::new(raw).unwrap()
    }

    fn tag(raw: &str) -> Tag {
        raw.parse().unwrap()
    }

    fn rule(pattern: &str, capabilities: &[Capability]) -> Rule {
        Rule {
            path: PathPattern::new(pattern).unwrap(),
            capabilities: capabilities.iter().copied().collect(),
            require_tags: Vec::new(),
        }
    }

    fn policy(rules: Vec<Rule>, deny: Vec<DenyRule>) -> Policy {
        Policy {
            name: "test".to_owned(),
            rules,
            deny,
        }
    }

    fn decide(policies: &[Policy], raw: &str, capability: Capability, tags: &[Tag]) -> bool {
        evaluate(
            policies,
            &AccessRequest {
                path: &path(raw),
                capability,
                tags,
            },
        )
        .is_allowed()
    }

    #[test]
    fn a_grant_applies_only_to_its_paths_and_capabilities() {
        let policies = [policy(
            vec![rule("prod/billing/**", &[Capability::Read])],
            vec![],
        )];

        assert!(decide(&policies, "prod/billing/db", Capability::Read, &[]));
        assert!(!decide(
            &policies,
            "prod/billing/db",
            Capability::Write,
            &[]
        ));
        assert!(!decide(&policies, "prod/search/db", Capability::Read, &[]));
    }

    #[test]
    fn nothing_is_granted_by_default() {
        assert!(!decide(&[], "prod/db", Capability::Read, &[]));
        assert!(!decide(
            &[policy(vec![], vec![])],
            "prod/db",
            Capability::Read,
            &[]
        ));
    }

    #[test]
    fn deny_overrides_a_grant_in_the_same_policy() {
        let policies = [policy(
            vec![rule("prod/**", &[Capability::Read])],
            vec![DenyRule {
                path: PathPattern::new("prod/**/admin/**").unwrap(),
                capabilities: None,
            }],
        )];

        assert!(decide(&policies, "prod/billing/db", Capability::Read, &[]));
        assert!(!decide(
            &policies,
            "prod/billing/admin/root",
            Capability::Read,
            &[]
        ));
    }

    /// Attaching a second policy must never be able to defeat the first one's prohibition.
    #[test]
    fn deny_in_one_policy_overrides_a_grant_in_another() {
        let policies = [
            policy(
                vec![],
                vec![DenyRule {
                    path: PathPattern::new("prod/**").unwrap(),
                    capabilities: None,
                }],
            ),
            policy(vec![rule("prod/**", &[Capability::Read])], vec![]),
        ];

        assert!(!decide(&policies, "prod/billing/db", Capability::Read, &[]));
    }

    #[test]
    fn a_deny_may_be_limited_to_specific_capabilities() {
        let policies = [policy(
            vec![rule("prod/**", &[Capability::Read, Capability::Write])],
            vec![DenyRule {
                path: PathPattern::new("prod/**").unwrap(),
                capabilities: Some([Capability::Write].into_iter().collect()),
            }],
        )];

        assert!(decide(&policies, "prod/db", Capability::Read, &[]));
        assert!(!decide(&policies, "prod/db", Capability::Write, &[]));
    }

    #[test]
    fn require_tags_narrows_a_grant_and_never_widens_one() {
        let policies = [policy(
            vec![Rule {
                require_tags: vec![tag("env=prod")],
                ..rule("**", &[Capability::Read])
            }],
            vec![],
        )];

        assert!(decide(
            &policies,
            "prod/db",
            Capability::Read,
            &[tag("env=prod")]
        ));
        assert!(!decide(
            &policies,
            "prod/db",
            Capability::Read,
            &[tag("env=dev")]
        ));
        assert!(
            !decide(&policies, "prod/db", Capability::Read, &[]),
            "a missing tag denies"
        );

        // Carrying the tag is not itself a grant: the path still has to match a rule.
        let scoped = [policy(
            vec![Rule {
                require_tags: vec![tag("env=prod")],
                ..rule("prod/**", &[Capability::Read])
            }],
            vec![],
        )];
        assert!(!decide(
            &scoped,
            "dev/db",
            Capability::Read,
            &[tag("env=prod")]
        ));
    }

    #[test]
    fn all_required_tags_must_be_present() {
        let policies = [policy(
            vec![Rule {
                require_tags: vec![tag("env=prod"), tag("app=billing")],
                ..rule("**", &[Capability::Read])
            }],
            vec![],
        )];

        assert!(decide(
            &policies,
            "a",
            Capability::Read,
            &[tag("env=prod"), tag("app=billing")]
        ));
        assert!(!decide(
            &policies,
            "a",
            Capability::Read,
            &[tag("env=prod")]
        ));
    }

    #[test]
    fn admin_is_not_implied_by_any_other_capability() {
        let policies = [policy(
            vec![rule(
                "**",
                &[
                    Capability::Read,
                    Capability::Write,
                    Capability::Delete,
                    Capability::List,
                ],
            )],
            vec![],
        )];

        assert!(!decide(&policies, "prod/db", Capability::Admin, &[]));
    }

    #[test]
    fn documents_round_trip_and_reject_bad_input() {
        let document = r#"{
            "name": "billing-app",
            "rules": [
                { "path": "prod/billing/**", "capabilities": ["read"], "require_tags": ["env=prod"] }
            ],
            "deny": [ { "path": "prod/**/admin/**" } ]
        }"#;

        let parsed = Policy::from_json(document).unwrap();
        assert_eq!(parsed.name, "billing-app");
        assert_eq!(parsed.rules[0].require_tags, vec![tag("env=prod")]);
        assert_eq!(
            Policy::from_json(&parsed.to_json().unwrap()).unwrap(),
            parsed
        );

        // A typo must fail loudly rather than leave a rule the operator believes is in force.
        assert!(Policy::from_json(
            r#"{"name":"x","rules":[{"path":"prod/**","capabilties":["read"]}]}"#
        )
        .is_err());
        assert!(Policy::from_json(r#"{"name":"x","ruels":[]}"#).is_err());

        assert!(Policy::from_json(
            r#"{"name":"x","rules":[{"path":"prod//db","capabilities":["read"]}]}"#
        )
        .is_err());
        assert!(Policy::from_json(
            r#"{"name":"x","rules":[{"path":"prod/**","capabilities":["reed"]}]}"#
        )
        .is_err());
        assert!(Policy::from_json(r#"{"name":"x","rules":[{"path":"prod/**","capabilities":["read"],"require_tags":["env"]}]}"#).is_err());
    }
}
