//! Segment-aware glob matching for policy paths.
//!
//! Two wildcards, both operating on whole `/`-separated segments:
//!
//! * `*`  matches exactly one segment.
//! * `**` matches zero or more segments.
//!
//! Matching is a dynamic-programming table rather than a regular expression or naive
//! recursion. That gives a hard `O(pattern x path)` bound, so a pattern like `**/**/**/x`
//! cannot be used to burn daemon CPU on every request.

/// Whether `path` matches `pattern`.
#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();

    // reachable[j] == "the pattern consumed so far can end at path segment j".
    let mut reachable = vec![false; path.len() + 1];
    reachable[0] = true;

    for segment in pattern {
        let mut next = vec![false; path.len() + 1];

        match segment {
            "**" => {
                // Zero or more: once reachable, every later position is too.
                let mut carried = false;
                for (slot, &here) in next.iter_mut().zip(reachable.iter()) {
                    carried |= here;
                    *slot = carried;
                }
            }
            "*" => next[1..].copy_from_slice(&reachable[..path.len()]),
            literal => {
                for j in 0..path.len() {
                    next[j + 1] = reachable[j] && path[j] == literal;
                }
            }
        }

        reachable = next;
        if !reachable.iter().any(|&r| r) {
            return false;
        }
    }

    reachable[path.len()]
}

/// Whether a pattern is well formed. Rejected patterns are refused when a policy is stored,
/// so an unmatchable rule can never be saved and later mistaken for an effective one.
#[must_use]
pub fn is_valid_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && pattern.split('/').all(|segment| {
            segment == "*"
                || segment == "**"
                || (!segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment
                        .bytes()
                        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.')))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_patterns_match_exactly() {
        assert!(matches("prod/billing/db", "prod/billing/db"));
        assert!(!matches("prod/billing/db", "prod/billing/db2"));
        assert!(!matches("prod/billing", "prod/billing/db"));
        assert!(!matches("prod/billing/db", "prod/billing"));
    }

    #[test]
    fn single_star_matches_exactly_one_segment() {
        assert!(matches("prod/*/db", "prod/billing/db"));
        assert!(!matches("prod/*/db", "prod/db"), "* must not match zero segments");
        assert!(!matches("prod/*/db", "prod/a/b/db"), "* must not match two segments");
        assert!(!matches("prod/*", "prod/billing/db"));
    }

    #[test]
    fn double_star_matches_any_number_of_segments() {
        assert!(matches("prod/**", "prod"), "** matches zero segments");
        assert!(matches("prod/**", "prod/billing"));
        assert!(matches("prod/**", "prod/billing/db/user"));
        assert!(!matches("prod/**", "dev/billing"));
        assert!(matches("**", "anything/at/all"));
        assert!(matches("**/db", "prod/billing/db"));
        assert!(matches("**/db", "db"));
    }

    /// The escalation a substring match would allow.
    #[test]
    fn wildcards_never_cross_segment_boundaries() {
        assert!(!matches("prod/billing/*", "prod/billing-admin/db"));
        assert!(!matches("prod/billing/**", "prod/billing-admin/db"));
        assert!(!matches("prod/*", "prod-staging/db"));
    }

    #[test]
    fn repeated_double_stars_terminate_quickly() {
        let pattern = "**/".repeat(12) + "target";
        let path = (0..15).map(|n| format!("s{n}")).collect::<Vec<_>>().join("/");

        assert!(!matches(&pattern, &path));
        assert!(matches(&pattern, &format!("{path}/target")));
    }

    #[test]
    fn validation_rejects_unmatchable_patterns() {
        assert!(is_valid_pattern("prod/**"));
        assert!(is_valid_pattern("prod/*/db"));
        assert!(is_valid_pattern("a"));

        assert!(!is_valid_pattern(""));
        assert!(!is_valid_pattern("prod//db"), "empty segment");
        assert!(!is_valid_pattern("prod/../db"));
        assert!(!is_valid_pattern("prod/DB"), "uppercase cannot match a lowercase path");
        assert!(!is_valid_pattern("prod/bil*ing"), "partial-segment globs are not supported");
    }
}
