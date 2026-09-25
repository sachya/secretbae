//! The metadata browser must never be able to fetch a secret's value.
//!
//! A full-screen value display would leak into terminal scrollback and into any screen share,
//! so `top` is restricted to metadata by construction rather than by care. This is asserted
//! against the source itself: the routes that return plaintext must not be reachable from the
//! module at all, which no amount of careful review of a future change would guarantee.

const TOP_SOURCES: [(&str, &str); 4] = [
    ("top/mod.rs", include_str!("../src/top/mod.rs")),
    ("top/app.rs", include_str!("../src/top/app.rs")),
    ("top/render.rs", include_str!("../src/top/render.rs")),
    ("top/theme.rs", include_str!("../src/top/theme.rs")),
];

/// Everything that returns a decrypted value, by any name it could be referenced under.
const VALUE_BEARING: [&str; 6] = [
    "route::READ",
    "route::RESOLVE",
    "ReadRequest",
    "ReadResponse",
    "ResolveRequest",
    "ResolveResponse",
];

#[test]
fn the_metadata_browser_cannot_reach_a_route_that_returns_a_value() {
    for (name, source) in TOP_SOURCES {
        for reference in VALUE_BEARING {
            assert!(
                !source.contains(reference),
                "{name} references {reference}; the browser must only ever fetch metadata"
            );
        }
    }
}

/// The columns it does render, so a future refactor that drops one is caught rather than
/// quietly shipping an emptier table.
#[test]
fn the_browser_renders_the_metadata_columns_it_promises() {
    let render = TOP_SOURCES
        .iter()
        .find(|(name, _)| *name == "top/render.rs")
        .expect("render.rs is listed above")
        .1;

    for column in ["KEY", "VERSIONS", "CURRENT", "TAGS", "UPDATED"] {
        assert!(
            render.contains(column),
            "the table no longer renders a {column} column"
        );
    }
}
