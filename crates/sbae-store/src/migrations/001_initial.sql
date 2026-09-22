-- secretbae schema v1.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE secrets (
    id              BLOB    PRIMARY KEY,
    path            TEXT    NOT NULL UNIQUE,
    -- NULL between creating the row and committing its first version.
    current_version INTEGER,
    max_versions    INTEGER NOT NULL DEFAULT 10,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE secret_versions (
    secret_id     BLOB    NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version       INTEGER NOT NULL,
    state         TEXT    NOT NULL CHECK (state IN ('active', 'deleted', 'destroyed')),
    -- Cleared when a version is destroyed; a destroyed row survives so that the version
    -- number is never reused and the audit trail stays intelligible.
    nonce         BLOB,
    ciphertext    BLOB,
    dek_nonce     BLOB,
    wrapped_dek   BLOB,
    mk_generation INTEGER NOT NULL,
    created_at    INTEGER NOT NULL,
    created_by    TEXT,
    comment       TEXT,
    PRIMARY KEY (secret_id, version),
    CHECK (state = 'destroyed' OR ciphertext IS NOT NULL)
) STRICT;

CREATE TABLE tags (
    id    INTEGER PRIMARY KEY,
    key   TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (key, value)
) STRICT;

CREATE TABLE secret_tags (
    secret_id BLOB    NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    tag_id    INTEGER NOT NULL REFERENCES tags(id)    ON DELETE CASCADE,
    PRIMARY KEY (secret_id, tag_id)
) STRICT;

CREATE INDEX secret_tags_by_tag ON secret_tags(tag_id);

CREATE TABLE policies (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    document   TEXT NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE tokens (
    id            BLOB PRIMARY KEY,
    -- Indexed so verification is one lookup plus one constant-time compare, never a scan.
    lookup_prefix TEXT NOT NULL UNIQUE,
    hash          BLOB NOT NULL,
    name          TEXT NOT NULL,
    -- When set, the connecting process must present this uid via SO_PEERCRED.
    bound_uid     INTEGER,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    revoked_at    INTEGER,
    last_used_at  INTEGER
) STRICT;

CREATE TABLE token_policies (
    token_id  BLOB    NOT NULL REFERENCES tokens(id)   ON DELETE CASCADE,
    policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (token_id, policy_id)
) STRICT;

CREATE TABLE audit (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    token_prefix TEXT,
    peer_uid     INTEGER,
    peer_pid     INTEGER,
    action       TEXT NOT NULL,
    path         TEXT,
    version      INTEGER,
    result       TEXT NOT NULL,
    detail       TEXT,
    prev_hash    BLOB NOT NULL,
    entry_hash   BLOB NOT NULL
) STRICT;
