//! Command-line interface definitions and argument parsing.

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};
use sbae_proto::{SecretPath, Tag, TagSelector, Version};

/// Top-level CLI definition.
#[derive(Parser, Debug)]
#[command(
    name = "secretbae",
    about = "Client for the secretbae secret management daemon",
    version
)]
pub struct Cli {
    #[arg(long, global = true, help = "Output formatted JSON")]
    pub json: bool,

    #[arg(
        long,
        global = true,
        default_value = sbae_proto::api::DEFAULT_SOCKET_PATH,
        help = "Path to the secretbae daemon Unix domain socket"
    )]
    pub socket: PathBuf,

    #[arg(
        long,
        global = true,
        help = "Path to token file (must not be group- or world-readable)"
    )]
    pub token_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// Supported subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(about = "Display daemon status and sealed state")]
    Status,

    #[command(about = "Write a new version of a secret")]
    Put {
        #[arg(help = "Secret path")]
        path: SecretPath,

        #[arg(long, conflicts_with_all = ["file", "value"], help = "Read payload from standard input")]
        stdin: bool,

        #[arg(long, conflicts_with_all = ["stdin", "value"], help = "Read payload from a file")]
        file: Option<PathBuf>,

        #[arg(long, conflicts_with_all = ["stdin", "file"], help = "Literal string secret payload")]
        value: Option<String>,

        #[arg(long = "tag", action = ArgAction::Append, help = "Key=value tag to attach")]
        tags: Vec<Tag>,

        #[arg(long, help = "Optional audit comment")]
        comment: Option<String>,
    },

    #[command(about = "Read a secret value")]
    Get {
        #[arg(help = "Secret path")]
        path: SecretPath,

        #[arg(long, help = "Specific version to read (defaults to current version)")]
        version: Option<Version>,

        #[arg(long, conflicts_with = "json", help = "Write raw decrypted payload to stdout with no trailing newline")]
        raw: bool,
    },

    #[command(about = "List secrets matching an optional prefix and tags")]
    Ls {
        #[arg(help = "Optional prefix filter")]
        prefix: Option<String>,

        #[arg(long = "tag", action = ArgAction::Append, help = "Filter by tag (all tags must match)")]
        tags: Vec<Tag>,
    },

    #[command(about = "List all versions of a secret")]
    Versions {
        #[arg(help = "Secret path")]
        path: SecretPath,
    },

    #[command(about = "Roll back a secret to a previous version")]
    Rollback {
        #[arg(help = "Secret path")]
        path: SecretPath,

        #[arg(long, required = true, help = "Target version to restore")]
        to: Version,
    },

    #[command(about = "Soft-delete or destroy a secret")]
    Rm {
        #[arg(help = "Secret path")]
        path: SecretPath,

        #[arg(long, help = "Specific version to delete")]
        version: Option<Version>,

        #[arg(long, help = "Irreversibly destroy ciphertext rather than soft-deleting")]
        destroy: bool,
    },

    #[command(about = "Manage metadata tags on secrets")]
    Tag {
        #[command(subcommand)]
        action: TagAction,
    },

    #[command(about = "Manage authentication tokens")]
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    #[command(about = "Manage access control policies")]
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    #[command(about = "Verify the integrity of the audit log hash chain")]
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    #[command(about = "Inject profile secrets into the environment and execve directly")]
    Exec {
        #[arg(long, required = true, help = "Profile name in /etc/secretbae/profiles/<name>.toml")]
        profile: String,

        #[arg(last = true, required = true, help = "Command and arguments to execute")]
        command: Vec<String>,
    },

    #[command(about = "Generate shell completions")]
    Completions {
        #[arg(help = "Target shell")]
        shell: clap_complete::Shell,
    },

    #[command(about = "Rotate the master key, rewrapping every stored data key")]
    Rekey {
        #[arg(long, help = "Skip the confirmation prompt")]
        yes: bool,
    },

    #[command(about = "Write an encrypted backup bundle")]
    Backup {
        #[arg(help = "File to write the bundle to")]
        output: std::path::PathBuf,

        #[arg(
            long,
            env = "SECRETBAE_BACKUP_PASSPHRASE",
            help = "Bundle passphrase; prompted for if omitted"
        )]
        passphrase: Option<String>,
    },

    #[command(about = "Restore an encrypted backup bundle into an empty store")]
    Restore {
        #[arg(help = "Bundle file to read")]
        input: std::path::PathBuf,

        #[arg(
            long,
            env = "SECRETBAE_BACKUP_PASSPHRASE",
            help = "Bundle passphrase; prompted for if omitted"
        )]
        passphrase: Option<String>,
    },

    #[command(about = "Live metadata browser")]
    Top {
        #[arg(
            long,
            default_value = "2",
            help = "Auto-refresh interval in seconds"
        )]
        interval: u64,

        #[arg(
            long,
            help = "Render a single non-interactive frame and exit"
        )]
        once: bool,
    },
}

/// Tag subcommands.
#[derive(Subcommand, Debug)]
pub enum TagAction {
    #[command(about = "Attach tags to a secret")]
    Add {
        #[arg(help = "Secret path")]
        path: SecretPath,

        #[arg(required = true, help = "Tags as key=value")]
        tags: Vec<Tag>,
    },

    #[command(about = "Remove tags from a secret")]
    Rm {
        #[arg(help = "Secret path")]
        path: SecretPath,

        #[arg(required = true, help = "Tags as key=value, or a bare key to remove every value under it")]
        tags: Vec<TagSelector>,
    },

    #[command(about = "List tags attached to a secret")]
    Ls {
        #[arg(help = "Secret path")]
        path: SecretPath,
    },
}

/// Token subcommands.
#[derive(Subcommand, Debug)]
pub enum TokenAction {
    #[command(about = "Issue a new bearer token")]
    Create {
        #[arg(long, required = true, help = "Human-readable token name")]
        name: String,

        #[arg(
            long = "policy",
            action = ArgAction::Append,
            help = "Policy name to attach (repeatable). At least one of --policy or --unrestricted is required."
        )]
        policies: Vec<String>,

        #[arg(
            long,
            help = "Attach the built-in 'unrestricted' policy: read, write, delete and list on every secret, but never token or policy administration. For a first token or local experimentation; write a scoped --policy for anything production."
        )]
        unrestricted: bool,

        #[arg(long, help = "Token lifetime (e.g. 90d, 12h, 3600s)")]
        ttl: Option<String>,

        #[arg(long, help = "Bind token to local username or UID")]
        bind_uid: Option<String>,
    },

    #[command(about = "List active tokens")]
    List {
        #[arg(help = "Optional prefix filter")]
        prefix: Option<String>,
    },

    #[command(about = "Revoke a token by its public prefix")]
    Revoke {
        #[arg(help = "Token lookup prefix")]
        prefix: String,
    },
}

/// Policy subcommands.
#[derive(Subcommand, Debug)]
pub enum PolicyAction {
    #[command(about = "Upload or replace a policy document")]
    Put {
        #[arg(long, required = true, help = "Path to policy document file")]
        file: PathBuf,
    },

    #[command(about = "List all stored policy names")]
    List,

    #[command(about = "Delete a policy document by name")]
    Rm {
        #[arg(help = "Policy name to delete")]
        name: String,
    },
}

/// Audit subcommands.
#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    #[command(about = "Verify the hash-chain integrity of the audit log")]
    Verify,
}