//! Canonical byte encoding for audit entries.
//!
//! Delimited string concatenation allows boundary-shifting attacks where field contents
//! migrate across adjacent columns without changing the hashed string. Every field here is
//! encoded with an explicit 4-byte little-endian length prefix, and `None` fields emit a single
//! 0xFF marker to distinguish absence from empty values.

use crate::AuditEntry;

fn encode_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    // 4-byte little-endian prefix prevents adjacent field contents from merging.
    let len = u32::try_from(bytes.len()).expect("audit field length fits in u32");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_opt_field(buf: &mut Vec<u8>, opt: Option<&[u8]>) {
    match opt {
        Some(bytes) => encode_field(buf, bytes),
        // 0xFF distinguishes None from a present 0-length byte string.
        None => buf.push(0xFF),
    }
}

impl AuditEntry {
    /// Serializes the entry into its unambiguous canonical representation.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_canonical(&mut buf);
        buf
    }

    fn write_canonical(&self, buf: &mut Vec<u8>) {
        encode_field(buf, &self.ts.as_i64().to_le_bytes());
        encode_opt_field(buf, self.token_prefix.as_ref().map(|p| p.as_str().as_bytes()));
        encode_opt_field(
            buf,
            self.peer_uid.map(|u| u.as_u32().to_le_bytes()).as_ref().map(|b| &b[..]),
        );
        encode_opt_field(
            buf,
            self.peer_pid.map(|p| p.as_u32().to_le_bytes()).as_ref().map(|b| &b[..]),
        );
        encode_field(buf, self.action.as_str().as_bytes());
        encode_opt_field(buf, self.path.as_ref().map(|p| p.as_str().as_bytes()));
        encode_opt_field(
            buf,
            self.version.map(|v| v.get().to_le_bytes()).as_ref().map(|b| &b[..]),
        );
        encode_field(buf, self.result.as_str().as_bytes());
        encode_opt_field(buf, self.detail.as_ref().map(|d| d.as_str().as_bytes()));
    }
}
