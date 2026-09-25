//! Process hardening and irreversible privilege drop.
//!
//! The only module in the workspace permitted to use `unsafe`. Every block below documents
//! the invariant that makes the call sound; the surrounding crate is `deny(unsafe_code)`.
//!
//! Ordering is load-bearing and is fixed by `startup::run`: dumpability is disabled and
//! memory locked *before* any key material is read, and the uid is dropped *last*, because
//! dropping it first would remove the privilege needed to drop the gid.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;

use crate::{DaemonError, Result};

/// Resolved credentials of the account the daemon runs as after startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub uid: u32,
    pub gid: u32,
}

/// Look up a system account by name.
pub fn resolve_account(name: &str) -> Result<Account> {
    let c_name = CString::new(name).map_err(|_| DaemonError::UnknownUser(name.to_owned()))?;

    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buffer = vec![0i8; 4096];

    // SAFETY: `c_name` is a valid NUL-terminated string that outlives the call; `passwd` and
    // `result` are valid writable locations; `buffer` is a distinct allocation of the length
    // passed. getpwnam_r writes only within those bounds and does not retain the pointers.
    let code = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            std::ptr::addr_of_mut!(passwd),
            buffer.as_mut_ptr(),
            buffer.len(),
            std::ptr::addr_of_mut!(result),
        )
    };

    if code != 0 {
        return Err(DaemonError::Io(io::Error::from_raw_os_error(code)));
    }
    if result.is_null() {
        return Err(DaemonError::UnknownUser(name.to_owned()));
    }

    Ok(Account {
        uid: passwd.pw_uid,
        gid: passwd.pw_gid,
    })
}

/// Disable core dumps and `ptrace` attachment by non-root, and pin memory out of swap.
///
/// Must run before the keyfile is read. A core dump written after the master key is in
/// memory would put it in plaintext on disk, defeating every other protection.
pub fn harden_process() -> Result<()> {
    // SAFETY: prctl with PR_SET_DUMPABLE takes an integer argument and touches no memory the
    // caller owns. Returns -1 on failure without other side effects.
    let dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if dumpable != 0 {
        return Err(DaemonError::Harden(
            "PR_SET_DUMPABLE",
            io::Error::last_os_error(),
        ));
    }

    // SAFETY: mlockall takes flags only and touches no caller memory.
    let locked = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if locked != 0 {
        return Err(DaemonError::Harden("mlockall", io::Error::last_os_error()));
    }

    Ok(())
}

/// Permanently drop from root to `account`.
///
/// Uses `setres*id`, which sets the real, effective *and saved* ids together. A plain
/// `setuid` would leave the saved id at 0, from which the process could restore root at any
/// point; the whole purpose here is that it cannot.
pub fn drop_privileges(account: Account) -> Result<()> {
    if current_uid() != 0 {
        return Err(DaemonError::NotRoot);
    }

    // Supplementary groups are inherited from root and would otherwise survive the drop.
    // SAFETY: a zero-length list is read from a null pointer by contract.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(DaemonError::Harden("setgroups", io::Error::last_os_error()));
    }

    // The gid must go first: after the uid is dropped the process no longer has the
    // privilege required to change its groups.
    // SAFETY: setresgid takes integers only.
    if unsafe { libc::setresgid(account.gid, account.gid, account.gid) } != 0 {
        return Err(DaemonError::Harden("setresgid", io::Error::last_os_error()));
    }

    // SAFETY: setresuid takes integers only.
    if unsafe { libc::setresuid(account.uid, account.uid, account.uid) } != 0 {
        return Err(DaemonError::Harden("setresuid", io::Error::last_os_error()));
    }

    verify_dropped(account)
}

/// Confirm the drop actually took effect.
///
/// Checking the return codes above is not sufficient on its own -- historically this is the
/// exact step whose omission turns a privilege drop into a no-op -- so the outcome is
/// re-read from the kernel and the restoration of root is tried and required to fail.
fn verify_dropped(account: Account) -> Result<()> {
    // SAFETY: these getters take no arguments and cannot fail.
    let became_the_account = unsafe {
        libc::getuid() == account.uid
            && libc::geteuid() == account.uid
            && libc::getgid() == account.gid
            && libc::getegid() == account.gid
    };

    if !became_the_account {
        return Err(DaemonError::PrivilegeDropIncomplete);
    }

    // SAFETY: setuid takes an integer. It is expected to fail; success means the saved uid
    // is still 0 and the process could return to root, which must abort startup.
    if unsafe { libc::setuid(0) } == 0 {
        return Err(DaemonError::PrivilegeDropIncomplete);
    }

    Ok(())
}

/// The process's `RLIMIT_MEMLOCK` soft limit, or `None` when it is unlimited.
#[must_use]
pub fn memlock_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: getrlimit writes into a valid, owned `rlimit` and reads nothing else.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) } != 0 {
        return None;
    }

    (limit.rlim_cur != libc::RLIM_INFINITY).then_some(limit.rlim_cur)
}

#[must_use]
pub fn current_uid() -> u32 {
    // SAFETY: getuid takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// `chown(2)` for the socket and its directory, kept here so `unsafe` stays in one module.
#[must_use]
pub fn chown_raw(path: &std::ffi::CStr, account: Account) -> i32 {
    // SAFETY: `path` is a valid NUL-terminated string that outlives the call; the ids are
    // plain integers. chown reads the path and returns -1 on failure without other effects.
    unsafe { libc::chown(path.as_ptr(), account.uid, account.gid) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_resolves_to_uid_zero() {
        assert_eq!(resolve_account("root").unwrap().uid, 0);
    }

    #[test]
    fn an_unknown_account_is_reported_as_such() {
        assert!(matches!(
            resolve_account("no-such-user-cf83e13"),
            Err(DaemonError::UnknownUser(_))
        ));
        assert!(resolve_account("embedded\0nul").is_err());
    }

    /// The test suite does not run as root, so this exercises the guard rather than the drop.
    #[test]
    fn dropping_without_root_is_refused() {
        if current_uid() != 0 {
            assert!(matches!(
                drop_privileges(Account {
                    uid: 65534,
                    gid: 65534
                }),
                Err(DaemonError::NotRoot)
            ));
        }
    }
}
