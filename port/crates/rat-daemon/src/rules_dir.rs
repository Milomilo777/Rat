//! Trust gate for the directory that holds the saved rules (release blocker:
//! the SYSTEM daemon loads and saves `rules.json` there). A standard user can
//! create `C:\ProgramData\rat` first (and so own it), plant a rules file, or
//! swap in a junction so SYSTEM writes elsewhere. On Windows the daemon
//! therefore creates the directory with a protected SYSTEM + Administrators
//! DACL. An existing directory is refused when it is a reparse point or is not
//! owned by SYSTEM / Administrators; otherwise its DACL is re-applied as the
//! same protected SYSTEM + Administrators descriptor (an admin-created
//! directory with inherited ProgramData ACEs would let a standard user plant
//! files), and the directory is refused if that fails. On Linux the systemd
//! unit owns the directory and nothing changes.

/// Pure decision: may the daemon read and write rules in this directory?
/// The Windows code only gathers the two facts.
pub fn rules_dir_trusted(owner_is_admin_or_system: bool, is_reparse_point: bool) -> bool {
    owner_is_admin_or_system && !is_reparse_point
}

/// DACL only: full control for SYSTEM and Administrators, inheritable,
/// protected (no inherited ACEs from ProgramData).
#[cfg(any(windows, test))]
pub const DIR_DACL_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Owner Administrators + the DACL above, the production descriptor.
#[cfg(any(windows, test))]
pub const DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Make sure the directory of `rules_file` exists and is trustworthy.
/// Returns whether rules may be loaded from and saved to it. Failures are
/// logged here, fail closed (false).
#[cfg(windows)]
pub fn ensure_rules_dir(rules_file: &std::path::Path) -> bool {
    let Some(dir) = rules_file.parent() else {
        eprintln!("rat-daemon: rules path has no directory; rules persistence disabled");
        return false;
    };
    // symlink_metadata never follows a link, so a planted junction is seen.
    if std::fs::symlink_metadata(dir).is_err() {
        if let Err(e) = win::create_dir_with_sddl(dir, DIR_SDDL) {
            eprintln!(
                "rat-daemon: cannot create rules directory {}: {e}; rules persistence disabled",
                dir.display()
            );
            return false;
        }
    }
    let facts = win::gather_facts(dir);
    match facts {
        Ok((owner_ok, reparse)) => {
            let trusted = rules_dir_trusted(owner_ok, reparse);
            if trusted {
                // Owner and reparse checks say nothing about WHO ELSE may write
                // here. Re-apply the protected DACL (also propagates to the
                // children); if that cannot be done the directory is not
                // trusted. Idempotent for a directory this daemon created.
                if let Err(e) = win::apply_protected_dacl(dir, DIR_DACL_SDDL) {
                    eprintln!(
                        "rat-daemon: cannot apply the protected DACL to rules directory {}: {e}; rules persistence disabled",
                        dir.display()
                    );
                    return false;
                }
            }
            if !trusted {
                eprintln!(
                    "rat-daemon: rules directory {} is not trusted (owner is SYSTEM/Administrators: {owner_ok}, reparse point: {reparse}); \
                     starting with an empty rule set and NOT touching the firewall or the directory",
                    dir.display()
                );
            }
            trusted
        }
        Err(e) => {
            eprintln!(
                "rat-daemon: cannot inspect rules directory {}: {e}; rules persistence disabled",
                dir.display()
            );
            false
        }
    }
}

/// Linux: the rules file is /etc/rat/rules.json; behaviour is unchanged.
#[cfg(not(windows))]
pub fn ensure_rules_dir(_rules_file: &std::path::Path) -> bool {
    true
}

#[cfg(windows)]
pub(crate) mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{LocalFree, FALSE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
        SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };

    const SDDL_REVISION_1: u32 = 1;

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    struct LocalMem(*mut std::ffi::c_void);
    impl Drop for LocalMem {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: allocated by the Convert*/Get* APIs, freed once.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// CreateDirectoryW with the descriptor applied atomically (no window in
    /// which the directory exists with inherited, user-writable ACEs).
    pub fn create_dir_with_sddl(dir: &Path, sddl: &str) -> std::io::Result<()> {
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: sddl_w is NUL-terminated; sd receives a LocalAlloc buffer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        let _guard = LocalMem(sd);
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: FALSE,
        };
        let path_w = wide(dir);
        // SAFETY: path_w is NUL-terminated; sa outlives the call.
        if unsafe { CreateDirectoryW(path_w.as_ptr(), &sa) } == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Replace the DACL of an existing directory with the one in `dacl_sddl`,
    /// protected (no inherited ACEs), and propagate it to children that
    /// inherit. The owner is not touched.
    pub fn apply_protected_dacl(dir: &Path, dacl_sddl: &str) -> std::io::Result<()> {
        let sddl_w: Vec<u16> = dacl_sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: sddl_w is NUL-terminated; sd receives a LocalAlloc buffer.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        let _guard = LocalMem(sd);
        let mut present = 0i32;
        let mut defaulted = 0i32;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: sd is a valid descriptor; dacl points into it.
        let ok = unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) };
        if ok == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            // A NULL DACL would grant everyone access: never apply that.
            return Err(std::io::Error::other("descriptor has no DACL"));
        }
        let mut path_w = wide(dir);
        // SAFETY: path_w is NUL-terminated and mutable as the API requires;
        // dacl stays valid while _guard lives.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        Ok(())
    }

    /// (owner is SYSTEM or Administrators, directory is a reparse point)
    pub fn gather_facts(dir: &Path) -> std::io::Result<(bool, bool)> {
        let path_w = wide(dir);
        // SAFETY: path_w is NUL-terminated.
        let attrs = unsafe { GetFileAttributesW(path_w.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(std::io::Error::last_os_error());
        }
        let reparse = attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0;

        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: out pointers are valid; owner points into sd.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        let _guard = LocalMem(sd);
        // SAFETY: owner is a valid SID inside sd, alive until _guard drops.
        let owner_ok = !owner.is_null()
            && unsafe {
                IsWellKnownSid(owner, WinLocalSystemSid) != 0
                    || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            };
        Ok((owner_ok, reparse))
    }

    /// The DACL of `dir` as SDDL (tests read back what the helper set).
    #[cfg(test)]
    pub fn dacl_sddl(dir: &Path) -> std::io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
        let path_w = wide(dir);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: as in gather_facts.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        let _guard = LocalMem(sd);
        let mut out: *mut u16 = std::ptr::null_mut();
        // SAFETY: sd is valid; out receives a LocalAlloc'd wide string.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut out,
                std::ptr::null_mut(),
            )
        };
        if ok == FALSE {
            return Err(std::io::Error::last_os_error());
        }
        let _s = LocalMem(out as *mut std::ffi::c_void);
        let mut len = 0usize;
        // SAFETY: out is NUL-terminated.
        unsafe {
            while *out.add(len) != 0 {
                len += 1;
            }
            Ok(String::from_utf16_lossy(std::slice::from_raw_parts(
                out, len,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_decision_all_combinations() {
        assert!(rules_dir_trusted(true, false));
        assert!(!rules_dir_trusted(true, true), "junction/symlink refused");
        assert!(!rules_dir_trusted(false, false), "user-owned refused");
        assert!(!rules_dir_trusted(false, true));
    }

    #[test]
    fn production_sddl_is_owner_admins_plus_the_dacl() {
        assert_eq!(DIR_SDDL, format!("O:BA{DIR_DACL_SDDL}"));
    }

    #[cfg(not(windows))]
    #[test]
    fn linux_is_unchanged() {
        assert!(ensure_rules_dir(std::path::Path::new(
            "/nonexistent/rules.json"
        )));
    }

    #[cfg(windows)]
    fn temp_base(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "rat-rulesdir-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[cfg(windows)]
    #[test]
    fn created_dir_has_protected_system_and_admins_only_dacl() {
        let base = temp_base("dacl");
        let dir = base.join("rat");
        // DACL-only descriptor: setting the owner to Administrators needs an
        // elevated token, which a test run may lack.
        win::create_dir_with_sddl(&dir, DIR_DACL_SDDL).expect("create");
        let sddl = win::dacl_sddl(&dir).expect("read back");
        assert!(sddl.starts_with("D:P"), "DACL must be protected: {sddl}");
        assert_eq!(sddl.matches("(A;").count(), 2, "exactly two ACEs: {sddl}");
        assert_eq!(sddl.matches('(').count(), 2, "no other ACE types: {sddl}");
        assert!(sddl.contains(";;;SY)"), "SYSTEM ACE: {sddl}");
        assert!(sddl.contains(";;;BA)"), "Administrators ACE: {sddl}");
        let _ = std::fs::remove_dir(&dir);
        let _ = std::fs::remove_dir(&base);
    }

    // An existing directory that carries inherited (user-writable)
    // ACEs is brought to the protected SYSTEM + Administrators DACL.
    #[cfg(windows)]
    #[test]
    fn apply_protected_dacl_replaces_inherited_aces() {
        let base = temp_base("apply");
        let dir = base.join("rat");
        std::fs::create_dir(&dir).unwrap(); // inherits the temp dir's ACEs
        let before = win::dacl_sddl(&dir).expect("read before");
        assert!(
            !before.starts_with("D:P"),
            "precondition: dir inherits ACEs: {before}"
        );
        win::apply_protected_dacl(&dir, DIR_DACL_SDDL).expect("apply");
        let after = win::dacl_sddl(&dir).expect("read after");
        assert!(after.starts_with("D:P"), "protected: {after}");
        assert_eq!(after.matches('(').count(), 2, "only two ACEs: {after}");
        assert!(
            after.contains(";;;SY)") && after.contains(";;;BA)"),
            "{after}"
        );
        // The test user's own access came from an inherited ACE and is gone,
        // but the owner can always re-set the DACL to clean up.
        let _ = std::fs::remove_dir(&dir);
        let _ = std::fs::remove_dir(&base);
    }

    #[cfg(windows)]
    #[test]
    fn plain_dir_is_not_reparse_and_junction_is() {
        let base = temp_base("facts");
        let (_owner, reparse) = win::gather_facts(&base).expect("facts");
        assert!(!reparse);
        // A junction inside the temp dir (the attack shape).
        let target = base.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = base.join("link");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .expect("cmd");
        assert!(status.status.success(), "mklink failed");
        let (_o, reparse) = win::gather_facts(&link).expect("facts");
        assert!(reparse, "junction must be seen as a reparse point");
        // remove_dir on a junction removes only the link.
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir(&target);
        let _ = std::fs::remove_dir(&base);
    }
}
