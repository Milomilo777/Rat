//! Shared system services (AppInfo.swift:89-104 `SharedServices`): processes
//! that work for many apps at once. Their sockets belong to the service and
//! the service is its own responsible process, so nothing on the socket says
//! which app asked — the ledger marks them instead of guessing.
//!
//! The Swift table is macOS process names; the port adds the equivalent
//! Windows/Linux shared hosts so `ConnectionDetails::shared_service` can be
//! filled on every platform. Matching is on the executable FILE NAME
//! (a full path is accepted), case-insensitive — Windows reports
//! `SVCHOST.EXE` as often as `svchost.exe`.

/// macOS shared services, notes verbatim from AppInfo.swift:92-100.
const MACOS: &[(&str, &str)] = &[
    (
        "mDNSResponder",
        "DNS and Bonjour for every app. Which app asked for a name cannot be seen: that needs a DNS proxy (a Network Extension), which Rat cannot install.",
    ),
    ("nsurlsessiond", "Background downloads and uploads on behalf of apps."),
    ("apsd", "Push notifications for every app."),
    ("trustd", "Certificate checks for every app."),
    ("cloudd", "iCloud sync on behalf of apps."),
    ("networkserviceproxy", "iCloud Private Relay for apps that use it."),
    (
        "com.apple.WebKit.Networking",
        "Web content for an app that macOS did not name.",
    ),
];

/// Port-side equivalents on the other two platforms.
const WINDOWS: &[(&str, &str)] = &[
    (
        "svchost.exe",
        "Windows services host: DNS (Dnscache), DHCP and many other services run here for every app; which app asked cannot be seen from the connection tables.",
    ),
];

const LINUX: &[(&str, &str)] = &[
    (
        "systemd-resolved",
        "DNS for every app via systemd-resolved; which app asked for a name cannot be seen.",
    ),
    (
        "dnsmasq",
        "DNS/DHCP for every app behind dnsmasq; which app asked cannot be seen.",
    ),
    (
        "avahi-daemon",
        "mDNS/DNS-SD for every app; which app asked cannot be seen.",
    ),
];

fn file_name(process: &str) -> &str {
    let p = process.rsplit(['/', '\\']).next().unwrap_or(process);
    p
}

/// What the process does for others, or `None` for a process that works for
/// itself (`SharedServices.note(for:)`).
pub fn note(process: &str) -> Option<&'static str> {
    let name = file_name(process);
    MACOS
        .iter()
        .chain(WINDOWS)
        .chain(LINUX)
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, note)| *note)
}

/// True when the process is a shared service host (feeds
/// [`crate::ConnectionDetails::shared_service`]).
pub fn is_shared_service(process: &str) -> bool {
    note(process).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_table_matches_swift() {
        for name in [
            "mDNSResponder",
            "nsurlsessiond",
            "apsd",
            "trustd",
            "cloudd",
            "networkserviceproxy",
            "com.apple.WebKit.Networking",
        ] {
            assert!(note(name).is_some(), "{name} should be classified shared");
        }
        assert_eq!(
            note("trustd"),
            Some("Certificate checks for every app."),
            "notes are the Swift text"
        );
    }

    #[test]
    fn test_plain_apps_are_not_shared() {
        for name in ["curl", "firefox", "/usr/bin/wget", "C:\\Apps\\app.exe"] {
            assert!(!is_shared_service(name), "{name} works for itself");
        }
    }

    #[test]
    fn test_platform_hosts_and_paths() {
        assert!(is_shared_service("svchost.exe"));
        assert!(
            is_shared_service("C:\\Windows\\System32\\SVCHOST.EXE"),
            "full paths and Windows casing both match"
        );
        assert!(is_shared_service("/lib/systemd/systemd-resolved"));
        assert!(is_shared_service("dnsmasq"));
        assert!(is_shared_service("avahi-daemon"));
        assert_eq!(
            note("avahi-daemon"),
            Some("mDNS/DNS-SD for every app; which app asked cannot be seen.")
        );
    }
}
