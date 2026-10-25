//! Update check, platform-independent core of App/Model/UpdateChecker.swift:
//! dotted-version comparison and picking the newest release from a GitHub
//! `/releases` JSON body. The HTTP fetch is layered on top by the app
//! (runs only when the user chooses it, Swift doc comment).

pub const REPO: &str = "ImanMontajabi/Rat";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Release {
    pub tag: String,
    pub url: String,
    pub prerelease: bool,
}

fn parts(s: &str) -> Vec<i64> {
    // Swift: trim v/V from both ends, split on ".", Int($0) ?? 0.
    s.trim_matches(['v', 'V'])
        .split('.')
        .map(|p| p.parse::<i64>().unwrap_or(0))
        .collect()
}

/// True when `latest` is a higher dotted version than `current`
/// ("v0.3.0" vs "0.2.0"). Non-numeric segments count as 0 (Swift `Int($0) ?? 0`).
pub fn is_newer(latest: &str, current: &str) -> bool {
    let (a, b) = (parts(latest), parts(current));
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

/// The newest published release from a GitHub `releases` JSON body (drafts
/// skipped; pre-releases only when `include_pre_releases`). Ties keep the
/// earlier entry, like Swift's `max(by:)`.
pub fn newest_release(json: &str, include_pre_releases: bool) -> Option<Release> {
    let list = serde_json::from_str::<serde_json::Value>(json).ok()?;
    let list = list.as_array()?;
    let mut best: Option<Release> = None;
    for j in list {
        if j.get("draft").and_then(|d| d.as_bool()).unwrap_or(false) {
            continue;
        }
        let Some(tag) = j.get("tag_name").and_then(|t| t.as_str()) else {
            continue;
        };
        let prerelease = j
            .get("prerelease")
            .and_then(|p| p.as_bool())
            .unwrap_or(false);
        if !include_pre_releases && prerelease {
            continue;
        }
        let url = j
            .get("html_url")
            .and_then(|u| u.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://github.com/{REPO}/releases"));
        let r = Release {
            tag: tag.to_string(),
            url,
            prerelease,
        };
        if best.as_ref().is_none_or(|b| is_newer(&r.tag, &b.tag)) {
            best = Some(r);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_dotted_versions() {
        assert!(is_newer("v0.3.0", "0.2.0"));
        assert!(is_newer("0.3.0", "v0.2.0"));
        assert!(!is_newer("0.2.0", "0.3.0"));
        assert!(!is_newer("0.2.0", "0.2.0"), "equal is not newer");
        assert!(!is_newer("1.2", "1.2.0"), "missing segment counts as 0");
        assert!(is_newer("1.2.1", "1.2"));
        assert!(is_newer("0.10.0", "0.9.9"), "numeric, not lexicographic");
        assert!(is_newer("V2.0.0", "1.9.9"), "capital V prefix trimmed");
        assert!(
            !is_newer("2.0.0-beta", "2.0.0"),
            "suffix parses as 0 -> equal"
        );
        assert!(!is_newer("unknown", "0"), "garbage counts as 0.0.0");
    }

    #[test]
    fn test_newest_release_filters_and_picks() {
        let json = r#"[
            {"tag_name":"v0.9.0","html_url":"https://x/0.9.0","prerelease":false},
            {"tag_name":"v1.2.0","prerelease":true},
            {"tag_name":"v1.0.0","draft":true,"html_url":"https://x/draft"},
            {"name":"no tag here"},
            {"tag_name":"v1.1.0","html_url":"https://x/1.1.0"}
        ]"#;
        let stable = newest_release(json, false).expect("a stable release");
        assert_eq!(stable.tag, "v1.1.0");
        assert_eq!(stable.url, "https://x/1.1.0");
        assert!(!stable.prerelease);

        let with_pre = newest_release(json, true).expect("a release");
        assert_eq!(with_pre.tag, "v1.2.0", "pre-release included on request");
        assert_eq!(
            with_pre.url, "https://github.com/ImanMontajabi/Rat/releases",
            "missing html_url falls back to the releases page"
        );
    }

    #[test]
    fn test_newest_release_bad_input() {
        assert!(newest_release("not json", false).is_none());
        assert!(newest_release("[]", false).is_none());
        assert!(newest_release("{}", false).is_none());
    }
}
