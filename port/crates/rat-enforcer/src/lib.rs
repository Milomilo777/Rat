use std::io;

#[cfg(not(windows))]
pub mod linux;
#[cfg(windows)]
pub mod windows;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Blocklist {
    pub paths: Vec<String>,
    pub local_ports: Vec<u16>,
}

pub trait Enforcer {
    type Plan;
    fn plan(&self, wanted: &Blocklist) -> Self::Plan;
    fn apply(&self, plan: &Self::Plan) -> io::Result<()>;
}

pub fn validate_path(path: &str) -> Result<String, &'static str> {
    if path.contains(['"', '\'', ';', '\n', '\r']) {
        return Err("invalid characters in path");
    }
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_validation_path() {
        assert!(validate_path("/usr/bin/app").is_ok());
        assert!(validate_path("C:\\ProgramFiles\\App").is_ok());
        assert!(validate_path("C:\\Program Files\\App").is_ok());
        assert!(validate_path("/usr/bin/app; rm -rf /").is_err());
        assert!(validate_path("/usr/bin/app\"").is_err());
        assert!(validate_path("/usr/bin/app\n").is_err());
        assert!(validate_path("/usr/bin/app\r").is_err());
        assert!(validate_path("/usr/bin/app'").is_err());
        assert!(validate_path("/usr/bin/رنامه").is_ok());
        assert!(validate_path("/usr/bin/应用").is_ok());
    }

    proptest! {
        #[test]
        fn proptest_validate_path_no_panic(s in "\\PC*") {
            let _ = validate_path(&s);
        }

        #[test]
        fn proptest_validate_path_rejects_bad_chars(s in ".*[\"';\n\r].*") {
            assert!(validate_path(&s).is_err());
        }

        #[test]
        fn proptest_validate_path_accepts_good_chars(s in "[^\"';\n\r]+") {
            assert!(validate_path(&s).is_ok());
        }
    }
}
