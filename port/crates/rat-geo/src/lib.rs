use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub city: String,
    pub country: String,
    pub country_code: String,
}

pub struct GeoIP {
    db: maxminddb::Reader<Vec<u8>>,
}

impl GeoIP {
    pub fn new(path: &str) -> Result<Self, String> {
        let db = maxminddb::Reader::open_readfile(path).map_err(|e| e.to_string())?;
        Ok(Self { db })
    }

    pub fn locate(&self, ip: IpAddr) -> Option<GeoLocation> {
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || (ip.is_ipv4() && matches!(ip, IpAddr::V4(v4) if v4.is_link_local()))
        {
            return None;
        }
        if ip.is_ipv6() && matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80) {
            return None;
        }

        let city: maxminddb::geoip2::City = self.db.lookup(ip).ok()?;

        let location = city.location.as_ref()?;
        let lat = location.latitude?;
        let lon = location.longitude?;

        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let country = city
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string())
            .unwrap_or_default();

        let country_code = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string())
            .unwrap_or_default();

        Some(GeoLocation {
            latitude: lat,
            longitude: lon,
            city: city_name,
            country,
            country_code,
        })
    }
}

use std::path::PathBuf;

pub fn default_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("RAT_GEOIP_DB") {
        return PathBuf::from(p);
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            let mut p = PathBuf::from(appdata);
            p.push("Rat");
            p.push("dbip-city-lite.mmdb");
            return p;
        }
        PathBuf::from(r"C:\ProgramData\Rat\dbip-city-lite.mmdb")
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            let mut p = PathBuf::from(xdg);
            p.push("rat");
            p.push("dbip-city-lite.mmdb");
            return p;
        }
        if let Ok(home) = std::env::var("HOME") {
            let mut p = PathBuf::from(home);
            p.push(".local");
            p.push("share");
            p.push("rat");
            p.push("dbip-city-lite.mmdb");
            return p;
        }
        PathBuf::from("/var/lib/rat/dbip-city-lite.mmdb")
    }
}

pub struct TimeZoneLocator;

impl TimeZoneLocator {
    pub fn coordinates() -> Option<(f64, f64, String)> {
        #[cfg(not(target_os = "windows"))]
        {
            Self::coordinates_linux()
        }
        #[cfg(target_os = "windows")]
        {
            Self::coordinates_windows()
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn coordinates_linux() -> Option<(f64, f64, String)> {
        let zone_name = std::fs::read_link("/etc/localtime")
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .and_then(|s| {
                s.find("zoneinfo/")
                    .map(|idx| s[idx + "zoneinfo/".len()..].to_string())
            })?;

        Self::lookup_in_zone_tab(&zone_name, "/usr/share/zoneinfo/zone.tab")
    }

    #[cfg(target_os = "windows")]
    fn coordinates_windows() -> Option<(f64, f64, String)> {
        // Need to read windows time zone and convert using cldr table
        let output = std::process::Command::new("tzutil")
            .arg("/g")
            .output()
            .ok()?;
        let tz_str = String::from_utf8(output.stdout).ok()?;
        let tz_str = tz_str.trim();
        let iana = crate::windows_tz::map_windows_zone_to_iana(tz_str)?;

        Self::lookup_in_zone_tab(iana, "/usr/share/zoneinfo/zone.tab")
    }

    pub fn lookup_in_zone_tab(zone_name: &str, zone_tab_path: &str) -> Option<(f64, f64, String)> {
        let content = std::fs::read_to_string(zone_tab_path).ok()?;
        for line in content.lines() {
            if line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 && parts[2] == zone_name {
                let coords_str = parts[1];
                let coords = Self::parse_iso6709(coords_str)?;
                let city = zone_name
                    .split('/')
                    .next_back()
                    .unwrap_or(zone_name)
                    .replace('_', " ");
                return Some((coords.0, coords.1, city));
            }
        }
        None
    }

    pub fn parse_iso6709(s: &str) -> Option<(f64, f64)> {
        let mut chars = s.char_indices();
        let _ = chars.next()?;
        let (split_idx, _) = chars.find(|&(_, c)| c == '+' || c == '-')?;
        let lat = Self::parse_deg(&s[..split_idx], 2)?;
        let lon = Self::parse_deg(&s[split_idx..], 3)?;
        Some((lat, lon))
    }

    fn parse_deg(s: &str, deg_digits: usize) -> Option<f64> {
        let mut chars = s.chars();
        let sign_char = chars.next()?;
        let sign = match sign_char {
            '+' => 1.0,
            '-' => -1.0,
            _ => return None,
        };

        let d = chars.as_str();
        if d.chars().count() < deg_digits + 2 {
            return None;
        }

        let deg_str: String = d.chars().take(deg_digits).collect();
        let min_str: String = d.chars().skip(deg_digits).take(2).collect();

        let deg: f64 = deg_str.parse().ok()?;
        let min: f64 = min_str.parse().ok()?;
        let sec: f64 = if d.chars().count() >= deg_digits + 4 {
            let sec_str: String = d.chars().skip(deg_digits + 2).take(2).collect();
            sec_str.parse().ok()?
        } else {
            0.0
        };

        Some(sign * (deg + min / 60.0 + sec / 3600.0))
    }
}

pub mod windows_tz;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NetworkOwner {
    pub number: u32,
    pub organization: String,
}

impl NetworkOwner {
    pub fn label(&self) -> String {
        if self.organization.is_empty() {
            format!("AS{}", self.number)
        } else {
            format!("AS{} {}", self.number, self.organization)
        }
    }
}

pub struct ASNDatabase {
    db: maxminddb::Reader<Vec<u8>>,
}

impl ASNDatabase {
    pub fn new(path: &str) -> Result<Self, String> {
        let db = maxminddb::Reader::open_readfile(path).map_err(|e| e.to_string())?;
        Ok(Self { db })
    }

    pub fn owner(&self, ip: IpAddr) -> Option<NetworkOwner> {
        if ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || (ip.is_ipv4() && matches!(ip, IpAddr::V4(v4) if v4.is_link_local()))
        {
            return None;
        }
        if ip.is_ipv6() && matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80) {
            return None;
        }

        let asn: maxminddb::geoip2::Asn = self.db.lookup(ip).ok()?;

        let number = asn.autonomous_system_number?;
        let organization = asn
            .autonomous_system_organization
            .map(|s| s.to_string())
            .unwrap_or_default();

        Some(NetworkOwner {
            number,
            organization,
        })
    }
}

pub fn default_asn_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("RAT_GEOIP_ASN_DB") {
        return PathBuf::from(p);
    }

    let mut default_path = default_db_path();
    default_path.set_file_name("dbip-asn-lite.mmdb");
    default_path
}

pub struct GeoDatabases {
    pub city_db_path: PathBuf,
    pub asn_db_path: PathBuf,
}

impl GeoDatabases {
    pub fn new() -> Self {
        Self {
            city_db_path: default_db_path(),
            asn_db_path: default_asn_db_path(),
        }
    }
}

impl Default for GeoDatabases {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoDatabases {
    pub fn load_city_db(&mut self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        let path = path.as_ref();
        let _ = maxminddb::Reader::open_readfile(path).map_err(|e| e.to_string())?;
        self.city_db_path = path.to_path_buf();
        Ok(())
    }

    pub fn load_asn_db(&mut self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        let path = path.as_ref();
        let _ = maxminddb::Reader::open_readfile(path).map_err(|e| e.to_string())?;
        self.asn_db_path = path.to_path_buf();
        Ok(())
    }
}
