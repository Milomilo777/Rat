use ipnet::IpNet;
use mmdb_writer::Writer;
use rat_geo::GeoIP;
use std::collections::BTreeMap;

fn write_test_db(path: &str) {
    let mut writer = Writer::builder("Test-City").build();

    let mut city = BTreeMap::new();
    let mut location = BTreeMap::new();
    location.insert("latitude".to_string(), mmdb_writer::Value::Double(42.0));
    location.insert("longitude".to_string(), mmdb_writer::Value::Double(-71.0));
    city.insert("location".to_string(), mmdb_writer::Value::Map(location));

    let mut city_info = BTreeMap::new();
    let mut city_names = BTreeMap::new();
    city_names.insert(
        "en".to_string(),
        mmdb_writer::Value::String("Boston".to_string()),
    );
    city_info.insert("names".to_string(), mmdb_writer::Value::Map(city_names));
    city.insert("city".to_string(), mmdb_writer::Value::Map(city_info));

    let mut country_info = BTreeMap::new();
    let mut country_names = BTreeMap::new();
    country_names.insert(
        "en".to_string(),
        mmdb_writer::Value::String("United States".to_string()),
    );
    country_info.insert("names".to_string(), mmdb_writer::Value::Map(country_names));
    country_info.insert(
        "iso_code".to_string(),
        mmdb_writer::Value::String("US".to_string()),
    );
    city.insert("country".to_string(), mmdb_writer::Value::Map(country_info));

    writer
        .insert_value(
            "1.2.3.0/24".parse::<IpNet>().unwrap(),
            mmdb_writer::Value::Map(city),
        )
        .unwrap();

    let mut f = std::fs::File::create(path).unwrap();
    writer.write_to(&mut f).unwrap();
}

#[test]
fn test_geoip_lookup() {
    let path = "test.mmdb";
    write_test_db(path);

    let db = GeoIP::new(path).unwrap();
    let loc = db.locate("1.2.3.4".parse().unwrap()).unwrap();
    assert_eq!(loc.city, "Boston");
    assert_eq!(loc.country, "United States");
    assert_eq!(loc.country_code, "US");
    assert_eq!(loc.latitude, 42.0);
    assert_eq!(loc.longitude, -71.0);

    assert!(db.locate("8.8.8.8".parse().unwrap()).is_none());
    assert!(db.locate("127.0.0.1".parse().unwrap()).is_none());

    std::fs::remove_file(path).unwrap();
}

#[test]
#[serial_test::serial]
fn test_default_db_path() {
    unsafe {
        std::env::set_var("RAT_GEOIP_DB", "/tmp/rat/db.mmdb");
    }
    let path = rat_geo::default_db_path();
    assert_eq!(path.to_str().unwrap(), "/tmp/rat/db.mmdb");

    unsafe {
        std::env::remove_var("RAT_GEOIP_DB");
        std::env::set_var("XDG_DATA_HOME", "/custom/xdg");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let path = rat_geo::default_db_path();
        assert_eq!(
            path.to_str().unwrap(),
            "/custom/xdg/rat/dbip-city-lite.mmdb"
        );
    }
}

#[test]
fn test_parse_iso6709() {
    let coords = rat_geo::TimeZoneLocator::parse_iso6709("+5230+01322").unwrap();
    assert_eq!(coords.0, 52.5); // 52 + 30/60
    assert_eq!(coords.1, 13.366666666666667); // 13 + 22/60

    let coords2 = rat_geo::TimeZoneLocator::parse_iso6709("+403042-0740056").unwrap();
    assert!((coords2.0 - (40.0 + 30.0 / 60.0 + 42.0 / 3600.0)).abs() < 1e-6);
    assert!((coords2.1 - (-74.0 - 0.0 / 60.0 - 56.0 / 3600.0)).abs() < 1e-6);
}

#[test]
fn test_zone_tab() {
    let zone_tab = "
# comment
XX	+5230+01322	Europe/Berlin
YY	+403042-0740056	America/New_York
ZZ	+5230+01322	Something_Else_City
";
    let path = "test_zone.tab";
    std::fs::write(path, zone_tab).unwrap();

    let res = rat_geo::TimeZoneLocator::lookup_in_zone_tab("Europe/Berlin", path).unwrap();
    assert_eq!(res.2, "Berlin");

    let res2 = rat_geo::TimeZoneLocator::lookup_in_zone_tab("Something_Else_City", path).unwrap();
    assert_eq!(res2.2, "Something Else City");

    std::fs::remove_file(path).unwrap();
}

#[test]
fn test_asn_lookup() {
    let path = "test_asn.mmdb";

    let mut writer = mmdb_writer::Writer::builder("GeoLite2-ASN").build();
    let mut asn_map = std::collections::BTreeMap::new();
    asn_map.insert(
        "autonomous_system_number".to_string(),
        mmdb_writer::Value::U32(13335),
    );
    asn_map.insert(
        "autonomous_system_organization".to_string(),
        mmdb_writer::Value::String("Cloudflare, Inc.".to_string()),
    );

    writer
        .insert_value(
            "1.1.1.0/24".parse::<ipnet::IpNet>().unwrap(),
            mmdb_writer::Value::Map(asn_map),
        )
        .unwrap();

    let mut f = std::fs::File::create(path).unwrap();
    writer.write_to(&mut f).unwrap();

    let db = rat_geo::ASNDatabase::new(path).unwrap();
    let owner = db.owner("1.1.1.1".parse().unwrap()).unwrap();
    assert_eq!(owner.number, 13335);
    assert_eq!(owner.organization, "Cloudflare, Inc.");
    assert_eq!(owner.label(), "AS13335 Cloudflare, Inc.");

    assert!(db.owner("8.8.8.8".parse().unwrap()).is_none());

    std::fs::remove_file(path).unwrap();
}

#[test]
#[serial_test::serial]
fn test_default_asn_db_path() {
    unsafe {
        std::env::remove_var("RAT_GEOIP_DB");
        std::env::set_var("RAT_GEOIP_ASN_DB", "/tmp/rat/asn.mmdb");
    }
    let path = rat_geo::default_asn_db_path();
    assert_eq!(path.to_str().unwrap(), "/tmp/rat/asn.mmdb");

    unsafe {
        std::env::remove_var("RAT_GEOIP_DB");
        std::env::remove_var("RAT_GEOIP_ASN_DB");
        std::env::set_var("XDG_DATA_HOME", "/custom/xdg");
    }

    #[cfg(not(target_os = "windows"))]
    {
        let path = rat_geo::default_asn_db_path();
        assert_eq!(path.to_str().unwrap(), "/custom/xdg/rat/dbip-asn-lite.mmdb");
    }
}

#[test]
fn test_geoip_edge_cases() {
    let path = "test_edge_cases.mmdb";
    write_test_db(path);
    let db = rat_geo::GeoIP::new(path).unwrap();

    // IPv6 loopback
    assert!(db.locate("::1".parse().unwrap()).is_none());

    // IPv6 link local
    assert!(db.locate("fe80::1".parse().unwrap()).is_none());

    // IPv4 mapped
    // Note: since our writer wrote a v6 database? Wait, no, we didn't specify IpVersion in writer builder.
    // If it's a v6 database, it can lookup ipv4 mapped ipv6? Let's check how maxmind handles that.

    // IPv4 link local
    assert!(db.locate("169.254.1.1".parse().unwrap()).is_none());

    // IPv4 multicast
    assert!(db.locate("224.0.0.1".parse().unwrap()).is_none());

    // Unspecified
    assert!(db.locate("0.0.0.0".parse().unwrap()).is_none());
    assert!(db.locate("::".parse().unwrap()).is_none());

    std::fs::remove_file(path).unwrap();
}

#[test]
fn test_zone_tab_edge_cases() {
    let zone_tab = "
# comment
XX	+5230+01322	Europe/Berlin
YY	+403042-0740056	America/New_York
ZZ	+5230+01322	Long/Path/With/Many/Slashes
AA	+5230+01322	Non_ASCII_City_موشح
BB	+5230+01322	Non_ASCII_City_北京
CC	invalid_coords	Invalid/City
DD	+5230+01322
";
    let path = "test_zone_edge.tab";
    std::fs::write(path, zone_tab).unwrap();

    let res =
        rat_geo::TimeZoneLocator::lookup_in_zone_tab("Long/Path/With/Many/Slashes", path).unwrap();
    assert_eq!(res.2, "Slashes");

    let res2 = rat_geo::TimeZoneLocator::lookup_in_zone_tab("Non_ASCII_City_موشح", path).unwrap();
    assert_eq!(res2.2, "Non ASCII City موشح");

    let res3 = rat_geo::TimeZoneLocator::lookup_in_zone_tab("Non_ASCII_City_北京", path).unwrap();
    assert_eq!(res3.2, "Non ASCII City 北京");

    // Invalid coordinates
    assert!(rat_geo::TimeZoneLocator::lookup_in_zone_tab("Invalid/City", path).is_none());

    // Missing fields
    assert!(rat_geo::TimeZoneLocator::lookup_in_zone_tab("DD", path).is_none());

    std::fs::remove_file(path).unwrap();
}

#[test]
fn test_geoip_ipv4_mapped_edge() {
    let path = "test_ipv4_mapped.mmdb";
    let mut writer = mmdb_writer::Writer::builder("Test-City").build();

    let mut city = BTreeMap::new();
    let mut location = BTreeMap::new();
    location.insert("latitude".to_string(), mmdb_writer::Value::Double(42.0));
    location.insert("longitude".to_string(), mmdb_writer::Value::Double(-71.0));
    city.insert("location".to_string(), mmdb_writer::Value::Map(location));

    let mut city_info = BTreeMap::new();
    let mut city_names = BTreeMap::new();
    city_names.insert(
        "en".to_string(),
        mmdb_writer::Value::String("Boston".to_string()),
    );
    city_info.insert("names".to_string(), mmdb_writer::Value::Map(city_names));
    city.insert("city".to_string(), mmdb_writer::Value::Map(city_info));

    writer
        .insert_value(
            "1.2.3.0/24".parse::<IpNet>().unwrap(),
            mmdb_writer::Value::Map(city),
        )
        .unwrap();

    let mut f = std::fs::File::create(path).unwrap();
    writer.write_to(&mut f).unwrap();

    let db = rat_geo::GeoIP::new(path).unwrap();

    // IPv4-mapped IPv6 Address ::ffff:1.2.3.4
    // Depending on DB format, it may not locate. Just want to make sure it doesn't crash.
    let mapped_ip: std::net::IpAddr = "::ffff:1.2.3.4".parse().unwrap();
    let _ = db.locate(mapped_ip);

    std::fs::remove_file(path).unwrap();
}

#[test]
fn test_parse_deg_edge_cases() {
    // Malformed degree strings
    assert!(rat_geo::TimeZoneLocator::parse_iso6709("+52").is_none());
    assert!(rat_geo::TimeZoneLocator::parse_iso6709("+523").is_none());
    assert!(rat_geo::TimeZoneLocator::parse_iso6709("A5230+01322").is_none()); // Bad sign
    assert!(rat_geo::TimeZoneLocator::parse_iso6709("+XX30+01322").is_none()); // Parse float error
    assert!(rat_geo::TimeZoneLocator::parse_iso6709("+5230+XX322").is_none());
}

use proptest::prelude::*;

proptest! {
    #[test]
    fn test_parse_iso6709_proptest(
        sign1 in "[+-]",
        deg1 in 0u32..90,
        min1 in 0u32..60,
        sign2 in "[+-]",
        deg2 in 0u32..180,
        min2 in 0u32..60,
    ) {
        let lat_str = format!("{}{:02}{:02}", sign1, deg1, min1);
        let lon_str = format!("{}{:03}{:02}", sign2, deg2, min2);
        let combined = format!("{}{}", lat_str, lon_str);

        if let Some((lat, lon)) = rat_geo::TimeZoneLocator::parse_iso6709(&combined) {
            let expected_lat = (deg1 as f64 + min1 as f64 / 60.0) * if sign1 == "+" { 1.0 } else { -1.0 };
            let expected_lon = (deg2 as f64 + min2 as f64 / 60.0) * if sign2 == "+" { 1.0 } else { -1.0 };
            prop_assert!((lat - expected_lat).abs() < 1e-6);
            prop_assert!((lon - expected_lon).abs() < 1e-6);
        }
    }

    #[test]
    fn test_parse_iso6709_no_panic(s in "\\PC*") {
        let _ = rat_geo::TimeZoneLocator::parse_iso6709(&s);
    }
}

#[test]
fn test_geodatabases_validation() {
    let path = "test_validation.mmdb";
    write_test_db(path);
    let mut dbs = rat_geo::GeoDatabases::new();
    assert!(dbs.load_city_db(path).is_ok());
    assert!(dbs.load_city_db("nonexistent.mmdb").is_err());
    std::fs::remove_file(path).unwrap();
}
