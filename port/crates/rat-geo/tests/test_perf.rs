use mmdb_writer::Writer;
use rat_geo::{ASNDatabase, GeoIP};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Instant;

fn write_test_db(path: &str) {
    let mut writer = Writer::builder("GeoLite2-City").build();

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
            "1.2.3.0/24".parse::<ipnet::IpNet>().unwrap(),
            mmdb_writer::Value::Map(city),
        )
        .unwrap();

    let mut f = std::fs::File::create(path).unwrap();
    writer.write_to(&mut f).unwrap();
}

fn setup_asn_db(path: &str) {
    let mut writer = Writer::builder("GeoLite2-ASN").build();
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
}

#[test]
fn test_perf_budget() {
    // We set an explicit budget of 5us per lookup.
    // The test will fail if it takes more than 3x the budget (15us per lookup).
    // For 10,000 lookups, the budget is 50ms, and failure threshold is 150ms.
    let path = "test_perf.mmdb";
    write_test_db(path);
    let db = GeoIP::new(path).unwrap();

    let ip: IpAddr = "1.2.3.4".parse().unwrap();

    let start = Instant::now();
    for _ in 0..10_000 {
        let _ = db.locate(ip);
    }
    let elapsed = start.elapsed();

    println!("10,000 GeoIP lookups took {:?}", elapsed);
    assert!(
        elapsed.as_millis() < 150,
        "GeoIP lookup budget exceeded by more than 3x (took {:?})",
        elapsed
    );

    std::fs::remove_file(path).unwrap();

    let asn_path = "test_asn_perf.mmdb";
    setup_asn_db(asn_path);
    let asn_db = ASNDatabase::new(asn_path).unwrap();
    let asn_ip: IpAddr = "1.1.1.1".parse().unwrap();

    let start = Instant::now();
    for _ in 0..10_000 {
        let _ = asn_db.owner(asn_ip);
    }
    let elapsed = start.elapsed();

    println!("10,000 ASN lookups took {:?}", elapsed);
    assert!(
        elapsed.as_millis() < 150,
        "ASN lookup budget exceeded by more than 3x (took {:?})",
        elapsed
    );

    std::fs::remove_file(asn_path).unwrap();
}
