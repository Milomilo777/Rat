use criterion::{Criterion, criterion_group, criterion_main};
use mmdb_writer::Writer;
use rat_geo::{ASNDatabase, GeoIP};
use std::hint::black_box;
use std::net::IpAddr;

fn setup_db() -> String {
    let path = "test_bench.mmdb";
    let mut writer = Writer::builder("GeoLite2-City").build();
    let mut city = std::collections::BTreeMap::new();
    let mut location = std::collections::BTreeMap::new();
    location.insert("latitude".to_string(), mmdb_writer::Value::Double(42.0));
    location.insert("longitude".to_string(), mmdb_writer::Value::Double(-71.0));
    city.insert("location".to_string(), mmdb_writer::Value::Map(location));
    writer
        .insert_value(
            "1.2.3.0/24".parse::<ipnet::IpNet>().unwrap(),
            mmdb_writer::Value::Map(city),
        )
        .unwrap();
    let mut f = std::fs::File::create(path).unwrap();
    writer.write_to(&mut f).unwrap();
    path.to_string()
}

fn bench_locate(c: &mut Criterion) {
    let path = setup_db();
    let db = GeoIP::new(&path).unwrap();
    let ip: IpAddr = "1.2.3.4".parse().unwrap();

    let mut group = c.benchmark_group("geo");
    group.bench_function("locate", |b| {
        b.iter(|| {
            black_box(db.locate(black_box(ip)));
        })
    });
    group.finish();
    std::fs::remove_file(&path).unwrap();
}

fn setup_asn_db() -> String {
    let path = "test_asn_bench.mmdb";
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
    path.to_string()
}

fn bench_asn(c: &mut Criterion) {
    let path = setup_asn_db();
    let db = ASNDatabase::new(&path).unwrap();
    let ip: IpAddr = "1.1.1.1".parse().unwrap();

    let mut group = c.benchmark_group("geo");
    group.bench_function("asn_owner", |b| {
        b.iter(|| {
            black_box(db.owner(black_box(ip)));
        })
    });
    group.finish();
    std::fs::remove_file(&path).unwrap();
}

criterion_group!(benches, bench_locate, bench_asn);
criterion_main!(benches);
