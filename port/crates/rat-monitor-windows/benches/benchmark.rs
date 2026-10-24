use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rat_monitor_windows::{parse_port, convert_ipv4_addr, extract_process_name_from_path, check_is_vpn_interface_type};

pub fn bench_parse_port(c: &mut Criterion) {
    c.bench_function("parse_port", |b| b.iter(|| parse_port(black_box(13056))));
}

pub fn bench_convert_ipv4(c: &mut Criterion) {
    c.bench_function("convert_ipv4", |b| b.iter(|| convert_ipv4_addr(black_box(16777343))));
}

pub fn bench_extract_process_name(c: &mut Criterion) {
    c.bench_function("extract_process_name", |b| {
        let p = std::path::Path::new(r"C:\Program Files\App\app.exe");
        b.iter(|| extract_process_name_from_path(black_box(Some(p))))
    });
}

pub fn bench_check_is_vpn(c: &mut Criterion) {
    c.bench_function("check_is_vpn", |b| {
        b.iter(|| check_is_vpn_interface_type(black_box(53), black_box("Wintun Userspace Tunnel")))
    });
}

criterion_group!(benches, bench_parse_port, bench_convert_ipv4, bench_extract_process_name, bench_check_is_vpn);
criterion_main!(benches);
