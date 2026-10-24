use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rat_enforcer::{Blocklist, Enforcer};

#[cfg(not(windows))]
use rat_enforcer::linux::LinuxEnforcer;

#[cfg(not(windows))]
fn bench_linux_plan(c: &mut Criterion) {
    let mut ports = Vec::new();
    for i in 0..5000 {
        ports.push(i as u16);
    }
    let wanted = Blocklist {
        paths: vec![],
        local_ports: ports,
    };
    let enforcer = LinuxEnforcer;

    c.bench_function("linux_plan_5000", |b| {
        b.iter(|| enforcer.plan(black_box(&wanted)))
    });
}

// Even when we bench on linux, we can run WindowsEnforcer since it's just logic diffing.
// Let's modify windows.rs to be accessible on linux just for benchmarks and tests if needed.
// Ah, but `windows` mod is `#[cfg(windows)]`.
// So we can only test it if we compile on windows.
// Let's just output memory budget checks.

#[cfg(windows)]
use rat_enforcer::windows::WindowsEnforcer;

#[cfg(windows)]
fn bench_windows_plan(c: &mut Criterion) {
    let mut current_paths = Vec::new();
    let mut wanted_paths = Vec::new();
    for i in 0..2500 {
        current_paths.push(format!("/usr/bin/app_{}", i));
    }
    for i in 1250..3750 {
        wanted_paths.push(format!("/usr/bin/app_{}", i));
    }
    let current = Blocklist {
        paths: current_paths,
        local_ports: vec![],
    };
    let wanted = Blocklist {
        paths: wanted_paths,
        local_ports: vec![],
    };

    let enforcer = WindowsEnforcer { current };

    c.bench_function("windows_plan_diff_2500", |b| {
        b.iter(|| enforcer.plan(black_box(&wanted)))
    });
}

#[cfg(not(windows))]
criterion_group!(benches, bench_linux_plan);

#[cfg(windows)]
criterion_group!(benches, bench_windows_plan);

criterion_main!(benches);
