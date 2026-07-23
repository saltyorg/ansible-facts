use criterion::{criterion_group, criterion_main, Criterion};
use saltbox_facts::{
    has_global_ipv6_from_if_inet6, parse_groups_reader, parse_users_reader,
    timezone_from_etc_timezone, timezone_from_localtime_target,
};
use std::hint::black_box;
use std::io::Cursor;
use std::path::Path;

fn benches(c: &mut Criterion) {
    let if_inet6_sample = "\
fe800000000000000000000000000001 02 40 20 80 eth0
2a0104f9c014e6d90000000000000001 02 40 00 80 eth0
";
    c.bench_function("has_global_ipv6_from_if_inet6", |b| {
        b.iter(|| black_box(has_global_ipv6_from_if_inet6(black_box(if_inet6_sample))))
    });

    c.bench_function("timezone_from_etc_timezone", |b| {
        b.iter(|| black_box(timezone_from_etc_timezone(black_box("Europe/Copenhagen\n"))))
    });

    let localtime_target = Path::new("/usr/share/zoneinfo/Europe/Copenhagen");
    c.bench_function("timezone_from_localtime_target", |b| {
        b.iter(|| black_box(timezone_from_localtime_target(black_box(localtime_target))))
    });

    let mut groups = String::new();
    for i in 0..1000 {
        let _ = std::fmt::Write::write_fmt(
            &mut groups,
            format_args!("group{i}:x:{i}:user{i},user{}\n", i + 1),
        );
    }
    c.bench_function("parse_groups_content_1000", |b| {
        b.iter(|| {
            black_box(parse_groups_reader(Cursor::new(black_box(groups.as_bytes()))).unwrap())
        })
    });

    let mut users = String::new();
    for i in 0..1000 {
        let _ = std::fmt::Write::write_fmt(
            &mut users,
            format_args!("user{i}:x:{i}:{i}:User {i}:/home/user{i}:/bin/bash\n"),
        );
    }
    c.bench_function("parse_users_content_1000", |b| {
        b.iter(|| black_box(parse_users_reader(Cursor::new(black_box(users.as_bytes()))).unwrap()))
    });
}

criterion_group!(local_paths, benches);
criterion_main!(local_paths);
