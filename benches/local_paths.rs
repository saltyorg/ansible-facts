use criterion::{criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::hint::black_box;
use std::path::Path;

fn has_global_ipv6_from_if_inet6(content: &str) -> bool {
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_), Some(_), Some(_), Some(scope), Some(_), Some(_)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if scope == "00" {
            return true;
        }
    }
    false
}

fn timezone_from_etc_timezone(content: &str) -> Option<String> {
    let tz = content.trim();
    if tz.is_empty() {
        None
    } else {
        Some(tz.to_string())
    }
}

fn timezone_from_localtime_target(target: &Path) -> Option<String> {
    let target_str = target.to_string_lossy();
    target_str
        .find("zoneinfo/")
        .and_then(|index| target_str.get(index + "zoneinfo/".len()..))
        .map(str::trim)
        .filter(|tz| !tz.is_empty())
        .map(str::to_string)
}

fn parse_groups_content(content: &str) -> HashMap<String, (&str, Vec<String>)> {
    let mut data = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split(':');
        let (Some(name), Some(_), Some(gid)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let group_list = parts.next().map_or_else(Vec::new, |members| {
            members.split(',').map(String::from).collect::<Vec<_>>()
        });
        data.insert(name.to_string(), (gid, group_list));
    }
    data
}

fn parse_users_content(content: &str) -> HashMap<String, [&str; 5]> {
    let mut data = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split(':');
        let (Some(name), Some(_), Some(uid), Some(gid), Some(comment), Some(home), Some(shell)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        data.insert(name.to_string(), [uid, gid, comment, home, shell]);
    }
    data
}

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
            format_args!("group{}:x:{}:user{},user{}\n", i, i, i, i + 1),
        );
    }
    c.bench_function("parse_groups_content_1000", |b| {
        b.iter(|| black_box(parse_groups_content(black_box(&groups))))
    });

    let mut users = String::new();
    for i in 0..1000 {
        let _ = std::fmt::Write::write_fmt(
            &mut users,
            format_args!(
                "user{}:x:{}:{}:User {}:/home/user{}:/bin/bash\n",
                i, i, i, i, i
            ),
        );
    }
    c.bench_function("parse_users_content_1000", |b| {
        b.iter(|| black_box(parse_users_content(black_box(&users))))
    });
}

criterion_group!(local_paths, benches);
criterion_main!(local_paths);
