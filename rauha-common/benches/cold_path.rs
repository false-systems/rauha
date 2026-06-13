use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rauha_common::zone::{PolicyFile, Zone, ZonePolicy, ZoneState, ZoneType};
use uuid::Uuid;

const POLICY_TOML: &str = r#"
[zone]
name = "bench-zone"
type = "non-global"

[capabilities]
allowed = ["CAP_NET_BIND_SERVICE", "CAP_CHOWN"]

[resources]
cpu_shares = 1024
memory_limit = "512Mi"
io_weight = 100
pids_max = 256

[network]
mode = "isolated"
allowed_zones = ["frontend"]
allowed_egress = ["0.0.0.0/0:443"]
allowed_ingress = []

[filesystem]
root = "/var/lib/rauha/zones/bench-zone"
shared_layers = true
writable_paths = ["/tmp", "/var/log"]

[devices]
allowed = ["/dev/null", "/dev/zero", "/dev/urandom"]

[syscalls]
deny = ["mount", "umount2"]
"#;

fn bench_policy_parse_validate(c: &mut Criterion) {
    c.bench_function("policy_parse_validate", |b| {
        b.iter(|| {
            let policy_file: PolicyFile = toml::from_str(black_box(POLICY_TOML)).unwrap();
            policy_file
                .to_zone_policy(black_box("/var/lib/rauha"))
                .unwrap()
        })
    });
}

fn bench_zone_object_construction(c: &mut Criterion) {
    c.bench_function("zone_object_construction", |b| {
        b.iter(|| {
            let now = Utc::now();
            Zone {
                id: Uuid::new_v4(),
                name: black_box("bench-zone").to_string(),
                zone_type: ZoneType::NonGlobal,
                state: ZoneState::Ready,
                policy: ZonePolicy::default(),
                created_at: now,
                updated_at: now,
                network_state: None,
            }
        })
    });
}

criterion_group!(
    cold_path,
    bench_policy_parse_validate,
    bench_zone_object_construction
);
criterion_main!(cold_path);
