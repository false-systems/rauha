//! Admit containerd's OCI configuration without relaxing the zone's controls.
use rauha_common::error::{RauhaError, Result};
use serde_json::Value;

pub(super) fn admit(json: &str, mut enforced: Value) -> Result<Value> {
    let mut spec: Value = serde_json::from_str(json)
        .map_err(|e| RauhaError::BackendError(format!("invalid OCI bundle: {e}")))?;
    let refuse = |message: &str| RauhaError::InvalidPolicy(format!("containerd bundle: {message}"));
    if !spec.is_object() || !spec["process"].is_object() || !spec["linux"].is_object() {
        return Err(refuse("requires an OCI Linux process"));
    }
    serde_json::from_value::<oci_spec::runtime::Spec>(spec.clone())
        .map_err(|e| refuse(&format!("invalid OCI specification: {e}")))?;
    if spec.get("hooks").is_some() {
        return Err(refuse("host-executed OCI hooks are not admitted"));
    }
    if spec["linux"]["rootfsPropagation"]
        .as_str()
        .is_some_and(|mode| !matches!(mode, "private" | "rprivate" | "slave" | "rslave"))
    {
        return Err(refuse("rootfs mount propagation must not modify the host"));
    }
    if let Some(annotations) = spec["annotations"].as_object_mut() {
        if annotations.iter().any(|(key, value)| {
            key.starts_with("run.oci.") && enforced["annotations"].get(key) != Some(value)
        }) {
            return Err(refuse(
                "runtime security annotations are controlled by the zone",
            ));
        }
        if let Some(required) = enforced["annotations"].as_object() {
            annotations.extend(required.clone());
        }
    } else if let Some(required) = enforced.get("annotations") {
        spec["annotations"] = required.clone();
    }
    for kind in [
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
    ] {
        if let Some(requested) = spec["process"]["capabilities"][kind].as_array_mut() {
            let allowed = enforced["process"]["capabilities"][kind].as_array();
            requested.retain(|cap| allowed.is_some_and(|set| set.contains(cap)));
        }
    }
    if let Some(namespaces) = spec["linux"]["namespaces"].as_array() {
        for ns in namespaces {
            if let Some(path) = ns
                .get("path")
                .filter(|p| !p.as_str().unwrap_or("").is_empty())
            {
                let allowed = enforced["linux"]["namespaces"]
                    .as_array()
                    .is_some_and(|set| {
                        set.iter().any(|n| {
                            n["type"] == ns["type"]
                                && (n.get("path") == Some(path)
                                    || same_namespace(n["path"].as_str(), path.as_str()))
                        })
                    });
                if !allowed {
                    return Err(refuse(
                        "joining namespaces outside the zone is not admitted",
                    ));
                }
            }
        }
    }
    if let Some(devices) = spec["linux"]["devices"].as_array() {
        let allowed = enforced["linux"]["devices"].as_array();
        if devices
            .iter()
            .any(|d| !allowed.is_some_and(|set| set.contains(d)))
        {
            return Err(refuse("requested devices exceed zone policy"));
        }
    }
    constrain_devices(&mut spec, &enforced)?;
    if let Some(mounts) = spec["mounts"].as_array() {
        let allowed = enforced["mounts"]
            .as_array_mut()
            .ok_or_else(|| refuse("zone mounts missing"))?;
        for mount in mounts {
            // The zone never exposes the host's cgroup hierarchy.
            if mount["destination"] == "/sys/fs/cgroup"
                && (mount["type"] == "cgroup" || mount["type"] == "cgroup2")
            {
                continue;
            }
            // A nonempty writable image directory is normally copied into a
            // private bind. An explicit tmpfs request instead asks to hide that
            // content; keep its size/options rather than silently using the bind.
            if mount["type"] == "tmpfs" && mount["source"] == "tmpfs" {
                if let Some(zone_mount) = allowed.iter_mut().find(|zone_mount| {
                    zone_mount["destination"] == mount["destination"]
                        && zone_mount["type"] == "bind"
                        && zone_mount["options"].as_array().is_some_and(|options| {
                            options.iter().any(|option| option == "rw")
                                && !options.iter().any(|option| option == "ro")
                        })
                }) {
                    let mut requested = mount.clone();
                    let options = requested["options"]
                        .as_array_mut()
                        .ok_or_else(|| refuse("tmpfs mount options are missing"))?;
                    let mut admitted_options = zone_mount["options"].as_array().unwrap().clone();
                    intersect_tmpfs_limits(options, &mut admitted_options)?;
                    if options.iter().any(|option| option == "ro")
                        && options.iter().any(|option| option == "rw")
                    {
                        return Err(refuse("tmpfs cannot override a readonly restriction"));
                    }
                    if options.iter().any(|option| {
                        matches!(
                            option.as_str(),
                            Some(
                                "shared"
                                    | "rshared"
                                    | "slave"
                                    | "rslave"
                                    | "bind"
                                    | "rbind"
                                    | "remount"
                                    | "move"
                            )
                        )
                    }) {
                        return Err(refuse(
                            "tmpfs cannot bind an existing mount or propagate to the host",
                        ));
                    }
                    for flag in ["nosuid", "nodev", "noexec"] {
                        let required = flag != "noexec"
                            || zone_mount["options"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|option| option == flag);
                        if required {
                            options.retain(|option| option != flag);
                            options.push(flag.into());
                        }
                    }
                    *zone_mount = requested;
                }
            }
            if let Some(zone_mount) = allowed.iter_mut().find(|m| {
                m["destination"] == mount["destination"]
                    && m["type"] == mount["type"]
                    && m["source"] == mount["source"]
            }) {
                // Preserve caller restrictions while retaining the zone's required flags.
                if let Some(options) = mount["options"].as_array() {
                    if zone_mount["options"].is_null() {
                        zone_mount["options"] = Value::Array(Vec::new());
                    }
                    let enforced_options = zone_mount["options"]
                        .as_array_mut()
                        .ok_or_else(|| refuse("zone mount options missing"))?;
                    for option in options {
                        if matches!(
                            option.as_str(),
                            Some("ro" | "noexec" | "nosuid" | "nodev" | "nosymfollow")
                        ) && !enforced_options.contains(option)
                        {
                            enforced_options.push(option.clone());
                        }
                    }
                    if mount["type"] == "tmpfs" {
                        intersect_tmpfs_limits(options, enforced_options)?;
                    } else {
                        for option in options {
                            if !enforced_options.contains(option)
                                && !matches!(
                                    option.as_str(),
                                    Some(
                                        "rw" | "exec"
                                            | "suid"
                                            | "dev"
                                            | "strictatime"
                                            | "relatime"
                                            | "noatime"
                                            | "nodiratime"
                                            | "lazytime"
                                    )
                                )
                            {
                                return Err(refuse(&format!(
                                    "mount option {option} at {} is not represented in zone policy",
                                    mount["destination"]
                                )));
                            }
                        }
                    }
                }
            } else {
                let destination = mount["destination"]
                    .as_str()
                    .ok_or_else(|| refuse("mount destination is missing"))?;
                let source = mount["source"]
                    .as_str()
                    .ok_or_else(|| refuse("mount source is missing"))?;
                let options = mount["options"]
                    .as_array()
                    .ok_or_else(|| refuse("bind mount options are missing"))?;
                let absolute = |path: &str| {
                    std::path::Path::new(path).is_absolute()
                        && std::path::Path::new(path).components().all(|component| {
                            matches!(
                                component,
                                std::path::Component::RootDir | std::path::Component::Normal(_)
                            )
                        })
                };
                if mount["type"] != "bind"
                    || !absolute(destination)
                    || destination == "/"
                    || !absolute(source)
                    || !options
                        .iter()
                        .any(|option| option == "bind" || option == "rbind")
                {
                    return Err(refuse(&format!(
                        "mount at {destination:?} (type {}, source {source:?}) requires an absolute bind or a zone-admitted virtual mount",
                        mount["type"]
                    )));
                }
                let readonly = options.iter().any(|option| option == "ro");
                if options.iter().any(|option| {
                    matches!(
                        option.as_str(),
                        Some("shared" | "rshared" | "slave" | "rslave")
                    )
                }) || readonly && options.iter().any(|option| option == "rw")
                {
                    return Err(refuse("bind mounts cannot propagate to the host or override readonly restrictions"));
                }
                let writable = allowed.iter().any(|zone_mount| {
                    let Some(path) = zone_mount["destination"].as_str() else {
                        return false;
                    };
                    !matches!(path, "/proc" | "/dev" | "/dev/pts" | "/dev/mqueue" | "/sys")
                        && (destination == path
                            || destination
                                .strip_prefix(path)
                                .is_some_and(|tail| tail.starts_with('/')))
                        && zone_mount["options"]
                            .as_array()
                            .is_some_and(|options| !options.iter().any(|option| option == "ro"))
                });
                if !readonly && !writable {
                    return Err(refuse(
                        "writable bind mounts require a zone-declared writable destination",
                    ));
                }
                let mut admitted = mount.clone();
                let options = admitted["options"].as_array_mut().unwrap();
                if readonly
                    && options.iter().any(|option| option == "rbind")
                    && !options.iter().any(|option| option == "rro")
                {
                    options.push("rro".into());
                }
                if allowed.iter().any(|zone_mount| {
                    zone_mount["destination"].as_str().is_some_and(|path| {
                        (destination == path
                            || destination
                                .strip_prefix(path)
                                .is_some_and(|tail| tail.starts_with('/')))
                            && zone_mount["options"].as_array().is_some_and(|options| {
                                options.iter().any(|option| option == "noexec")
                            })
                    })
                }) {
                    options.push("noexec".into());
                }
                for flag in ["nosuid", "nodev"] {
                    if !options.iter().any(|option| option == flag) {
                        options.push(flag.into());
                    }
                }
                allowed.push(admitted);
            }
        }
    }
    // Keep the caller's user, argv, environment, cwd, rlimits and annotations.
    spec["root"] = enforced["root"].clone();
    spec["mounts"] = enforced["mounts"].clone();
    spec["process"]["noNewPrivileges"] = Value::Bool(true);
    spec["linux"]["namespaces"] = enforced["linux"]["namespaces"].clone();
    spec["linux"]["devices"] = enforced["linux"]["devices"].clone();
    if let Some(seccomp) = enforced["linux"].get("seccomp") {
        spec["linux"]["seccomp"] = match spec["linux"].get("seccomp") {
            Some(requested) => compose_seccomp(requested, seccomp)?,
            None => seccomp.clone(),
        };
    }
    spec["linux"].as_object_mut().unwrap().remove("cgroupsPath");
    Ok(spec)
}

fn intersect_tmpfs_limits(caller: &[Value], zone: &mut Vec<Value>) -> Result<()> {
    for option in caller.iter().filter_map(Value::as_str) {
        if matches!(
            option,
            "ro" | "rw"
                | "noexec"
                | "exec"
                | "nosuid"
                | "suid"
                | "nodev"
                | "dev"
                | "nosymfollow"
                | "strictatime"
                | "relatime"
                | "noatime"
                | "nodiratime"
                | "lazytime"
        ) || ["size=", "nr_inodes=", "mode="]
            .iter()
            .any(|prefix| option.starts_with(prefix))
            || zone.iter().any(|existing| existing == option)
        {
            continue;
        }
        return Err(RauhaError::InvalidPolicy(format!("containerd tmpfs option {option:?} conflicts with or is not represented in zone policy")));
    }
    let requested_mode = caller
        .iter()
        .rev()
        .filter_map(Value::as_str)
        .find_map(|option| option.strip_prefix("mode="));
    if let Some(requested_mode) = requested_mode {
        let zone_mode = zone
            .iter()
            .rev()
            .filter_map(Value::as_str)
            .find_map(|option| option.strip_prefix("mode="))
            .unwrap_or("1777");
        let mode = |value: &str| {
            u32::from_str_radix(value, 8)
                .ok()
                .filter(|mode| *mode <= 0o7777)
                .ok_or_else(|| RauhaError::InvalidPolicy(format!("invalid tmpfs mode {value:?}")))
        };
        let requested_mode = mode(requested_mode)?;
        let zone_mode = mode(zone_mode)?;
        let admitted = (requested_mode & zone_mode) | ((requested_mode | zone_mode) & 0o1000);
        zone.retain(|option| {
            !option
                .as_str()
                .is_some_and(|option| option.starts_with("mode="))
        });
        zone.push(format!("mode={admitted:o}").into());
    }
    for prefix in ["size=", "nr_inodes="] {
        let last_limit = |options: &[Value]| {
            options
                .iter()
                .rev()
                .filter_map(Value::as_str)
                .find_map(|option| option.strip_prefix(prefix).map(str::to_owned))
        };
        let Some(requested) = last_limit(caller) else {
            continue;
        };
        let requested = tmpfs_limit(&requested)?;
        let admitted = match last_limit(zone) {
            Some(limit) => {
                let limit = tmpfs_limit(&limit)?;
                match (requested, limit) {
                    (0, limit) => limit,
                    (requested, 0) => requested,
                    (requested, limit) => requested.min(limit),
                }
            }
            None => requested,
        };
        zone.retain(|option| {
            !option
                .as_str()
                .is_some_and(|option| option.starts_with(prefix))
        });
        zone.push(format!("{prefix}{admitted}").into());
    }
    Ok(())
}

fn tmpfs_limit(value: &str) -> Result<u64> {
    let invalid = || {
        RauhaError::InvalidPolicy(format!("containerd tmpfs limit {value:?} must be an absolute byte/inode count, optionally suffixed K/M/G/T/P/E"))
    };
    let (digits, shift) = match value.as_bytes().last().map(u8::to_ascii_lowercase) {
        Some(b'k') => (&value[..value.len() - 1], 10),
        Some(b'm') => (&value[..value.len() - 1], 20),
        Some(b'g') => (&value[..value.len() - 1], 30),
        Some(b't') => (&value[..value.len() - 1], 40),
        Some(b'p') => (&value[..value.len() - 1], 50),
        Some(b'e') => (&value[..value.len() - 1], 60),
        _ => (value, 0),
    };
    let (digits, radix) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (hex, 16)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (digits, 8)
    } else {
        (digits, 10)
    };
    if digits.is_empty() || digits.starts_with(['+', '-']) {
        return Err(invalid());
    }
    u64::from_str_radix(digits, radix)
        .ok()
        .and_then(|number| number.checked_mul(1u64 << shift))
        .ok_or_else(invalid)
}

pub(super) fn constrain_devices(spec: &mut Value, enforced: &Value) -> Result<()> {
    let requested = spec["linux"]["resources"]["devices"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut rules = vec![serde_json::json!({"allow":false,"access":"rwm"})];
    for device in enforced["linux"]["devices"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let mut access = String::new();
        for bit in ['r', 'w', 'm'] {
            let mut permitted = true;
            for rule in &requested {
                if rule["type"]
                    .as_str()
                    .is_none_or(|kind| kind == "a" || device["type"] == kind)
                    && rule
                        .get("major")
                        .is_none_or(|major| major.is_null() || major == &device["major"])
                    && rule
                        .get("minor")
                        .is_none_or(|minor| minor.is_null() || minor == &device["minor"])
                    && rule["access"]
                        .as_str()
                        .is_some_and(|access| access.contains(bit))
                {
                    permitted = rule["allow"].as_bool().ok_or_else(|| {
                        RauhaError::InvalidPolicy("device rule requires allow boolean".into())
                    })?;
                }
            }
            if permitted {
                access.push(bit);
            }
        }
        if !access.is_empty() {
            rules.push(serde_json::json!({"allow":true,"type":device["type"],"major":device["major"],"minor":device["minor"],"access":access}));
        }
    }
    if spec["linux"].get("resources").is_none() {
        spec["linux"]["resources"] = serde_json::json!({});
    }
    spec["linux"]["resources"]["devices"] = rules.into();
    Ok(())
}

fn compose_seccomp(requested: &Value, enforced: &Value) -> Result<Value> {
    let refuse =
        |message: &str| RauhaError::InvalidPolicy(format!("containerd seccomp: {message}"));
    if requested == enforced {
        return Ok(requested.clone());
    }
    if requested.get("listenerPath").is_some() || requested.get("listenerMetadata").is_some() {
        return Err(refuse("notification listeners are controlled by the zone"));
    }
    if !matches!(
        requested["defaultAction"].as_str(),
        Some(
            "SCMP_ACT_ALLOW"
                | "SCMP_ACT_ERRNO"
                | "SCMP_ACT_KILL"
                | "SCMP_ACT_KILL_PROCESS"
                | "SCMP_ACT_KILL_THREAD"
        )
    ) {
        return Err(refuse(
            "unsupported default action for zone filter composition",
        ));
    }
    let default_allow = requested["defaultAction"] == "SCMP_ACT_ALLOW";
    let mut result = requested.clone();
    let rules = result
        .as_object_mut()
        .ok_or_else(|| refuse("filter must be an object"))?
        .entry("syscalls")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| refuse("syscalls must be an array"))?;
    if rules.iter().any(|rule| {
        !matches!(
            rule["action"].as_str(),
            Some(
                "SCMP_ACT_ALLOW"
                    | "SCMP_ACT_ERRNO"
                    | "SCMP_ACT_KILL"
                    | "SCMP_ACT_KILL_PROCESS"
                    | "SCMP_ACT_KILL_THREAD"
                    | "SCMP_ACT_TRAP"
            )
        )
    }) {
        return Err(refuse("requested syscall actions must allow or deny; tracing and notification are zone-controlled"));
    }
    for zone_rule in enforced["syscalls"]
        .as_array()
        .ok_or_else(|| refuse("invalid zone filter"))?
    {
        let zone_names = zone_rule["names"]
            .as_array()
            .ok_or_else(|| refuse("invalid zone syscall names"))?;
        if zone_rule["args"]
            .as_array()
            .is_some_and(|args| !args.is_empty())
        {
            return Err(refuse(
                "conditional zone rules require separate filter stacking",
            ));
        }
        let mut extra = Vec::new();
        for rule in rules.iter_mut() {
            let names = rule["names"]
                .as_array()
                .ok_or_else(|| refuse("invalid requested syscall names"))?;
            let restricted: Vec<_> = names
                .iter()
                .filter(|name| zone_names.contains(name))
                .cloned()
                .collect();
            if restricted.is_empty() {
                continue;
            }
            if rule["action"] == "SCMP_ACT_ALLOW" {
                if zone_rule["action"] == "SCMP_ACT_NOTIFY" && !default_allow {
                    let mut notification = rule.clone();
                    notification["names"] = restricted.into();
                    notification["action"] = "SCMP_ACT_NOTIFY".into();
                    notification.as_object_mut().unwrap().remove("errnoRet");
                    extra.push(notification);
                }
                rule["names"]
                    .as_array_mut()
                    .unwrap()
                    .retain(|name| !zone_names.contains(name));
            } else if default_allow {
                // Combining overlapping conditional actions needs separate BPF filters.
                return Err(refuse(
                    "overlapping deny rules with an allow default cannot be composed",
                ));
            }
        }
        rules.retain(|rule| !rule["names"].as_array().is_some_and(Vec::is_empty));
        rules.extend(extra);
        if default_allow {
            rules.push(zone_rule.clone());
        }
    }
    if let Some(path) = enforced.get("listenerPath") {
        result["listenerPath"] = path.clone();
    }
    if let Some(metadata) = enforced.get("listenerMetadata") {
        result["listenerMetadata"] = metadata.clone();
    }
    Ok(result)
}

fn same_namespace(left: Option<&str>, right: Option<&str>) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.zip(right).is_some_and(|(left, right)| {
        std::fs::metadata(left)
            .ok()
            .zip(std::fs::metadata(right).ok())
            .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tmpfs_limits_preserve_the_smaller_caller_or_zone_bound() {
        for (caller, zone, expected) in [
            ("4m", "64m", 4 << 20),
            ("64m", "4m", 4 << 20),
            ("0", "4m", 4 << 20),
            ("4m", "0", 4 << 20),
            ("010", "16", 8),
        ] {
            let mut zone = vec![json!(format!("size={zone}")), json!("nr_inodes=20")];
            intersect_tmpfs_limits(
                &[json!(format!("size={caller}")), json!("nr_inodes=10")],
                &mut zone,
            )
            .unwrap();
            assert!(zone.contains(&json!(format!("size={expected}"))));
            assert!(zone.contains(&json!("nr_inodes=10")));
        }
        assert!(
            intersect_tmpfs_limits(&[json!("size=50%")], &mut vec![json!("size=64m")]).is_err()
        );
        assert!(tmpfs_limit("18446744073709551615E").is_err());
    }

    #[test]
    fn tmpfs_modes_intersect_and_unknown_options_do_not_disappear() {
        for (caller, zone, expected) in [
            ("000", "755", "0"),
            ("755", "700", "700"),
            ("1777", "755", "1755"),
        ] {
            let mut zone = vec![json!(format!("mode={zone}"))];
            intersect_tmpfs_limits(&[json!(format!("mode={caller}"))], &mut zone).unwrap();
            assert_eq!(zone, vec![json!(format!("mode={expected}"))]);
        }
        assert!(intersect_tmpfs_limits(&[json!("uid=123")], &mut vec![json!("uid=0")]).is_err());
        assert!(intersect_tmpfs_limits(&[json!("unknown-option")], &mut vec![]).is_err());
    }

    #[test]
    fn caller_tmpfs_replaces_only_an_admitted_writable_copy_up() {
        let enforced = json!({"root":{"path":"/private/root","readonly":true},"process":{"capabilities":{}},"mounts":[
            {"destination":"/run","source":"/private/writable/run","type":"bind","options":["rw","noexec"]}
        ],"linux":{"namespaces":[],"devices":[]}});
        let mut spec = json!({"process":{"args":["/bin/true"],"cwd":"/","user":{"uid":0,"gid":0}},"linux":{},"mounts":[
            {"destination":"/run","source":"tmpfs","type":"tmpfs","options":["size=4096k","mode=755","nosuid","suid","nodev","dev","noexec","exec"]}
        ]});
        let admitted = admit(&spec.to_string(), enforced.clone()).unwrap();
        let mount = &admitted["mounts"][0];
        assert_eq!(mount["type"], "tmpfs");
        for option in ["size=4194304", "mode=755", "nosuid", "nodev", "noexec"] {
            assert!(mount["options"]
                .as_array()
                .unwrap()
                .contains(&json!(option)));
        }
        let options = mount["options"].as_array().unwrap();
        for (restrictive, permissive) in [("nosuid", "suid"), ("nodev", "dev"), ("noexec", "exec")]
        {
            assert!(
                options
                    .iter()
                    .rposition(|option| option == restrictive)
                    .unwrap()
                    > options
                        .iter()
                        .rposition(|option| option == permissive)
                        .unwrap()
            );
        }
        spec["mounts"][0]["destination"] = json!("/unapproved");
        assert!(admit(&spec.to_string(), enforced.clone()).is_err());
        spec["mounts"][0]["destination"] = json!("/run");
        spec["mounts"][0]["options"] = json!(["bind"]);
        assert!(admit(&spec.to_string(), enforced).is_err());
    }

    #[test]
    fn virtual_mount_without_zone_options_retains_caller_restrictions() {
        let enforced = json!({"root":{"path":"/private/root","readonly":true},"process":{"capabilities":{}},"mounts":[
            {"destination":"/proc","source":"proc","type":"proc"}
        ],"linux":{"namespaces":[],"devices":[]}});
        let spec = json!({"process":{"args":["/bin/true"],"cwd":"/","user":{"uid":0,"gid":0}},"linux":{},"mounts":[
            {"destination":"/proc","source":"proc","type":"proc","options":["nosuid","nodev","noexec","nosymfollow"]}
        ]});
        let admitted = admit(&spec.to_string(), enforced).unwrap();
        assert_eq!(
            admitted["mounts"][0]["options"],
            spec["mounts"][0]["options"]
        );
    }

    #[test]
    fn device_rules_intersect_both_allowlists() {
        let enforced = json!({"linux":{"devices":[
            {"type":"c","major":1,"minor":3}, {"type":"c","major":1,"minor":5}
        ]}});
        let mut spec = json!({"linux":{"resources":{"memory":{"limit":1024},"devices":[
            {"allow":false,"access":"rwm"},
            {"allow":true,"type":"c","major":1,"minor":3,"access":"r"},
            {"allow":true,"type":"b","major":8,"minor":0,"access":"rwm"}
        ]}}});
        constrain_devices(&mut spec, &enforced).unwrap();
        assert_eq!(spec["linux"]["resources"]["memory"]["limit"], 1024);
        assert_eq!(
            spec["linux"]["resources"]["devices"],
            json!([
                {"allow":false,"access":"rwm"},
                {"allow":true,"type":"c","major":1,"minor":3,"access":"r"}
            ])
        );
    }

    #[test]
    fn read_only_volumes_stay_read_only_recursively() {
        let enforced = json!({"root":{"path":"/private/root","readonly":true},"process":{"capabilities":{}},"mounts":[],"linux":{"namespaces":[],"devices":[]}});
        let mut spec = json!({"process":{"args":["/bin/true"],"cwd":"/","user":{"uid":0,"gid":0}},"linux":{},"mounts":[
            {"destination":"/volume","source":"/host-data","type":"bind","options":["rbind","ro"]}
        ]});
        let admitted = admit(&spec.to_string(), enforced.clone()).unwrap();
        let options = admitted["mounts"][0]["options"].as_array().unwrap();
        assert!(options.contains(&json!("rro")));
        assert!(options.contains(&json!("nosuid")));
        spec["mounts"][0]["options"] = json!(["rbind", "ro", "rw"]);
        assert!(admit(&spec.to_string(), enforced.clone()).is_err());
        spec["mounts"][0]["options"] = json!(["rbind", "rw"]);
        assert!(admit(&spec.to_string(), enforced).is_err());
    }

    #[test]
    fn zone_denials_remove_grants_without_erasing_caller_restrictions() {
        let caller = json!({"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":13,"syscalls":[
            {"names":["read","write","mount"],"action":"SCMP_ACT_ALLOW"},
            {"names":["ptrace"],"action":"SCMP_ACT_TRAP"}
        ]});
        let zone = json!({"defaultAction":"SCMP_ACT_ALLOW","syscalls":[
            {"names":["mount","ptrace"],"action":"SCMP_ACT_ERRNO","errnoRet":1}
        ]});
        let composed = compose_seccomp(&caller, &zone).unwrap();
        assert_eq!(composed["defaultErrnoRet"], 13);
        assert_eq!(composed["syscalls"][0]["names"], json!(["read", "write"]));
        assert_eq!(composed["syscalls"][1], caller["syscalls"][1]);
        let mut unsafe_filter = caller;
        unsafe_filter["syscalls"][0]["action"] = "SCMP_ACT_LOG".into();
        assert!(compose_seccomp(&unsafe_filter, &zone).is_err());
    }

    #[test]
    fn broker_composition_preserves_conditional_arguments() {
        let caller = json!({"defaultAction":"SCMP_ACT_ERRNO","syscalls":[
            {"names":["openat"],"action":"SCMP_ACT_ALLOW","args":[{"index":2,"value":0,"op":"SCMP_CMP_EQ"}]}
        ]});
        let zone = json!({"defaultAction":"SCMP_ACT_ALLOW","listenerPath":"/private/broker.sock","syscalls":[
            {"names":["openat"],"action":"SCMP_ACT_NOTIFY"}
        ]});
        let composed = compose_seccomp(&caller, &zone).unwrap();
        assert_eq!(composed["syscalls"][0]["action"], "SCMP_ACT_NOTIFY");
        assert_eq!(
            composed["syscalls"][0]["args"],
            caller["syscalls"][0]["args"]
        );
        assert_eq!(composed["listenerPath"], zone["listenerPath"]);
    }

    #[test]
    fn preserves_process_but_refuses_privilege_and_mount_changes() {
        let enforced = json!({"root":{"path":"/private/root","readonly":true},"process":{"capabilities":{"bounding":[]}},"mounts":[],"linux":{"namespaces":[],"devices":[]}});
        let spec = json!({"process":{"args":["/bin/sh","-c","exit 7"],"cwd":"/","user":{"uid":123,"gid":456}},"linux":{}});
        let admitted = admit(&spec.to_string(), enforced.clone()).unwrap();
        assert_eq!(admitted["process"]["args"], spec["process"]["args"]);
        assert_eq!(admitted["process"]["user"], spec["process"]["user"]);
        assert_eq!(admitted["root"]["readonly"], true);
        assert_eq!(admitted["process"]["noNewPrivileges"], true);
        for patch in [
            json!({"hooks":{}}),
            json!({"mounts":[{"destination":"/host","source":"/"}]}),
            json!({"linux":{"namespaces":[{"type":"network","path":"/proc/1/ns/net"}]}}),
        ] {
            let mut invalid = spec.clone();
            invalid
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert!(admit(&invalid.to_string(), enforced.clone()).is_err());
        }
        let mut requested = spec;
        requested["process"]["capabilities"] = json!({"bounding":["CAP_SYS_ADMIN"]});
        assert_eq!(
            admit(&requested.to_string(), enforced).unwrap()["process"]["capabilities"]["bounding"],
            json!([])
        );
    }
}
