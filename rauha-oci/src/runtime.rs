use oci_spec::runtime::{
    LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType, MountBuilder, ProcessBuilder,
    RootBuilder, Spec, SpecBuilder,
};
use rauha_common::container::ContainerSpec;
use rauha_common::error::RauhaError;
use rauha_common::zone::ZonePolicy;

use crate::distribution::OciImageConfig;

/// Generate an OCI runtime spec by merging image config, container spec, and zone policy.
pub fn generate_spec(
    image_config: &OciImageConfig,
    container_spec: &ContainerSpec,
    _policy: &ZonePolicy,
    rootfs_path: &str,
) -> Result<Spec, RauhaError> {
    let img = image_config.config.as_ref();

    // Determine command: container spec overrides image defaults.
    let args = if !container_spec.command.is_empty() {
        container_spec.command.clone()
    } else {
        let mut cmd = Vec::new();
        if let Some(ep) = img.and_then(|c| c.entrypoint.as_ref()) {
            cmd.extend(ep.iter().cloned());
        }
        if let Some(c) = img.and_then(|c| c.cmd.as_ref()) {
            cmd.extend(c.iter().cloned());
        }
        if cmd.is_empty() {
            vec!["/bin/sh".to_string()]
        } else {
            cmd
        }
    };

    // Merge environment variables: image defaults + container overrides.
    let mut env: Vec<String> = img
        .and_then(|c| c.env.as_ref())
        .cloned()
        .unwrap_or_default();
    for (k, v) in &container_spec.env {
        // Override existing or add new.
        let key_prefix = format!("{k}=");
        if let Some(pos) = env.iter().position(|e| e.starts_with(&key_prefix)) {
            env[pos] = format!("{k}={v}");
        } else {
            env.push(format!("{k}={v}"));
        }
    }
    // Ensure PATH is set.
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    }

    // Working directory.
    let cwd = container_spec
        .working_dir
        .as_deref()
        .or_else(|| img.and_then(|c| c.working_dir.as_deref()))
        .unwrap_or("/")
        .to_string();

    // Build process spec.
    let process = ProcessBuilder::default()
        .args(args)
        .env(env)
        .cwd(cwd)
        .terminal(false)
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build process spec: {e}")))?;

    // Root filesystem.
    let root = RootBuilder::default()
        .path(rootfs_path)
        .readonly(false)
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build root spec: {e}")))?;

    // Standard container mounts.
    let mounts = vec![
        MountBuilder::default()
            .destination("/proc")
            .typ("proc")
            .source("proc")
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/sys")
            .typ("sysfs")
            .source("sysfs")
            .options(vec![
                "nosuid".into(),
                "noexec".into(),
                "nodev".into(),
                "ro".into(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev")
            .typ("tmpfs")
            .source("tmpfs")
            .options(vec![
                "nosuid".into(),
                "strictatime".into(),
                "mode=755".into(),
                "size=65536k".into(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev/pts")
            .typ("devpts")
            .source("devpts")
            .options(vec![
                "nosuid".into(),
                "noexec".into(),
                "newinstance".into(),
                "ptmxmode=0666".into(),
                "mode=0620".into(),
            ])
            .build()
            .unwrap(),
        MountBuilder::default()
            .destination("/dev/shm")
            .typ("tmpfs")
            .source("shm")
            .options(vec![
                "nosuid".into(),
                "noexec".into(),
                "nodev".into(),
                "mode=1777".into(),
                "size=65536k".into(),
            ])
            .build()
            .unwrap(),
    ];

    // Linux namespaces: the zone already has these, the shim enters them via setns.
    let ns_types = [
        LinuxNamespaceType::Pid,
        LinuxNamespaceType::Mount,
        LinuxNamespaceType::Network,
        LinuxNamespaceType::Uts,
        LinuxNamespaceType::Ipc,
    ];
    let namespaces: Vec<_> = ns_types
        .into_iter()
        .map(|typ| LinuxNamespaceBuilder::default().typ(typ).build().unwrap())
        .collect();

    let linux = LinuxBuilder::default()
        .namespaces(namespaces)
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build linux spec: {e}")))?;

    let spec = SpecBuilder::default()
        .version("1.0.2")
        .root(root)
        .process(process)
        .mounts(mounts)
        .linux(linux)
        .hostname(container_spec.name.clone())
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build OCI spec: {e}")))?;

    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::{OciImageConfig, OciImageConfigInner};

    fn make_image_config(
        cmd: Option<Vec<&str>>,
        entrypoint: Option<Vec<&str>>,
        env: Option<Vec<&str>>,
        working_dir: Option<&str>,
    ) -> OciImageConfig {
        OciImageConfig {
            config: Some(OciImageConfigInner {
                cmd: cmd.map(|v| v.into_iter().map(String::from).collect()),
                entrypoint: entrypoint.map(|v| v.into_iter().map(String::from).collect()),
                env: env.map(|v| v.into_iter().map(String::from).collect()),
                working_dir: working_dir.map(String::from),
                user: None,
            }),
        }
    }

    fn make_container_spec(
        name: &str,
        command: Vec<&str>,
        env: Vec<(&str, &str)>,
        working_dir: Option<&str>,
    ) -> ContainerSpec {
        ContainerSpec {
            name: name.into(),
            image: "test:latest".into(),
            command: command.into_iter().map(String::from).collect(),
            env: env
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            working_dir: working_dir.map(String::from),
            rootfs_path: None,
            overlay_layers: None,
            oci_spec_json: None,
        }
    }

    #[test]
    fn container_command_overrides_image() {
        let img = make_image_config(Some(vec!["/bin/sh"]), None, None, None);
        let spec = make_container_spec("test", vec!["/bin/echo", "hello"], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let args = result.process().as_ref().unwrap().args().as_ref().unwrap();
        assert_eq!(args, &["/bin/echo", "hello"]);
    }

    #[test]
    fn image_cmd_used_when_no_container_command() {
        let img = make_image_config(Some(vec!["nginx", "-g", "daemon off;"]), None, None, None);
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let args = result.process().as_ref().unwrap().args().as_ref().unwrap();
        assert_eq!(args, &["nginx", "-g", "daemon off;"]);
    }

    #[test]
    fn entrypoint_plus_cmd_concatenated() {
        let img = make_image_config(
            Some(vec!["--config", "/etc/app.conf"]),
            Some(vec!["/usr/bin/app"]),
            None,
            None,
        );
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let args = result.process().as_ref().unwrap().args().as_ref().unwrap();
        assert_eq!(args, &["/usr/bin/app", "--config", "/etc/app.conf"]);
    }

    #[test]
    fn fallback_to_bin_sh_when_no_command() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let args = result.process().as_ref().unwrap().args().as_ref().unwrap();
        assert_eq!(args, &["/bin/sh"]);
    }

    #[test]
    fn env_merge_and_override() {
        let img = make_image_config(
            Some(vec!["/bin/sh"]),
            None,
            Some(vec!["FOO=from_image", "BAR=keep_me"]),
            None,
        );
        let spec = make_container_spec(
            "test",
            vec![],
            vec![("FOO", "overridden"), ("NEW", "added")],
            None,
        );
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let env = result.process().as_ref().unwrap().env().as_ref().unwrap();

        assert!(env.contains(&"FOO=overridden".to_string()));
        assert!(env.contains(&"BAR=keep_me".to_string()));
        assert!(env.contains(&"NEW=added".to_string()));
        // FOO=from_image should NOT be present.
        assert!(!env.contains(&"FOO=from_image".to_string()));
    }

    #[test]
    fn path_always_set() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let env = result.process().as_ref().unwrap().env().as_ref().unwrap();
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
    }

    #[test]
    fn path_not_duplicated_if_in_image() {
        let img = make_image_config(
            Some(vec!["/bin/sh"]),
            None,
            Some(vec!["PATH=/custom/path"]),
            None,
        );
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let env = result.process().as_ref().unwrap().env().as_ref().unwrap();
        let path_count = env.iter().filter(|e| e.starts_with("PATH=")).count();
        assert_eq!(path_count, 1);
        assert!(env.contains(&"PATH=/custom/path".to_string()));
    }

    #[test]
    fn working_dir_precedence() {
        // Container spec overrides image.
        let img = make_image_config(Some(vec!["/bin/sh"]), None, None, Some("/app"));
        let spec = make_container_spec("test", vec![], vec![], Some("/override"));
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let cwd = result.process().as_ref().unwrap().cwd();
        assert_eq!(cwd.to_str().unwrap(), "/override");
    }

    #[test]
    fn working_dir_from_image() {
        let img = make_image_config(Some(vec!["/bin/sh"]), None, None, Some("/app"));
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let cwd = result.process().as_ref().unwrap().cwd();
        assert_eq!(cwd.to_str().unwrap(), "/app");
    }

    #[test]
    fn working_dir_defaults_to_root() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let cwd = result.process().as_ref().unwrap().cwd();
        assert_eq!(cwd.to_str().unwrap(), "/");
    }

    #[test]
    fn standard_mounts_present() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let mounts = result.mounts().as_ref().unwrap();
        let destinations: Vec<_> = mounts
            .iter()
            .map(|m| m.destination().to_string_lossy().to_string())
            .collect();

        assert!(destinations.contains(&"/proc".to_string()));
        assert!(destinations.contains(&"/sys".to_string()));
        assert!(destinations.contains(&"/dev".to_string()));
        assert!(destinations.contains(&"/dev/pts".to_string()));
        assert!(destinations.contains(&"/dev/shm".to_string()));
    }

    #[test]
    fn sys_is_readonly() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let mounts = result.mounts().as_ref().unwrap();
        let sys_mount = mounts
            .iter()
            .find(|m| m.destination().to_string_lossy() == "/sys")
            .unwrap();
        let options = sys_mount.options().as_ref().unwrap();
        assert!(options.iter().any(|o| o == "ro"));
    }

    #[test]
    fn hostname_set_from_container_name() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("my-container", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        assert_eq!(result.hostname().as_deref(), Some("my-container"));
    }

    #[test]
    fn rootfs_path_set() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/var/lib/rauha/rootfs").unwrap();
        let root = result.root().as_ref().unwrap();
        assert_eq!(root.path().to_str().unwrap(), "/var/lib/rauha/rootfs");
        assert_eq!(root.readonly(), Some(false));
    }

    #[test]
    fn five_namespaces_configured() {
        let img = OciImageConfig { config: None };
        let spec = make_container_spec("test", vec![], vec![], None);
        let policy = ZonePolicy::default();

        let result = generate_spec(&img, &spec, &policy, "/rootfs").unwrap();
        let linux = result.linux().as_ref().unwrap();
        let namespaces = linux.namespaces().as_ref().unwrap();
        assert_eq!(namespaces.len(), 5);
    }
}
