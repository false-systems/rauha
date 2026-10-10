//! containerd task lifecycle, backed by the zone's OCI supervisor.
use crate::rauha_client::{pb, RauhaClient};
use async_trait::async_trait;
use containerd_shim::{
    api,
    asynchronous::{spawn, ExitSignal, Shim},
    publisher::RemotePublisher,
    Config, Error, Flags, StartOpts, TtrpcResult,
};
use containerd_shim_protos::{
    events::task as events,
    protobuf::{
        well_known_types::{any::Any, timestamp::Timestamp},
        Message, MessageDyn, MessageField,
    },
    shim_async::Task,
    ttrpc::r#async::TtrpcContext,
    types::task::Status,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
struct TaskState {
    id: String,
    rauha_id: String,
    zone: String,
    owns_zone: bool,
    bundle: String,
    rootfs: PathBuf,
    mounted: bool,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    #[serde(default)]
    execs: HashMap<String, ExecState>,
    pid: u32,
    started: bool,
    #[serde(default)]
    paused: bool,
    exit_code: Option<i32>,
    finished_at: String,
    exit_published: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct ExecState {
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    pid: u32,
    state: String,
    exit_code: Option<i32>,
    finished_at: String,
    exit_published: bool,
}

fn timestamp(value: &str) -> Result<MessageField<Timestamp>, Error> {
    if value.is_empty() {
        return Ok(MessageField::none());
    }
    let time = chrono::DateTime::parse_from_rfc3339(value).map_err(other)?;
    Ok(MessageField::some(Timestamp {
        seconds: time.timestamp(),
        nanos: time.timestamp_subsec_nanos() as i32,
        ..Default::default()
    }))
}

impl TaskState {
    fn save(&self) -> Result<(), Error> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = Path::new(&self.bundle).join("rauha-task.json");
        let temp = path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temp)
            .map_err(other)?;
        file.write_all(&serde_json::to_vec(self)?).map_err(other)?;
        file.sync_all().map_err(other)?;
        std::fs::rename(temp, path).map_err(other)?;
        std::fs::File::open(&self.bundle)
            .and_then(|f| f.sync_all())
            .map_err(other)
    }

    fn exited_at(&self) -> Result<MessageField<Timestamp>, Error> {
        timestamp(&self.finished_at)
    }
}

fn other(error: impl std::fmt::Display) -> Error {
    Error::Other(error.to_string())
}

fn zone_name(namespace: &str, sandbox: &str) -> String {
    let digest = Sha256::digest(format!("{namespace}\0{sandbox}"));
    format!("ctr-{:x}", digest)
}

fn read_policy(path: &Path) -> Result<String, Error> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    const MAX_BYTES: u64 = 1024 * 1024;
    if !path.is_absolute() {
        return Err(Error::InvalidArgument(
            "RAUHA_CONTAINERD_POLICY must be an absolute path".into(),
        ));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(other)?;
    let metadata = file.metadata().map_err(other)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_BYTES
    {
        return Err(Error::InvalidArgument("containerd policy must be a root-owned regular file, not group/world-writable, at most 1 MiB".into()));
    }
    let mut policy = String::new();
    file.take(MAX_BYTES + 1)
        .read_to_string(&mut policy)
        .map_err(other)?;
    if policy.len() as u64 > MAX_BYTES {
        return Err(Error::InvalidArgument(
            "containerd policy exceeds 1 MiB".into(),
        ));
    }
    Ok(policy)
}

fn zone_policy(spec: &serde_json::Value, zone: &str, configured: &str) -> Result<String, Error> {
    if spec["annotations"].get("io.rauha.policy").is_some() {
        return Err(Error::InvalidArgument("io.rauha.policy is not accepted; policies are configured by the administrator through RAUHA_CONTAINERD_POLICY".into()));
    }
    let mut policy = if configured.is_empty() {
        toml::Table::new()
    } else {
        toml::from_str::<toml::Table>(configured).map_err(other)?
    };
    policy.insert(
        "zone".into(),
        toml::Value::Table(toml::Table::from_iter([
            ("name".into(), toml::Value::String(zone.into())),
            ("type".into(), toml::Value::String("non-global".into())),
        ])),
    );
    if let Some(path) = spec["linux"]["namespaces"]
        .as_array()
        .and_then(|namespaces| namespaces.iter().find(|ns| ns["type"] == "network"))
        .and_then(|ns| ns["path"].as_str())
        .filter(|path| !path.is_empty())
    {
        let network = policy
            .entry("network")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| Error::InvalidArgument("network policy must be a table".into()))?;
        network.insert("mode".into(), toml::Value::String("external".into()));
        network.insert("namespace".into(), toml::Value::String(path.into()));
    }
    toml::to_string(&policy).map_err(other)
}

fn process_status(state: &str) -> Result<Status, Error> {
    match state {
        "Created" => Ok(Status::CREATED),
        "Running" => Ok(Status::RUNNING),
        "Stopped" => Ok(Status::STOPPED),
        "Paused" => Ok(Status::PAUSED),
        _ => Err(other(format!("unknown daemon process state: {state}"))),
    }
}

#[derive(Clone)]
pub struct RauhaShim {
    exit: Arc<ExitSignal>,
    namespace: String,
    publisher: Option<Arc<RemotePublisher>>,
    client: Arc<Mutex<Option<RauhaClient>>>,
    tasks: Arc<Mutex<HashMap<String, TaskState>>>,
}

#[async_trait]
impl Shim for RauhaShim {
    type T = Self;
    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        Self {
            exit: Arc::new(ExitSignal::default()),
            namespace: args.namespace.clone(),
            publisher: None,
            client: Arc::new(Mutex::new(None)),
            tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        let grouping = opts.id.clone();
        spawn(opts, &grouping, Vec::new()).await
    }
    async fn delete_shim(&mut self) -> Result<api::DeleteResponse, Error> {
        let bytes = std::fs::read("rauha-task.json").map_err(other)?;
        let state: TaskState = serde_json::from_slice(&bytes)?;
        self.cleanup(&state, true).await?;
        Ok(api::DeleteResponse {
            pid: state.pid,
            exit_status: state.exit_code.unwrap_or(137) as u32,
            exited_at: state.exited_at()?,
            ..Default::default()
        })
    }
    async fn wait(&mut self) {
        self.exit.wait().await;
    }
    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        let mut service = self.clone();
        service.publisher = Some(Arc::new(publisher));
        service
    }
}

impl RauhaShim {
    async fn set_paused(&self, id: &str, paused: bool) -> Result<(), Error> {
        let mut tasks = self.tasks.lock().await;
        let state = tasks
            .get_mut(id)
            .ok_or_else(|| Error::NotFoundError(id.into()))?;
        self.client()
            .await?
            .containers
            .set_container_paused(pb::container::SetContainerPausedRequest {
                container_id: state.rauha_id.clone(),
                paused,
            })
            .await
            .map_err(other)?;
        state.paused = paused;
        state.save()?;
        if paused {
            self.publish(
                "/tasks/paused",
                events::TaskPaused {
                    container_id: id.into(),
                    ..Default::default()
                },
            )
            .await?;
        } else {
            self.publish(
                "/tasks/resumed",
                events::TaskResumed {
                    container_id: id.into(),
                    ..Default::default()
                },
            )
            .await?;
        }
        Ok(())
    }
    async fn client(&self) -> Result<RauhaClient, Error> {
        let mut client = self.client.lock().await;
        if let Some(client) = client.as_ref() {
            return Ok(client.clone());
        }
        let connected = RauhaClient::connect(&RauhaClient::endpoint())
            .await
            .map_err(other)?;
        *client = Some(connected.clone());
        Ok(connected)
    }

    async fn publish(&self, topic: &str, event: impl MessageDyn + 'static) -> Result<(), Error> {
        let publisher = self
            .publisher
            .as_ref()
            .ok_or_else(|| other("containerd publisher not initialized"))?;
        publisher
            .publish(Default::default(), topic, &self.namespace, Box::new(event))
            .await
    }

    async fn refresh(&self, state: &mut TaskState) -> Result<(), Error> {
        if state.exit_code.is_none() {
            let info = self
                .client()
                .await?
                .containers
                .get_container(pb::container::GetContainerRequest {
                    container_id: state.rauha_id.clone(),
                })
                .await
                .map_err(other)?
                .into_inner()
                .container
                .ok_or_else(|| other("daemon returned no container"))?;
            state.pid = info.pid;
            state.started |= info.state == "Running" || info.state == "Paused";
            state.paused = info.state == "Paused";
            if info.state == "Stopped" {
                state.exit_code = Some(
                    info.exit_code
                        .ok_or_else(|| other("stopped container has no exit status"))?,
                );
                state.finished_at = info.finished_at;
                state.save()?;
            }
        }
        if let Some(code) = state.exit_code.filter(|_| !state.exit_published) {
            self.publish(
                "/tasks/exit",
                events::TaskExit {
                    container_id: state.id.clone(),
                    id: state.id.clone(),
                    pid: state.pid,
                    exit_status: code as u32,
                    exited_at: state.exited_at()?,
                    ..Default::default()
                },
            )
            .await?;
            state.exit_published = true;
            state.save()?;
        }
        Ok(())
    }

    async fn cleanup(&self, state: &TaskState, force: bool) -> Result<(), Error> {
        let mut client = self.client().await?;
        match client
            .containers
            .delete_container(pb::container::DeleteContainerRequest {
                container_id: state.rauha_id.clone(),
                force,
            })
            .await
        {
            Ok(_) => {}
            Err(e) if e.code() == tonic::Code::NotFound => {}
            Err(e) => return Err(other(e)),
        }
        if state.owns_zone {
            match client
                .zones
                .delete_zone(pb::zone::DeleteZoneRequest {
                    name: state.zone.clone(),
                    force: false,
                })
                .await
            {
                Ok(_) => {}
                Err(e) if e.code() == tonic::Code::NotFound => {}
                Err(e) => return Err(other(e)),
            }
        }
        if state.mounted {
            unmount(&state.rootfs)?;
        }
        Ok(())
    }

    async fn refresh_exec(&self, state: &mut TaskState, exec_id: &str) -> Result<(), Error> {
        let process = state
            .execs
            .get_mut(exec_id)
            .ok_or_else(|| Error::NotFoundError(exec_id.into()))?;
        if process.exit_code.is_none() {
            let info = self
                .client()
                .await?
                .containers
                .get_exec(pb::container::ProcessRequest {
                    container_id: state.rauha_id.clone(),
                    exec_id: exec_id.into(),
                })
                .await
                .map_err(other)?
                .into_inner();
            process.pid = info.pid;
            process.state = info.state;
            process.exit_code = info.exit_code;
            process.finished_at = info.finished_at;
        }
        if let Some(code) = process.exit_code.filter(|_| !process.exit_published) {
            self.publish(
                "/tasks/exit",
                events::TaskExit {
                    container_id: state.id.clone(),
                    id: exec_id.into(),
                    pid: process.pid,
                    exit_status: code as u32,
                    exited_at: timestamp(&process.finished_at)?,
                    ..Default::default()
                },
            )
            .await?;
            process.exit_published = true;
            state.save()?;
        }
        Ok(())
    }

    fn observe(&self, id: String, exec_id: String) {
        let service = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let mut tasks = service.tasks.lock().await;
                let Some(state) = tasks.get_mut(&id) else {
                    break;
                };
                let result = if exec_id.is_empty() {
                    service.refresh(state).await.map(|()| state.exit_published)
                } else if !state.execs.contains_key(&exec_id) {
                    break;
                } else {
                    service
                        .refresh_exec(state, &exec_id)
                        .await
                        .map(|()| state.execs[&exec_id].exit_published)
                };
                match result {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(error) => log::warn!("cannot observe task {id}/{exec_id}: {error}"),
                }
            }
        });
    }
}

#[cfg(target_os = "linux")]
fn unmount(rootfs: &Path) -> Result<(), Error> {
    containerd_shim::mount::umount_recursive(rootfs.to_str(), 0)
}
#[cfg(not(target_os = "linux"))]
fn unmount(_rootfs: &Path) -> Result<(), Error> {
    Err(Error::Unimplemented("containerd requires Linux".into()))
}

#[async_trait]
impl Task for RauhaShim {
    async fn exec(
        &self,
        _ctx: &TtrpcContext,
        req: api::ExecProcessRequest,
    ) -> TtrpcResult<api::Empty> {
        if req.exec_id.is_empty() || req.exec_id.contains('/') || req.exec_id.contains('\0') {
            return Err(Error::InvalidArgument("invalid exec ID".into()).into());
        }
        let spec = req
            .spec
            .as_ref()
            .ok_or_else(|| Error::InvalidArgument("missing OCI process".into()))?;
        if spec.type_url != "types.containerd.io/opencontainers/runtime-spec/1/Process" {
            return Err(
                Error::InvalidArgument("expected an OCI Process specification".into()).into(),
            );
        }
        let process_json = String::from_utf8(spec.value.clone()).map_err(other)?;
        let mut tasks = self.tasks.lock().await;
        let state = tasks
            .get_mut(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        if state.execs.contains_key(&req.exec_id) {
            return Err(Error::FailedPreconditionError("exec ID already exists".into()).into());
        }
        let info = self
            .client()
            .await?
            .containers
            .create_exec(pb::container::CreateExecRequest {
                container_id: state.rauha_id.clone(),
                exec_id: req.exec_id.clone(),
                process_json,
                stdin: req.stdin.clone(),
                stdout: req.stdout.clone(),
                stderr: req.stderr.clone(),
                terminal: req.terminal,
            })
            .await
            .map_err(other)?
            .into_inner();
        state.execs.insert(
            req.exec_id.clone(),
            ExecState {
                stdin: req.stdin,
                stdout: req.stdout,
                stderr: req.stderr,
                terminal: req.terminal,
                pid: info.pid,
                state: info.state,
                exit_code: info.exit_code,
                finished_at: info.finished_at,
                exit_published: false,
            },
        );
        state.save()?;
        self.publish(
            "/tasks/exec-added",
            events::TaskExecAdded {
                container_id: req.id,
                exec_id: req.exec_id,
                ..Default::default()
            },
        )
        .await?;
        Ok(api::Empty::default())
    }

    async fn resize_pty(
        &self,
        _ctx: &TtrpcContext,
        req: api::ResizePtyRequest,
    ) -> TtrpcResult<api::Empty> {
        let tasks = self.tasks.lock().await;
        let state = tasks
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        self.client()
            .await?
            .containers
            .resize_process(pb::container::ResizeProcessRequest {
                container_id: state.rauha_id.clone(),
                exec_id: req.exec_id,
                rows: req.height,
                cols: req.width,
            })
            .await
            .map_err(other)?;
        Ok(api::Empty::default())
    }

    async fn close_io(
        &self,
        _ctx: &TtrpcContext,
        req: api::CloseIORequest,
    ) -> TtrpcResult<api::Empty> {
        let tasks = self.tasks.lock().await;
        let state = tasks
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        if req.stdin {
            self.client()
                .await?
                .containers
                .close_process_io(pb::container::ProcessRequest {
                    container_id: state.rauha_id.clone(),
                    exec_id: req.exec_id,
                })
                .await
                .map_err(other)?;
        }
        Ok(api::Empty::default())
    }

    async fn create(
        &self,
        _ctx: &TtrpcContext,
        req: api::CreateTaskRequest,
    ) -> TtrpcResult<api::CreateTaskResponse> {
        if req.id.is_empty() || req.id.contains('/') || req.id.contains('\0') {
            return Err(Error::InvalidArgument("invalid task ID".into()).into());
        }
        if !req.checkpoint.is_empty() || !req.parent_checkpoint.is_empty() {
            return Err(Error::Unimplemented("checkpoint restore".into()).into());
        }
        let mut tasks = self.tasks.lock().await;
        if tasks.contains_key(&req.id) {
            return Err(Error::FailedPreconditionError("task already exists".into()).into());
        }
        let bundle = Path::new(&req.bundle).canonicalize().map_err(other)?;
        let mut spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bundle.join("config.json")).map_err(other)?)
                .map_err(other)?;
        let sandbox = spec["annotations"]["io.kubernetes.cri.container-type"] == "sandbox";
        spec["process"]["terminal"] = req.terminal.into();
        let sandbox_id = spec["annotations"]["io.kubernetes.cri.sandbox-id"]
            .as_str()
            .map(str::to_owned);
        let owns_zone = sandbox || sandbox_id.is_none();
        let zone = zone_name(
            &self.namespace,
            sandbox_id
                .as_deref()
                .filter(|_| !sandbox)
                .unwrap_or(&req.id),
        );
        let root = spec["root"]["path"]
            .as_str()
            .ok_or_else(|| Error::InvalidArgument("bundle has no rootfs".into()))?;
        let rootfs = bundle.join(root);
        if rootfs == Path::new("/") {
            return Err(Error::InvalidArgument("host rootfs is not allowed".into()).into());
        }
        if !req.rootfs.is_empty() {
            if !rootfs.starts_with(&bundle) || rootfs == bundle {
                return Err(Error::InvalidArgument(
                    "mounted rootfs must be inside its bundle".into(),
                )
                .into());
            }
            std::fs::create_dir_all(&rootfs).map_err(other)?;
        }
        let rootfs = rootfs.canonicalize().map_err(other)?;
        if rootfs == Path::new("/")
            || rootfs == bundle
            || !rootfs.is_dir()
            || !req.rootfs.is_empty() && !rootfs.starts_with(&bundle)
        {
            return Err(Error::InvalidArgument("rootfs must be inside its bundle".into()).into());
        }
        let configured = std::env::var_os("RAUHA_CONTAINERD_POLICY")
            .map(|path| read_policy(Path::new(&path)))
            .transpose()?
            .unwrap_or_default();
        let policy_toml = zone_policy(&spec, &zone, &configured)?;
        // Connect before acquiring mounts so an unavailable daemon leaves no rootfs behind.
        let mut client = self.client().await?;
        let mut mounted = false;
        for mount in &req.rootfs {
            if let Err(error) = containerd_shim::mount::mount_rootfs(
                Some(&mount.type_),
                Some(&mount.source),
                &mount.options,
                &rootfs,
            ) {
                if mounted {
                    unmount(&rootfs).map_err(|cleanup| {
                        other(format!("mount failed: {error}; rollback failed: {cleanup}"))
                    })?;
                }
                return Err(error.into());
            }
            mounted = true;
        }
        if spec.get("annotations").is_none() {
            spec["annotations"] = serde_json::json!({});
        }
        for (key, value) in [
            ("io", "fifo"),
            ("stdin", &req.stdin),
            ("stdout", &req.stdout),
            ("stderr", &req.stderr),
        ] {
            spec["annotations"][format!("io.rauha.containerd.{key}")] =
                serde_json::Value::String(value.to_owned());
        }
        if owns_zone {
            if let Err(error) = client
                .zones
                .create_zone(pb::zone::CreateZoneRequest {
                    name: zone.clone(),
                    zone_type: "non-global".into(),
                    policy_toml,
                })
                .await
            {
                if mounted {
                    unmount(&rootfs)?;
                }
                return Err(other(error).into());
            }
        }
        let created = client
            .containers
            .import_container(pb::container::ImportContainerRequest {
                zone_name: zone.clone(),
                name: req.id.clone(),
                rootfs: rootfs.to_string_lossy().into_owned(),
                spec_json: spec.to_string(),
            })
            .await;
        let created = match created {
            Ok(response) => response.into_inner(),
            Err(error) => {
                if owns_zone {
                    client
                        .zones
                        .delete_zone(pb::zone::DeleteZoneRequest {
                            name: zone,
                            force: false,
                        })
                        .await
                        .map_err(other)?;
                }
                if mounted {
                    unmount(&rootfs)?;
                }
                return Err(other(error).into());
            }
        };
        let state = TaskState {
            id: req.id.clone(),
            rauha_id: created.container_id,
            zone,
            owns_zone,
            bundle: bundle.to_string_lossy().into_owned(),
            rootfs,
            mounted,
            stdin: req.stdin.clone(),
            stdout: req.stdout.clone(),
            stderr: req.stderr.clone(),
            terminal: req.terminal,
            execs: HashMap::new(),
            pid: created.pid,
            started: false,
            paused: false,
            exit_code: None,
            finished_at: String::new(),
            exit_published: false,
        };
        if let Err(error) = state.save() {
            self.cleanup(&state, true).await.map_err(|cleanup| {
                other(format!(
                    "persisting task failed: {error}; rollback failed: {cleanup}"
                ))
            })?;
            return Err(error.into());
        }
        let pid = state.pid;
        tasks.insert(req.id.clone(), state);
        self.publish(
            "/tasks/create",
            events::TaskCreate {
                container_id: req.id,
                bundle: req.bundle,
                rootfs: req.rootfs,
                pid,
                io: MessageField::some(events::TaskIO {
                    stdin: req.stdin,
                    stdout: req.stdout,
                    stderr: req.stderr,
                    terminal: req.terminal,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await?;
        Ok(api::CreateTaskResponse {
            pid,
            ..Default::default()
        })
    }

    async fn start(
        &self,
        _ctx: &TtrpcContext,
        req: api::StartRequest,
    ) -> TtrpcResult<api::StartResponse> {
        let mut tasks = self.tasks.lock().await;
        let state = tasks
            .get_mut(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        if !req.exec_id.is_empty() {
            let process = state
                .execs
                .get_mut(&req.exec_id)
                .ok_or_else(|| Error::NotFoundError(req.exec_id.clone()))?;
            let info = self
                .client()
                .await?
                .containers
                .start_exec(pb::container::ProcessRequest {
                    container_id: state.rauha_id.clone(),
                    exec_id: req.exec_id.clone(),
                })
                .await
                .map_err(other)?
                .into_inner();
            process.pid = info.pid;
            process.state = info.state;
            state.save()?;
            self.publish(
                "/tasks/exec-started",
                events::TaskExecStarted {
                    container_id: req.id.clone(),
                    exec_id: req.exec_id.clone(),
                    pid: info.pid,
                    ..Default::default()
                },
            )
            .await?;
            self.observe(req.id, req.exec_id);
            return Ok(api::StartResponse {
                pid: info.pid,
                ..Default::default()
            });
        }
        if state.started || state.exit_code.is_some() {
            return Err(Error::FailedPreconditionError("task is not created".into()).into());
        }
        state.pid = self
            .client()
            .await?
            .containers
            .start_container(pb::container::StartContainerRequest {
                container_id: state.rauha_id.clone(),
            })
            .await
            .map_err(other)?
            .into_inner()
            .pid;
        state.started = true;
        state.save()?;
        self.publish(
            "/tasks/start",
            events::TaskStart {
                container_id: req.id.clone(),
                pid: state.pid,
                ..Default::default()
            },
        )
        .await?;
        self.observe(req.id, String::new());
        Ok(api::StartResponse {
            pid: state.pid,
            ..Default::default()
        })
    }

    async fn kill(&self, _ctx: &TtrpcContext, req: api::KillRequest) -> TtrpcResult<api::Empty> {
        let mut tasks = self.tasks.lock().await;
        let state = tasks
            .get_mut(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        let result = self
            .client()
            .await?
            .containers
            .signal_process(pb::container::SignalProcessRequest {
                container_id: state.rauha_id.clone(),
                signal: req.signal,
                exec_id: req.exec_id.clone(),
                all: req.all,
            })
            .await;
        if let Err(error) = result {
            if error.code() == tonic::Code::NotFound {
                return Err(Error::NotFoundError(error.message().into()).into());
            }
            if error.code() != tonic::Code::FailedPrecondition {
                return Err(other(error).into());
            }
            let stopped = if req.exec_id.is_empty() {
                self.refresh(state).await?;
                state.exit_code.is_some()
            } else {
                self.refresh_exec(state, &req.exec_id).await?;
                state.execs[&req.exec_id].exit_code.is_some()
            };
            let empty = if stopped && req.all {
                self.client()
                    .await?
                    .containers
                    .container_stats(pb::container::GetContainerRequest {
                        container_id: state.rauha_id.clone(),
                    })
                    .await
                    .map_err(other)?
                    .into_inner()
                    .process_ids
                    .is_empty()
            } else {
                stopped
            };
            if stopped && empty {
                return Err(Error::NotFoundError("process has exited".into()).into());
            }
            return Err(other(error).into());
        }
        Ok(api::Empty::default())
    }

    async fn state(
        &self,
        _ctx: &TtrpcContext,
        req: api::StateRequest,
    ) -> TtrpcResult<api::StateResponse> {
        let mut tasks = self.tasks.lock().await;
        let state = tasks
            .get_mut(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        if !req.exec_id.is_empty() {
            self.refresh_exec(state, &req.exec_id).await?;
            let process = &state.execs[&req.exec_id];
            return Ok(api::StateResponse {
                id: req.id,
                exec_id: req.exec_id,
                bundle: state.bundle.clone(),
                pid: process.pid,
                status: process_status(&process.state)?.into(),
                stdin: process.stdin.clone(),
                stdout: process.stdout.clone(),
                stderr: process.stderr.clone(),
                terminal: process.terminal,
                exit_status: process.exit_code.unwrap_or(0) as u32,
                exited_at: timestamp(&process.finished_at)?,
                ..Default::default()
            });
        }
        self.refresh(state).await?;
        Ok(api::StateResponse {
            id: state.id.clone(),
            bundle: state.bundle.clone(),
            pid: state.pid,
            status: if state.exit_code.is_some() {
                Status::STOPPED
            } else if state.paused {
                Status::PAUSED
            } else if state.started {
                Status::RUNNING
            } else {
                Status::CREATED
            }
            .into(),
            stdin: state.stdin.clone(),
            stdout: state.stdout.clone(),
            stderr: state.stderr.clone(),
            terminal: state.terminal,
            exit_status: state.exit_code.unwrap_or(0) as u32,
            exited_at: state.exited_at()?,
            ..Default::default()
        })
    }

    async fn wait(
        &self,
        _ctx: &TtrpcContext,
        req: api::WaitRequest,
    ) -> TtrpcResult<api::WaitResponse> {
        loop {
            {
                let mut tasks = self.tasks.lock().await;
                let state = tasks
                    .get_mut(&req.id)
                    .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
                if !req.exec_id.is_empty() {
                    self.refresh_exec(state, &req.exec_id).await?;
                    let process = &state.execs[&req.exec_id];
                    if let Some(code) = process.exit_code {
                        return Ok(api::WaitResponse {
                            exit_status: code as u32,
                            exited_at: timestamp(&process.finished_at)?,
                            ..Default::default()
                        });
                    }
                } else {
                    self.refresh(state).await?;
                    if let Some(code) = state.exit_code {
                        return Ok(api::WaitResponse {
                            exit_status: code as u32,
                            exited_at: state.exited_at()?,
                            ..Default::default()
                        });
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    async fn delete(
        &self,
        _ctx: &TtrpcContext,
        req: api::DeleteRequest,
    ) -> TtrpcResult<api::DeleteResponse> {
        let mut tasks = self.tasks.lock().await;
        let state = tasks
            .get_mut(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        if !req.exec_id.is_empty() {
            self.refresh_exec(state, &req.exec_id).await?;
            let info = self
                .client()
                .await?
                .containers
                .delete_exec(pb::container::ProcessRequest {
                    container_id: state.rauha_id.clone(),
                    exec_id: req.exec_id.clone(),
                })
                .await
                .map_err(other)?
                .into_inner();
            self.publish(
                "/tasks/delete",
                events::TaskDelete {
                    container_id: req.id,
                    id: req.exec_id.clone(),
                    pid: info.pid,
                    exit_status: info.exit_code.unwrap_or(0) as u32,
                    exited_at: timestamp(&info.finished_at)?,
                    ..Default::default()
                },
            )
            .await?;
            state.execs.remove(&req.exec_id);
            state.save()?;
            return Ok(api::DeleteResponse {
                pid: info.pid,
                exit_status: info.exit_code.unwrap_or(0) as u32,
                exited_at: timestamp(&info.finished_at)?,
                ..Default::default()
            });
        }
        self.refresh(state).await?;
        if state.started && state.exit_code.is_none() {
            return Err(Error::FailedPreconditionError("task is still running".into()).into());
        }
        self.cleanup(state, false).await?;
        let response = api::DeleteResponse {
            pid: state.pid,
            exit_status: state.exit_code.unwrap_or(0) as u32,
            exited_at: state.exited_at()?,
            ..Default::default()
        };
        self.publish(
            "/tasks/delete",
            events::TaskDelete {
                container_id: req.id.clone(),
                pid: state.pid,
                exit_status: response.exit_status,
                exited_at: response.exited_at.clone(),
                ..Default::default()
            },
        )
        .await?;
        std::fs::remove_file(Path::new(&state.bundle).join("rauha-task.json")).map_err(other)?;
        tasks.remove(&req.id);
        Ok(response)
    }

    async fn connect(
        &self,
        _ctx: &TtrpcContext,
        req: api::ConnectRequest,
    ) -> TtrpcResult<api::ConnectResponse> {
        let tasks = self.tasks.lock().await;
        let state = tasks
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        Ok(api::ConnectResponse {
            shim_pid: std::process::id(),
            task_pid: state.pid,
            ..Default::default()
        })
    }
    async fn shutdown(
        &self,
        _ctx: &TtrpcContext,
        _req: api::ShutdownRequest,
    ) -> TtrpcResult<api::Empty> {
        if self.tasks.lock().await.is_empty() {
            self.exit.signal();
        }
        Ok(api::Empty::default())
    }
    async fn stats(
        &self,
        _ctx: &TtrpcContext,
        req: api::StatsRequest,
    ) -> TtrpcResult<api::StatsResponse> {
        use containerd_shim_protos::cgroups::metrics::{
            CPUStat, CPUUsage, MemoryEntry, MemoryStat, Metrics, PidsStat,
        };
        let tasks = self.tasks.lock().await;
        let state = tasks
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        let stats = self
            .client()
            .await?
            .containers
            .container_stats(pb::container::GetContainerRequest {
                container_id: state.rauha_id.clone(),
            })
            .await
            .map_err(other)?
            .into_inner();
        let metrics = Metrics {
            cpu: MessageField::some(CPUStat {
                usage: MessageField::some(CPUUsage {
                    total: stats.cpu_usage_usec.saturating_mul(1000),
                    user: stats.cpu_user_usec.saturating_mul(1000),
                    kernel: stats.cpu_system_usec.saturating_mul(1000),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            memory: MessageField::some(MemoryStat {
                usage: MessageField::some(MemoryEntry {
                    usage: stats.memory_usage_bytes,
                    limit: stats.memory_limit_bytes,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            pids: MessageField::some(PidsStat {
                current: stats.pids_current,
                limit: stats.pids_limit,
                ..Default::default()
            }),
            ..Default::default()
        };
        Ok(api::StatsResponse {
            stats: MessageField::some(Any {
                type_url: "io.containerd.cgroups.v1.Metrics".into(),
                value: metrics.write_to_bytes().map_err(other)?,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    async fn pids(
        &self,
        _ctx: &TtrpcContext,
        req: api::PidsRequest,
    ) -> TtrpcResult<api::PidsResponse> {
        let tasks = self.tasks.lock().await;
        let state = tasks
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        let stats = self
            .client()
            .await?
            .containers
            .container_stats(pb::container::GetContainerRequest {
                container_id: state.rauha_id.clone(),
            })
            .await
            .map_err(other)?
            .into_inner();
        Ok(api::PidsResponse {
            processes: stats
                .process_ids
                .into_iter()
                .map(|pid| containerd_shim_protos::types::task::ProcessInfo {
                    pid,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        })
    }

    async fn pause(&self, _ctx: &TtrpcContext, req: api::PauseRequest) -> TtrpcResult<api::Empty> {
        self.set_paused(&req.id, true).await?;
        Ok(api::Empty::default())
    }

    async fn resume(
        &self,
        _ctx: &TtrpcContext,
        req: api::ResumeRequest,
    ) -> TtrpcResult<api::Empty> {
        self.set_paused(&req.id, false).await?;
        Ok(api::Empty::default())
    }

    async fn update(
        &self,
        _ctx: &TtrpcContext,
        req: api::UpdateTaskRequest,
    ) -> TtrpcResult<api::Empty> {
        let resources = req
            .resources
            .as_ref()
            .ok_or_else(|| Error::InvalidArgument("missing OCI resources".into()))?;
        if resources.type_url != "types.containerd.io/opencontainers/runtime-spec/1/LinuxResources"
        {
            return Err(Error::InvalidArgument("expected OCI LinuxResources".into()).into());
        }
        let tasks = self.tasks.lock().await;
        let state = tasks
            .get(&req.id)
            .ok_or_else(|| Error::NotFoundError(req.id.clone()))?;
        self.client()
            .await?
            .containers
            .update_container_resources(pb::container::UpdateContainerResourcesRequest {
                container_id: state.rauha_id.clone(),
                resources_json: String::from_utf8(resources.value.clone()).map_err(other)?,
            })
            .await
            .map_err(other)?;
        Ok(api::Empty::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zone_identity_includes_namespace_and_complete_task_id() {
        assert_ne!(
            zone_name("a", "abcdefghijkl1"),
            zone_name("a", "abcdefghijkl2")
        );
        assert_ne!(zone_name("a", "task"), zone_name("b", "task"));
        assert_eq!(zone_name("a", "task"), zone_name("a", "task"));
        assert_ne!(zone_name("a", "🐉"), zone_name("a", "🐲"));
    }
    #[test]
    fn daemon_states_are_not_guessed() {
        assert_eq!(process_status("Stopped").unwrap(), Status::STOPPED);
        assert_eq!(process_status("Paused").unwrap(), Status::PAUSED);
        assert!(process_status("stopped").is_err());
    }

    #[test]
    fn imported_network_policy_preserves_explicit_restrictions() {
        let spec = serde_json::json!({
            "linux": {"namespaces": [{"type":"network", "path":"/run/netns/cni-test"}]}
        });
        let policy: rauha_common::zone::PolicyFile = toml::from_str(
            &zone_policy(
                &spec,
                "pod",
                "[network]\nallowed_egress = [\"10.0.0.1:443\"]\n",
            )
            .unwrap(),
        )
        .unwrap();
        let policy = policy.to_zone_policy("/tmp/rauha").unwrap();
        assert_eq!(
            policy.network.mode,
            rauha_common::zone::NetworkMode::External {
                namespace: "/run/netns/cni-test".into()
            }
        );
        assert_eq!(policy.network.allowed_egress, ["10.0.0.1:443"]);
        assert!(policy.network.allowed_ingress.is_empty());
        assert!(policy.capabilities.allowed.is_empty());
    }

    #[test]
    fn workload_annotations_cannot_choose_a_more_privileged_policy() {
        let spec = serde_json::json!({"annotations":{"io.rauha.policy":"[network]\nmode='host'"}});
        assert!(zone_policy(&spec, "pod", "").is_err());
    }

    #[test]
    fn administrator_policy_refuses_unsafe_files() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.toml");
        std::fs::write(&path, "[network]\nmode='isolated'\n").unwrap();
        assert!(read_policy(Path::new("relative.toml")).is_err());
        assert!(read_policy(directory.path()).is_err());
        let link = directory.path().join("symlink");
        symlink(&path, &link).unwrap();
        assert!(read_policy(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_policy(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        if std::fs::metadata(&path).unwrap().uid() == 0 {
            assert!(read_policy(&path).is_ok());
        } else {
            assert!(read_policy(&path).is_err());
        }
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        assert!(read_policy(&path).is_err());
    }

    #[test]
    fn timestamps_preserve_exit_time_precision() {
        let time = timestamp("2026-10-10T00:00:00.123456789Z")
            .unwrap()
            .unwrap();
        assert_eq!(time.nanos, 123456789);
        assert!(timestamp("invalid").is_err());
        assert!(timestamp("").unwrap().is_none());
    }
}
