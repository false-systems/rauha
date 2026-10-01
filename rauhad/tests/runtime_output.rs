//! Live regression: run explicitly against the isolated Lima daemon as root.
//! RAUHA_TEST_RUN_DIR=/run/rauha cargo test -p rauhad --test runtime_output hostile_output -- --ignored --nocapture
use prost::Message;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::{collections::BTreeSet, path::Path};
use tonic::Code;

mod pb {
    tonic::include_proto!("rauha.sandbox.v1");
}
mod zone {
    tonic::include_proto!("rauha.zone.v1");
}
mod container {
    tonic::include_proto!("rauha.container.v1");
}

#[test]
#[ignore = "requires completed live daemon crash-recovery probe"]
fn recovered_shim_cleanup() {
    let state = std::env::var("RAUHA_TEST_RECOVERY_STATE").expect("set recovery state file");
    let state = std::fs::read_to_string(state).unwrap();
    let zone = state
        .lines()
        .find_map(|line| line.strip_prefix("zone="))
        .expect("zone missing from recovery state");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut found = false;
        for entry in std::fs::read_dir("/proc").unwrap() {
            let entry = entry.unwrap();
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let bytes = match std::fs::read(entry.path().join("cmdline")) {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => panic!("cannot inspect process: {e}"),
            };
            let args: Vec<_> = bytes.split(|byte| *byte == 0).collect();
            found |= args
                .windows(2)
                .any(|pair| pair == [b"--zone-name".as_slice(), zone.as_bytes()]);
        }
        if !found {
            println!("PASS recovery: deleted zone {zone} has no surviving shim");
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "deleted recovered zone left a live shim"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn log_directories(path: &Path) -> BTreeSet<std::path::PathBuf> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect()
}

#[tokio::test]
#[ignore = "requires a running isolated Linux daemon, image, and access to its log directory"]
async fn hostile_output_is_bounded_signed_retrievable_and_cleaned() {
    let run_dir =
        std::env::var("RAUHA_TEST_RUN_DIR").expect("set the isolated daemon run directory");
    let logs = Path::new(&run_dir).join("containers");
    std::fs::create_dir_all(&logs).unwrap();
    let before = log_directories(&logs);
    let endpoint =
        std::env::var("RAUHA_TEST_ENDPOINT").unwrap_or_else(|_| "http://[::1]:9876".into());
    let mut client = pb::sandbox_service_client::SandboxServiceClient::connect(endpoint.clone())
        .await
        .unwrap();
    let refused_id = format!("task-{}", uuid::Uuid::new_v4());
    let refused = pb::RunSandboxRequest {
        task_id: refused_id.clone(),
        name: format!("missing-{}", uuid::Uuid::new_v4()),
        image: "alpine:latest".into(),
        command: vec!["/bin/true".into()],
        audit: true,
        ..Default::default()
    };
    for _ in 0..20 {
        assert_eq!(
            client
                .run_sandbox(refused.clone())
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
    }
    assert_eq!(
        client
            .get_sandbox_result(pb::SandboxResultRequest {
                task_id: refused_id
            })
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    println!(
        "PASS refused requests: repeated identifier remains reusable, no retained reservation"
    );
    for (script, expected_issue) in [
        ("printf hello; printf world >&2", None),
        ("head -c 1048576 /dev/zero | tr '\\000' '\\377'; head -c 1048576 /dev/zero | tr '\\000' '\\377' >&2", Some("stdout.invalid_utf8")),
        ("head -c 16777216 /dev/zero; head -c 16777216 /dev/zero >&2; sleep 2", Some("stdout.storage_incomplete")),
    ] {
        let task_id = format!("task-{}", uuid::Uuid::new_v4());
        let request = pb::RunSandboxRequest {
            task_id: task_id.clone(), image: "alpine:latest".into(),
            command: vec!["/bin/sh".into(), "-c".into(), script.into()],
            audit: true, timeout_seconds: 30, ..Default::default()
        };
        let mut runner = client.clone();
        let duplicate = request.clone();
        let run = tokio::spawn(async move { runner.run_sandbox(request).await });
        let mut observed_logs = false;
        let mut checked_active = false;
        while !run.is_finished() {
            for dir in log_directories(&logs).difference(&before) {
                for stream in ["stdout", "stderr", "broker"] {
                    if let Ok(metadata) = std::fs::metadata(dir.join(format!("{stream}.log"))) {
                        observed_logs = true;
                        assert!(metadata.len() <= 1024 * 1024, "unbounded {stream}");
                    }
                }
            }
            if observed_logs && !checked_active && expected_issue == Some("stdout.storage_incomplete") {
                assert_eq!(client.delete_sandbox_result(pb::SandboxResultRequest { task_id: task_id.clone() }).await.unwrap_err().code(), Code::FailedPrecondition);
                assert_eq!(client.run_sandbox(duplicate.clone()).await.unwrap_err().code(), Code::AlreadyExists);
                checked_active = true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let result = run.await.unwrap().unwrap().into_inner();
        assert_eq!(result.status, "succeeded", "{}", result.stderr);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.encoded_len() <= rauha_common::sandbox::MAX_RESULT_BYTES);
        assert!(result.stdout.len() <= 1024 * 1024 && result.stderr.len() <= 1024 * 1024);
        if let Some(issue) = expected_issue { assert!(result.capture_issues.iter().any(|value| value == issue)); }
        else { assert!(result.capture_issues.is_empty()); }
        if expected_issue == Some("stdout.storage_incomplete") { assert!(observed_logs && checked_active); }
        let receipt: rauha_evidence::receipt::SignedExecutionReceipt = serde_json::from_str(&result.receipt_json).unwrap();
        receipt.verify().unwrap();
        assert_eq!(receipt.payload.capture_issues, result.capture_issues);
        assert_eq!(receipt.payload.outputs_sha256, rauha_evidence::receipt::sha256_json(&json!({
            "salt": result.task_id, "status":result.status, "exit_code":result.exit_code,
            "stdout":result.stdout, "stderr":result.stderr
        })).unwrap());
        let envelope: rauha_evidence::dsse::DsseEnvelope = serde_json::from_str(&result.receipt_dsse_json).unwrap();
        envelope.verify_public_hex(&receipt.public_key).unwrap();
        let key = pb::SandboxResultRequest { task_id: task_id.clone() };
        assert_eq!(client.get_sandbox_result(key.clone()).await.unwrap().into_inner(), result);
        assert_eq!(client.run_sandbox(duplicate).await.unwrap_err().code(), Code::AlreadyExists);
        assert_eq!(log_directories(&logs), before, "completed task leaked logs");
        assert!(client.delete_sandbox_result(key.clone()).await.unwrap().into_inner().deleted);
        assert_eq!(client.get_sandbox_result(key).await.unwrap_err().code(), Code::NotFound);
        println!("PASS {task_id}: bytes={} issues={:?}; signatures, retrieval, replay refusal and cleanup verified", result.encoded_len(), result.capture_issues);
    }
    broker_records_are_bounded_and_live_only_until_container_deletion(&endpoint, &logs).await;
}

async fn broker_records_are_bounded_and_live_only_until_container_deletion(
    endpoint: &str,
    logs: &Path,
) {
    let command = vec!["/bin/sh".into(), "-c".into(), "echo denied > /tmp/denied; i=0; while [ \"$i\" -lt 12000 ]; do exec 3</etc/hostname; i=$((i+1)); done".into()];
    let mut zones = zone::zone_service_client::ZoneServiceClient::connect(endpoint.to_string())
        .await
        .unwrap();
    let mut containers =
        container::container_service_client::ContainerServiceClient::connect(endpoint.to_string())
            .await
            .unwrap();
    let name = format!("output-broker-{}", uuid::Uuid::new_v4());
    zones
        .create_zone(zone::CreateZoneRequest {
            name: name.clone(),
            zone_type: "non-global".into(),
            policy_toml: include_str!("../../policies/broker.toml").into(),
        })
        .await
        .unwrap();
    let id = containers
        .create_container(container::CreateContainerRequest {
            zone_name: name.clone(),
            name: "log-lifetime".into(),
            image: "alpine:latest".into(),
            command: command.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
        .container_id;
    containers
        .start_container(container::StartContainerRequest {
            container_id: id.clone(),
        })
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let state = containers
            .get_container(container::GetContainerRequest {
                container_id: id.clone(),
            })
            .await
            .unwrap()
            .into_inner()
            .container
            .unwrap()
            .state;
        if state == "Stopped" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "broker workload did not finish"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // A shim refusal must reach the caller, not be turned into a successful stop.
    assert!(containers
        .stop_container(container::StopContainerRequest {
            container_id: id.clone(),
            timeout_seconds: 10,
        })
        .await
        .is_err());
    let dir = logs.join(&id);
    let bytes = std::fs::read(dir.join("broker.log")).unwrap();
    assert!(bytes.len() <= 1024 * 1024);
    assert!(
        dir.join("broker.incomplete").exists(),
        "overflow must be explicit"
    );
    let records: Vec<rauha_evidence::BrokerDecision> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(records.iter().any(|record| record.granted()));
    assert!(records.iter().any(|record| !record.granted()));
    assert!(records.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    assert_eq!(
        std::fs::metadata(dir.join("broker.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    containers
        .delete_container(container::DeleteContainerRequest {
            container_id: id,
            force: false,
        })
        .await
        .unwrap();
    assert!(
        !dir.exists(),
        "broker records leaked past container deletion"
    );
    let mut sandbox =
        pb::sandbox_service_client::SandboxServiceClient::connect(endpoint.to_string())
            .await
            .unwrap();
    let result = sandbox
        .run_sandbox(pb::RunSandboxRequest {
            task_id: format!("task-{}", uuid::Uuid::new_v4()),
            name: name.clone(),
            image: "alpine:latest".into(),
            command,
            timeout_seconds: 30,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(result.status, "succeeded");
    assert!(result
        .capture_issues
        .iter()
        .any(|issue| issue == "broker.storage_incomplete"));
    assert!(result.encoded_len() <= rauha_common::sandbox::MAX_RESULT_BYTES);
    let receipt: rauha_evidence::receipt::SignedExecutionReceipt =
        serde_json::from_str(&result.receipt_json).unwrap();
    receipt.verify().unwrap();
    assert_eq!(receipt.payload.capture_issues, result.capture_issues);
    sandbox
        .delete_sandbox_result(pb::SandboxResultRequest {
            task_id: result.task_id,
        })
        .await
        .unwrap();
    zones
        .delete_zone(zone::DeleteZoneRequest { name, force: true })
        .await
        .unwrap();
    println!("PASS broker: {} whole ordered records, grants and denials, bounded bytes, root-only mode and deletion verified", records.len());
}
