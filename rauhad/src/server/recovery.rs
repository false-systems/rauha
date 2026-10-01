use super::*;
use rauha_common::container::Container;

impl SandboxServiceImpl {
    fn task_containers(&self, record: &RecoveryRecord) -> anyhow::Result<Vec<Container>> {
        let zone_id = uuid::Uuid::parse_str(&record.receipt.zone_id)?;
        let name = format!("{}-task", record.receipt.task_id);
        let containers = self
            .registry
            .metadata()
            .list_containers(Some(&zone_id))?
            .into_iter()
            .filter(|container| {
                record
                    .container_id
                    .map_or_else(|| container.name == name, |id| container.id == id)
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(containers.len() <= 1, "ambiguous task container ownership");
        Ok(containers)
    }

    /// Called before accepting RPCs. Never starts a container or replays a command.
    pub async fn recover_tasks(&self) -> anyhow::Result<()> {
        for record in self.registry.metadata().recovery_records()? {
            let id = &record.receipt.task_id;
            let result =
                self.registry.metadata().get_result(id)?.ok_or_else(|| {
                    anyhow::anyhow!("recovery record without reserved result: {id}")
                })?;
            if result.is_empty() {
                let containers = self.task_containers(&record)?;
                let mut result = pb::sandbox::SandboxResult {
                    task_id: id.clone(), zone_id: record.receipt.zone_id.clone(),
                    command: record.command.clone(), status: "runtime_error".into(),
                    admission: admission_str(record.admission).into(),
                    unavailable_controls: record.receipt.unavailable_controls.clone(),
                    capture_issues: vec!["runtime.interrupted".into(), "execution.outcome_unknown".into(),
                        "enforcement_events.recovery_gap".into()],
                    events: vec![pb::sandbox::SandboxEventSummary {
                        timestamp: chrono::Utc::now().to_rfc3339(), kind: "task.recovered".into(),
                        message: "daemon interrupted before result commit; command was not replayed; effects may have occurred".into(),
                    }],
                    ..Default::default()
                };
                if let Some(container) = containers.first() {
                    // Consult the shim: a crash can occur after start but before
                    // the daemon persists the container's Running state.
                    let (state, _) = self.registry.get_container_state(&container.id).await?;
                    if state == "running" {
                        if let Err(error) = self.registry.stop_container(&container.id, 5).await {
                            // Exit may race StopContainer. Only a fresh shim
                            // confirmation of stopped permits recovery to proceed.
                            if !matches!(self.registry.get_container_state(&container.id).await,
                                Ok((state, _)) if state == "stopped")
                            {
                                return Err(error.into());
                            }
                        }
                    } else {
                        anyhow::ensure!(
                            state == "stopped" || state == "created",
                            "unknown recovered container state: {state}"
                        );
                    }
                    let logs = crate::logs::read_all_capped(
                        &container.id.to_string(),
                        &self.registry.config().paths.run_dir,
                        self.registry.config().evidence.sandbox_log_max_bytes,
                    );
                    result.stdout = logs.stdout;
                    result.stderr = logs.stderr;
                    result.capture_issues.extend(logs.issues);
                    // Broker bytes remain bounded on disk, but are not reconstructed
                    // into a complete event history after daemon interruption.
                    result.capture_issues.push("broker.recovery_gap".into());
                } else {
                    result
                        .capture_issues
                        .push("output.unavailable_after_interruption".into());
                }
                let result =
                    seal_bounded_result(result, record.receipt.clone(), &self.receipt_signer)
                        .map_err(anyhow::Error::msg)?;
                self.registry
                    .metadata()
                    .save_result(id, &result.encode_to_vec())?;
                tracing::warn!(task_id = %id, "recovered interrupted task without replay; signed uncertain result saved");
            }
            // A committed result is immutable, even if recovery crashes again
            // during cleanup. The record remains until cleanup succeeds.
            self.cleanup_recovered_task(&record).await?;
        }
        Ok(())
    }

    pub(super) async fn cleanup_recovered_task(
        &self,
        record: &RecoveryRecord,
    ) -> anyhow::Result<()> {
        if record.cleanup_zone {
            if let Some(zone) = self.registry.metadata().get_zone(&record.zone_name)? {
                anyhow::ensure!(
                    zone.id.to_string() == record.receipt.zone_id,
                    "recovery zone identity changed"
                );
                self.registry.delete_zone(&record.zone_name, true).await?;
            }
        } else {
            for container in self.task_containers(record)? {
                // Refresh an exit that raced the wait loop or a stop request.
                // Delete itself is idempotent at the shim if it is already gone.
                let _ = self.registry.get_container_state(&container.id).await;
                self.registry.delete_container(&container.id, true).await?;
            }
        }
        anyhow::ensure!(
            self.task_containers(record)?.is_empty(),
            "task container cleanup is incomplete"
        );
        self.registry
            .metadata()
            .finish_recovery(&record.receipt.task_id)?;
        sandbox_event_builder(
            &self.registry,
            event_name::SANDBOX_CLEANUP_SUCCEEDED,
            EventOutcome::Succeeded,
            &record.receipt.task_id,
            &record.zone_name,
            &record.receipt.zone_id,
        )
        .trust_level(TrustLevel::Complete)
        .emit();
        Ok(())
    }
}
