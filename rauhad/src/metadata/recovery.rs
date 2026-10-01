//! Write-ahead context for admitted sandbox tasks. No command or effect is replayed.
use super::db::MetadataStore;
use rauha_common::{sandbox::MAX_RESULT_BYTES, zone::PolicyAdmission};
use rauha_evidence::receipt::ExecutionReceiptPayload;
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

pub(super) const RECOVERY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("sandbox_recovery_v1");

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryRecord {
    pub zone_name: String,
    pub container_id: Option<uuid::Uuid>,
    pub cleanup_zone: bool,
    pub command: Vec<String>,
    pub admission: PolicyAdmission,
    pub receipt: ExecutionReceiptPayload,
}

impl MetadataStore {
    pub fn put_recovery(&self, record: &RecoveryRecord) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(record)?;
        anyhow::ensure!(
            bytes.len() <= MAX_RESULT_BYTES,
            "recovery context exceeds metadata budget"
        );
        let transaction = self.db.begin_write()?;
        {
            let results = transaction.open_table(super::results::RESULTS_TABLE)?;
            anyhow::ensure!(
                results
                    .get(record.receipt.task_id.as_str())?
                    .is_some_and(|v| v.value().is_empty()),
                "recovery context requires an unfinished result reservation"
            );
            transaction
                .open_table(RECOVERY_TABLE)?
                .insert(record.receipt.task_id.as_str(), bytes.as_slice())?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn recovery_records(&self) -> anyhow::Result<Vec<RecoveryRecord>> {
        let transaction = self.db.begin_read()?;
        let table = transaction.open_table(RECOVERY_TABLE)?;
        table
            .iter()?
            .map(|entry| {
                let (id, value) = entry?;
                let record: RecoveryRecord = serde_json::from_slice(value.value())?;
                anyhow::ensure!(
                    id.value() == record.receipt.task_id,
                    "recovery task identity mismatch"
                );
                Ok(record)
            })
            .collect()
    }

    pub fn finish_recovery(&self, id: &str) -> anyhow::Result<()> {
        let transaction = self.db.begin_write()?;
        anyhow::ensure!(
            transaction
                .open_table(super::results::RESULTS_TABLE)?
                .get(id)?
                .is_some_and(|v| !v.value().is_empty()),
            "cannot discard recovery context before result commit"
        );
        transaction.open_table(RECOVERY_TABLE)?.remove(id)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn has_recovery(&self, id: &str) -> anyhow::Result<bool> {
        let transaction = self.db.begin_read()?;
        Ok(transaction.open_table(RECOVERY_TABLE)?.get(id)?.is_some())
    }
}
