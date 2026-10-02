//! Results share the existing transactional metadata store. Empty entries reserve
//! capacity before execution and survive interruption; they are never replayed.
use super::db::MetadataStore;
use rauha_common::sandbox::MAX_RESULT_BYTES;
use redb::{ReadableTable, TableDefinition};

pub(super) const RESULTS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("sandbox_results");

impl MetadataStore {
    pub fn reserve_result(&self, id: &str, max_bytes: usize) -> anyhow::Result<bool> {
        let transaction = self.db.begin_write()?;
        {
            let mut table = transaction.open_table(RESULTS_TABLE)?;
            if table.get(id)?.is_some() {
                return Ok(false);
            }
            // ponytail: scan retained entries under the write transaction;
            // add a transactional byte counter if large histories make this costly.
            let mut used = 0usize;
            let recovery = transaction.open_table(super::recovery::RECOVERY_TABLE)?;
            for entry in table.iter()? {
                let (id, value) = entry?;
                used = used.saturating_add(
                    if value.value().is_empty() || recovery.get(id.value())?.is_some() {
                        MAX_RESULT_BYTES
                    } else {
                        value.value().len()
                    },
                );
            }
            // Interrupted reservations still consume their full wire budget.
            anyhow::ensure!(
                used.saturating_add(MAX_RESULT_BYTES) <= max_bytes,
                "result capacity exhausted; delete retained results before starting another task"
            );
            table.insert(id, &[] as &[u8])?;
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn save_result(&self, id: &str, bytes: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_RESULT_BYTES,
            "result exceeds wire budget"
        );
        let transaction = self.db.begin_write()?;
        {
            let mut table = transaction.open_table(RESULTS_TABLE)?;
            anyhow::ensure!(
                table.get(id)?.is_some_and(|value| value.value().is_empty()),
                "result reservation missing or already completed"
            );
            table.insert(id, bytes)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn get_result(&self, id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let transaction = self.db.begin_read()?;
        let table = transaction.open_table(RESULTS_TABLE)?;
        Ok(table.get(id)?.map(|value| value.value().to_vec()))
    }

    pub fn delete_result(&self, id: &str) -> anyhow::Result<bool> {
        let transaction = self.db.begin_write()?;
        anyhow::ensure!(
            transaction
                .open_table(super::recovery::RECOVERY_TABLE)?
                .get(id)?
                .is_none(),
            "task still requires recovery or cleanup"
        );
        let removed = transaction.open_table(RESULTS_TABLE)?.remove(id)?.is_some();
        transaction.commit()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_bound_storage_prevent_replay_and_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metadata.redb");
        let store = MetadataStore::open(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(store.reserve_result("one", MAX_RESULT_BYTES).unwrap());
        assert!(!store.reserve_result("one", MAX_RESULT_BYTES).unwrap());
        assert!(store.reserve_result("two", MAX_RESULT_BYTES).is_err());
        drop(store);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let store = MetadataStore::open(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(store.get_result("one").unwrap(), Some(Vec::new()));
        store.save_result("one", b"signed result").unwrap();
        assert!(store.save_result("one", b"replacement").is_err());
        drop(store);
        let store = MetadataStore::open(&path).unwrap();
        assert_eq!(store.get_result("one").unwrap().unwrap(), b"signed result");
        assert!(store.delete_result("one").unwrap());
        assert!(store.reserve_result("two", MAX_RESULT_BYTES).unwrap());
    }
}
