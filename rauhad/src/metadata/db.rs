use rauha_common::container::Container;
use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::Zone;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

const ZONES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("zones");
const CONTAINERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("containers");

/// Persistent metadata store backed by redb.
///
/// Stores zone and container metadata with ACID transactions.
/// redb is pure Rust, zero C deps — aligns with Rauha's dependency philosophy.
pub struct MetadataStore {
    pub(super) db: Arc<Database>,
}

impl MetadataStore {
    pub fn open(path: &Path) -> Result<Self> {
        // This database also holds workload output. Create it privately and
        // tighten databases made by older versions before adding result data.
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        drop(file);
        let db = Database::create(path).map_err(|e| RauhaError::MetadataError(e.to_string()))?;

        // Ensure tables exist.
        let write_txn = db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(ZONES_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            let _ = write_txn
                .open_table(CONTAINERS_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            write_txn
                .open_table(super::results::RESULTS_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;

        Ok(Self { db: Arc::new(db) })
    }

    // --- Zone operations ---

    pub fn put_zone(&self, zone: &Zone) -> Result<()> {
        let data =
            postcard::to_allocvec(zone).map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(ZONES_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .insert(zone.name.as_str(), data.as_slice())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn get_zone(&self, name: &str) -> Result<Option<Zone>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(ZONES_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        match table.get(name) {
            Ok(Some(value)) => match postcard::from_bytes::<Zone>(value.value()) {
                Ok(zone) => Ok(Some(zone)),
                Err(e) => {
                    tracing::warn!(
                        zone = name,
                        error = %e,
                        "zone metadata is incompatible (schema changed?) — treating as missing"
                    );
                    Ok(None)
                }
            },
            Ok(None) => Ok(None),
            Err(e) => Err(RauhaError::MetadataError(e.to_string())),
        }
    }

    pub fn delete_zone(&self, name: &str) -> Result<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(ZONES_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .remove(name)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(ZONES_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let mut zones = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?
        {
            let (key, value) = entry.map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            match postcard::from_bytes::<Zone>(value.value()) {
                Ok(zone) => zones.push(zone),
                Err(e) => {
                    // Schema migration: old entries may not have new fields.
                    // Skip them rather than crashing the daemon.
                    tracing::warn!(
                        zone = key.value(),
                        error = %e,
                        "skipping zone with incompatible metadata (schema changed?) — \
                         delete stale db or re-create the zone"
                    );
                }
            }
        }
        Ok(zones)
    }

    // --- Container operations ---

    pub fn put_container(&self, container: &Container) -> Result<()> {
        let data = postcard::to_allocvec(container)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let key = container.id.to_string();
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(CONTAINERS_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .insert(key.as_str(), data.as_slice())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn get_container(&self, id: &Uuid) -> Result<Option<Container>> {
        let key = id.to_string();
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(CONTAINERS_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        match table.get(key.as_str()) {
            Ok(Some(value)) => {
                let container: Container = postcard::from_bytes(value.value())
                    .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
                Ok(Some(container))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(RauhaError::MetadataError(e.to_string())),
        }
    }

    pub fn delete_container(&self, id: &Uuid) -> Result<()> {
        let key = id.to_string();
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(CONTAINERS_TABLE)
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            table
                .remove(key.as_str())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        Ok(())
    }

    pub fn list_containers(&self, zone_id: Option<&Uuid>) -> Result<Vec<Container>> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let table = read_txn
            .open_table(CONTAINERS_TABLE)
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
        let mut containers = Vec::new();
        for entry in table
            .iter()
            .map_err(|e| RauhaError::MetadataError(e.to_string()))?
        {
            let (_, value) = entry.map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            let container: Container = postcard::from_bytes(value.value())
                .map_err(|e| RauhaError::MetadataError(e.to_string()))?;
            if let Some(zid) = zone_id {
                if &container.zone_id == zid {
                    containers.push(container);
                }
            } else {
                containers.push(container);
            }
        }
        Ok(containers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_common::zone::*;
    use tempfile::NamedTempFile;

    fn test_db() -> MetadataStore {
        let tmp = NamedTempFile::new().unwrap();
        MetadataStore::open(tmp.path()).unwrap()
    }

    #[test]
    fn test_zone_crud() {
        let db = test_db();
        let zone = Zone {
            id: Uuid::new_v4(),
            name: "test-zone".into(),
            zone_type: ZoneType::NonGlobal,
            state: ZoneState::Ready,
            policy: ZonePolicy::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            network_state: None,
        };

        db.put_zone(&zone).unwrap();

        let loaded = db.get_zone("test-zone").unwrap().unwrap();
        assert_eq!(loaded.id, zone.id);
        assert_eq!(loaded.name, "test-zone");

        let zones = db.list_zones().unwrap();
        assert_eq!(zones.len(), 1);

        db.delete_zone("test-zone").unwrap();
        assert!(db.get_zone("test-zone").unwrap().is_none());
    }

    #[test]
    fn test_container_crud() {
        use rauha_common::container::{Container, ContainerState};

        let db = test_db();
        let zone_id = Uuid::new_v4();
        let container = Container {
            id: Uuid::new_v4(),
            name: "test-ctr".into(),
            zone_id,
            image: "alpine:latest".into(),
            state: ContainerState::Created,
            pid: Some(1234),
            created_at: chrono::Utc::now(),
            started_at: None,
            finished_at: None,
            exit_code: None,
        };

        db.put_container(&container).unwrap();

        let loaded = db.get_container(&container.id).unwrap().unwrap();
        assert_eq!(loaded.name, "test-ctr");
        assert_eq!(loaded.zone_id, zone_id);
        assert_eq!(loaded.state, ContainerState::Created);

        // Update state.
        let mut updated = loaded;
        updated.state = ContainerState::Running;
        updated.started_at = Some(chrono::Utc::now());
        db.put_container(&updated).unwrap();
        let reloaded = db.get_container(&container.id).unwrap().unwrap();
        assert_eq!(reloaded.state, ContainerState::Running);

        // Delete.
        db.delete_container(&container.id).unwrap();
        assert!(db.get_container(&container.id).unwrap().is_none());
    }

    #[test]
    fn test_list_containers_by_zone() {
        use rauha_common::container::{Container, ContainerState};

        let db = test_db();
        let zone_a = Uuid::new_v4();
        let zone_b = Uuid::new_v4();
        let now = chrono::Utc::now();

        for (i, zone_id) in [(0, zone_a), (1, zone_a), (2, zone_b)] {
            let c = Container {
                id: Uuid::new_v4(),
                name: format!("ctr-{i}"),
                zone_id,
                image: "alpine:latest".into(),
                state: ContainerState::Created,
                pid: Some(1000 + i),
                created_at: now,
                started_at: None,
                finished_at: None,
                exit_code: None,
            };
            db.put_container(&c).unwrap();
        }

        // All containers.
        assert_eq!(db.list_containers(None).unwrap().len(), 3);
        // Filtered by zone_a.
        assert_eq!(db.list_containers(Some(&zone_a)).unwrap().len(), 2);
        // Filtered by zone_b.
        assert_eq!(db.list_containers(Some(&zone_b)).unwrap().len(), 1);
        // Non-existent zone.
        assert_eq!(db.list_containers(Some(&Uuid::new_v4())).unwrap().len(), 0);
    }

    #[test]
    fn test_get_nonexistent_zone() {
        let db = test_db();
        assert!(db.get_zone("nope").unwrap().is_none());
    }

    #[test]
    fn test_get_nonexistent_container() {
        let db = test_db();
        assert!(db.get_container(&Uuid::new_v4()).unwrap().is_none());
    }

    #[test]
    fn test_multiple_zones() {
        let db = test_db();
        for i in 0..5 {
            let zone = Zone {
                id: Uuid::new_v4(),
                name: format!("zone-{i}"),
                zone_type: ZoneType::NonGlobal,
                state: ZoneState::Ready,
                policy: ZonePolicy::default(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                network_state: None,
            };
            db.put_zone(&zone).unwrap();
        }

        assert_eq!(db.list_zones().unwrap().len(), 5);

        // Delete one, verify count.
        db.delete_zone("zone-2").unwrap();
        assert_eq!(db.list_zones().unwrap().len(), 4);
        assert!(db.get_zone("zone-2").unwrap().is_none());
    }
}
