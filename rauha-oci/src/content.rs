use sha2::{Digest as Sha2Digest, Sha256};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A content digest in the form `sha256:{hex}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest(String);

impl Digest {
    /// Create a digest from a `sha256:{hex}` string.
    pub fn parse(s: &str) -> Option<Self> {
        let hex_part = s.strip_prefix("sha256:")?;
        if hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(Self(s.to_ascii_lowercase()))
        } else {
            None
        }
    }

    /// Compute the SHA256 digest of data.
    pub fn from_data(data: &[u8]) -> Self {
        let hash = Sha256::digest(data);
        Self(format!("sha256:{}", hex::encode(hash)))
    }

    /// Validate that data matches this digest.
    pub fn validate(&self, data: &[u8]) -> bool {
        Self::from_data(data) == *self
    }

    /// The hex portion of the digest.
    pub fn hex(&self) -> &str {
        // Safe: constructor guarantees format.
        &self.0["sha256:".len()..]
    }

    /// Full `sha256:{hex}` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Content-addressable blob storage backed by the filesystem.
///
/// Layout:
/// ```text
/// {root}/blobs/sha256/{hex-digest}     — raw blob data
/// {root}/references-v2/{name-hash}.json — full reference identity and manifest digest
/// ```
pub struct ContentStore {
    root: PathBuf,
}

impl ContentStore {
    pub fn new(root: &Path) -> std::io::Result<Self> {
        let blobs_dir = root.join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs_dir)?;
        // Old filenames lost reference identity; never guess which name they meant.
        std::fs::create_dir_all(root.join("references-v2"))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.root.join("blobs").join("sha256").join(digest.hex())
    }

    /// Store a blob, returning its digest.
    pub fn put_blob(&self, data: &[u8]) -> std::io::Result<Digest> {
        let digest = Digest::from_data(data);
        let path = self.blob_path(&digest);
        if !path.exists() {
            atomic_write(&path, data)?;
        }
        Ok(digest)
    }

    /// Read a blob by digest.
    pub fn get_blob(&self, digest: &Digest) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.blob_path(digest))
    }

    /// Check if a blob exists.
    pub fn has_blob(&self, digest: &Digest) -> bool {
        self.blob_path(digest).exists()
    }

    /// Store a manifest and link it to a reference name.
    pub fn put_manifest(&self, reference: &str, manifest: &[u8]) -> std::io::Result<Digest> {
        let digest = self.put_blob(manifest)?;
        let ref_path = self.manifest_ref_path(reference);
        let record = serde_json::to_vec(&(reference, digest.as_str()))?;
        atomic_write(&ref_path, &record)?;
        Ok(digest)
    }

    /// Get the manifest bytes for a reference.
    pub fn get_manifest(&self, reference: &str) -> std::io::Result<Option<Vec<u8>>> {
        let ref_path = self.manifest_ref_path(reference);
        let record = match std::fs::read(&ref_path) {
            Ok(record) => record,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let (stored_reference, digest_str): (String, String) = serde_json::from_slice(&record)?;
        if stored_reference != reference {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "image reference identity mismatch",
            ));
        }
        let digest = Digest::parse(&digest_str).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupt manifest reference",
            )
        })?;
        Ok(Some(self.get_blob(&digest)?))
    }

    /// Path to the blob data for a given digest (for direct file access, e.g. layer unpacking).
    pub fn blob_file_path(&self, digest: &Digest) -> PathBuf {
        self.blob_path(digest)
    }

    pub(crate) fn manifest_ref_path(&self, reference: &str) -> PathBuf {
        let key = Digest::from_data(reference.as_bytes());
        self.root
            .join("references-v2")
            .join(format!("{}.json", key.hex()))
    }

    pub(crate) fn temporary_blob(&self) -> std::io::Result<tempfile::NamedTempFile> {
        tempfile::NamedTempFile::new_in(self.root.join("blobs/sha256"))
    }

    pub(crate) fn publish_blob(
        &self,
        file: tempfile::NamedTempFile,
        digest: &Digest,
    ) -> std::io::Result<()> {
        file.as_file().sync_all()?;
        file.persist(self.blob_path(digest))
            .map_err(|error| error.error)?;
        std::fs::File::open(self.root.join("blobs/sha256"))?.sync_all()
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().expect("content paths have a parent");
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_references_do_not_alias_or_use_ambiguous_legacy_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();
        let a = "ghcr.io/team/a_b:latest";
        let b = "ghcr.io/team/a/b:latest";
        store.put_manifest(a, b"A").unwrap();
        store.put_manifest(b, b"B").unwrap();
        assert_eq!(store.get_manifest(a).unwrap().unwrap(), b"A");
        assert_eq!(store.get_manifest(b).unwrap().unwrap(), b"B");
        std::fs::create_dir(dir.path().join("manifests")).unwrap();
        std::fs::write(dir.path().join("manifests/old.json"), b"untrusted identity").unwrap();
        assert!(store.get_manifest("old").unwrap().is_none());
    }

    #[test]
    fn digest_roundtrip() {
        let data = b"hello world";
        let digest = Digest::from_data(data);
        assert!(digest.as_str().starts_with("sha256:"));
        assert!(digest.validate(data));
        assert!(!digest.validate(b"wrong"));
    }

    #[test]
    fn digest_parse() {
        let hex = "a".repeat(64);
        let valid = format!("sha256:{hex}");
        assert!(Digest::parse(&valid).is_some());
        assert!(Digest::parse("md5:abc").is_none());
        assert!(Digest::parse("sha256:tooshort").is_none());
    }

    #[test]
    fn content_store_put_get() {
        let dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let data = b"test blob content";
        let digest = store.put_blob(data).unwrap();

        assert!(store.has_blob(&digest));
        assert_eq!(store.get_blob(&digest).unwrap(), data);
    }

    #[test]
    fn content_store_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let store = ContentStore::new(dir.path()).unwrap();

        let manifest = br#"{"schemaVersion": 2}"#;
        store
            .put_manifest("docker.io/library/nginx:latest", manifest)
            .unwrap();

        let loaded = store
            .get_manifest("docker.io/library/nginx:latest")
            .unwrap();
        assert_eq!(loaded.unwrap(), manifest);

        assert!(store.get_manifest("nonexistent").unwrap().is_none());
    }
}
