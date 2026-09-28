use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EXECUTION_RECEIPT_SCHEMA: &str = "rauha.execution-receipt.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageAdmission {
    pub reference: String,
    /// Manifest digest of the image the container was built from, captured at
    /// container creation.
    pub manifest_digest: String,
    /// True only when `reference` pinned a digest and `manifest_digest` matches
    /// it. A tag that resolved or a cached manifest leaves this false.
    pub digest_verified: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementTotals {
    pub allow: u64,
    pub deny: u64,
    pub error: u64,
    pub dropped: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceiptPayload {
    pub schema: String,
    pub task_id: String,
    pub zone_id: String,
    pub image: ImageAdmission,
    pub policy_sha256: String,
    pub inputs_sha256: String,
    pub outputs_sha256: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub enforcement: EnforcementTotals,
    pub unavailable_controls: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExecutionReceipt {
    pub payload: ExecutionReceiptPayload,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct ReceiptSigner(SigningKey);

impl ReceiptSigner {
    /// Crate-internal: the signing key (used by the DSSE layer).
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.0
    }

    /// The public half of the receipt signing key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// Crate-internal test constructor.
    #[cfg(test)]
    pub(crate) fn from_signing_key(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        match read_key(path) {
            Ok(key) => return Ok(Self(SigningKey::from_bytes(&key))),
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("failed to read receipt signing key: {error}"));
            }
            Err(_) => {}
        }

        let parent = path
            .parent()
            .ok_or_else(|| "receipt signing key path has no parent".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create receipt key directory: {error}"))?;
        let mut key = [0u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut key))
            .map_err(|error| format!("failed to generate receipt signing key: {error}"))?;

        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(mut file) => {
                file.write_all(&key)
                    .and_then(|_| file.sync_all())
                    .map_err(|error| format!("failed to persist receipt signing key: {error}"))?;
                Ok(Self(SigningKey::from_bytes(&key)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_key(path)
                .map(|key| Self(SigningKey::from_bytes(&key)))
                .map_err(|error| format!("failed to read concurrent receipt key: {error}")),
            Err(error) => Err(format!("failed to create receipt signing key: {error}")),
        }
    }

    pub fn sign(&self, payload: ExecutionReceiptPayload) -> SignedExecutionReceipt {
        let bytes = serde_json::to_vec(&payload).expect("receipt payload is serializable");
        SignedExecutionReceipt {
            signature: hex::encode(self.0.sign(&bytes).to_bytes()),
            public_key: hex::encode(self.0.verifying_key().to_bytes()),
            payload,
        }
    }

    pub fn publish_public_key(&self, path: &Path) -> Result<(), String> {
        let expected = format!("{}\n", hex::encode(self.0.verifying_key().to_bytes()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)
        {
            Ok(mut file) => file
                .write_all(expected.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("failed to publish receipt public key: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let actual = read_public_key(path)
                    .map_err(|error| format!("failed to read receipt public key: {error}"))?;
                if actual == expected.trim() {
                    Ok(())
                } else {
                    Err("receipt public key does not match the signing key".into())
                }
            }
            Err(error) => Err(format!("failed to publish receipt public key: {error}")),
        }
    }
}

impl SignedExecutionReceipt {
    pub fn verify(&self) -> Result<(), String> {
        if self.payload.schema != EXECUTION_RECEIPT_SCHEMA {
            return Err(format!(
                "unsupported receipt schema: {}",
                self.payload.schema
            ));
        }
        let public_key: [u8; 32] = hex::decode(&self.public_key)
            .map_err(|_| "receipt public key is not hexadecimal".to_string())?
            .try_into()
            .map_err(|_| "receipt public key must be 32 bytes".to_string())?;
        let signature = Signature::from_slice(
            &hex::decode(&self.signature)
                .map_err(|_| "receipt signature is not hexadecimal".to_string())?,
        )
        .map_err(|_| "receipt signature must be 64 bytes".to_string())?;
        let bytes = serde_json::to_vec(&self.payload)
            .map_err(|error| format!("failed to serialize receipt payload: {error}"))?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| "receipt public key is invalid".to_string())?
            .verify_strict(&bytes, &signature)
            .map_err(|_| "receipt signature verification failed".to_string())
    }

    pub fn verify_trusted(&self, trusted_public_key: &str) -> Result<(), String> {
        if self.public_key != trusted_public_key.trim() {
            return Err("receipt signer does not match the trusted public key".into());
        }
        self.verify()
    }

    pub fn sha256(&self) -> String {
        sha256_bytes(&serde_json::to_vec(self).expect("receipt is serializable"))
    }
}

pub fn sha256_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_vec(value).map(|bytes| sha256_bytes(&bytes))
}

pub fn enforcement_totals<I>(decisions: I, dropped: u64) -> EnforcementTotals
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let mut counts = BTreeMap::new();
    for decision in decisions {
        *counts.entry(decision.as_ref().to_string()).or_insert(0u64) += 1;
    }
    EnforcementTotals {
        allow: counts.remove("allow").unwrap_or_default(),
        deny: counts.remove("deny").unwrap_or_default(),
        error: counts.remove("error").unwrap_or_default(),
        dropped,
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn read_key(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if file.metadata()?.mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "receipt signing key must not be accessible by group or others",
        ));
    }
    let mut key = [0u8; 32];
    file.read_exact(&mut key)?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "receipt signing key must be exactly 32 bytes",
        ));
    }
    Ok(key)
}

fn read_public_key(path: &Path) -> std::io::Result<String> {
    let mut value = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .read_to_string(&mut value)?;
    Ok(value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> ExecutionReceiptPayload {
        ExecutionReceiptPayload {
            schema: EXECUTION_RECEIPT_SCHEMA.into(),
            task_id: "task-1".into(),
            zone_id: "zone-1".into(),
            image: ImageAdmission {
                reference: "example/image@sha256:abc".into(),
                manifest_digest: "sha256:abc".into(),
                digest_verified: true,
            },
            policy_sha256: "sha256:policy".into(),
            inputs_sha256: "sha256:inputs".into(),
            outputs_sha256: "sha256:outputs".into(),
            status: "succeeded".into(),
            exit_code: Some(0),
            started_at: None,
            finished_at: None,
            enforcement: EnforcementTotals::default(),
            unavailable_controls: Vec::new(),
        }
    }

    #[test]
    fn signed_receipt_detects_payload_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let signer = ReceiptSigner::load_or_create(&dir.path().join("receipt.key")).unwrap();
        signer
            .publish_public_key(&dir.path().join("receipt.pub"))
            .unwrap();
        let mut receipt = signer.sign(payload());
        let trusted = std::fs::read_to_string(dir.path().join("receipt.pub")).unwrap();
        receipt.verify_trusted(&trusted).unwrap();
        receipt.payload.status = "failed".into();
        assert!(receipt.verify().is_err());
    }

    #[test]
    fn enforcement_totals_include_observed_drops() {
        assert_eq!(
            enforcement_totals(["allow", "deny", "deny", "error"], 3),
            EnforcementTotals {
                allow: 1,
                deny: 2,
                error: 1,
                dropped: 3,
            }
        );
    }
}
