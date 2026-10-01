//! DSSE / in-toto envelope for execution receipts.
//!
//! The legacy [`SignedExecutionReceipt`](crate::receipt::SignedExecutionReceipt)
//! is a bespoke shape only Rauha can verify. This module wraps the same
//! payload as an [in-toto Statement] inside a [DSSE envelope], so standard
//! tooling (cosign `verify-blob-attestation`, Witness, in-toto verifiers)
//! consumes Rauha receipts unchanged.
//!
//! Signature correctness follows the DSSE spec exactly: the signature is
//! over the PAE (pre-authentication encoding) of `(payload_type, payload)`,
//! never over the payload alone — signing raw payloads is the classic DSSE
//! confusion-vulnerability this design exists to prevent.
//!
//! [in-toto Statement]: https://in-toto.io/Statement/v1
//! [DSSE envelope]: https://github.com/secure-systems-lab/dsse

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::receipt::{ExecutionReceiptPayload, ReceiptSigner, EXECUTION_RECEIPT_SCHEMA};

/// DSSE payload type for in-toto statements.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// in-toto statement type.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// Predicate type identifying a Rauha execution receipt.
pub const PREDICATE_TYPE: &str = "https://rauha.dev/execution/v0";

/// in-toto v1 statement: the receipt payload as a predicate, with the image
/// manifest as the attested subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub _type: String,
    pub subject: Vec<StatementSubject>,
    pub predicate_type: String,
    pub predicate: ExecutionReceiptPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementSubject {
    /// Image reference the task ran from.
    pub name: String,
    /// `{ "sha256": "<hex>" }` — the manifest digest captured at container
    /// creation, without the `sha256:` prefix (in-toto digest-set form).
    pub digest: std::collections::BTreeMap<String, String>,
}

/// DSSE envelope. `payload` is base64(standard) of the serialized statement;
/// each signature is base64(standard) Ed25519 over the PAE.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    /// `sha256:<hex>` of the Ed25519 verifying key — identifies which node
    /// key signed, per the DSSE keyid convention.
    pub keyid: String,
    pub sig: String,
}

impl ReceiptSigner {
    /// Wrap a receipt payload as a signed DSSE in-toto statement.
    pub fn sign_dsse(&self, payload: ExecutionReceiptPayload) -> DsseEnvelope {
        let statement = statement_from_payload(payload);
        // Sign the exact bytes that go into the envelope: verification must
        // never depend on re-serialization.
        let raw = serde_json::to_vec(&statement).expect("statement is serializable");
        let pae = pae(DSSE_PAYLOAD_TYPE, &raw);
        let sig = self.signing_key().sign(&pae);
        DsseEnvelope {
            payload_type: DSSE_PAYLOAD_TYPE.to_string(),
            payload: base64_encode(&raw),
            signatures: vec![DsseSignature {
                keyid: keyid(&self.verifying_key()),
                sig: base64_encode(&sig.to_bytes()),
            }],
        }
    }
}

impl DsseEnvelope {
    /// Verify the envelope signature and decode the statement.
    ///
    /// Verification is over the PAE of `(payload_type, decoded payload)`,
    /// which means both the statement bytes *and* the payload type are
    /// covered — an envelope whose type field was swapped after signing
    /// fails here.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<InTotoStatement, String> {
        if self.payload_type != DSSE_PAYLOAD_TYPE {
            return Err(format!(
                "unexpected DSSE payload type: {} (expected {DSSE_PAYLOAD_TYPE})",
                self.payload_type
            ));
        }
        let raw = base64_decode(&self.payload)
            .map_err(|e| format!("DSSE payload is not valid base64: {e}"))?;
        let pae = pae(&self.payload_type, &raw);
        let signature = self
            .signatures
            .first()
            .ok_or_else(|| "DSSE envelope has no signatures".to_string())?;
        let sig_bytes = base64_decode(&signature.sig)
            .map_err(|e| format!("DSSE signature is not valid base64: {e}"))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| "DSSE signature must be 64 bytes".to_string())?;
        verifying_key
            .verify(&pae, &sig)
            .map_err(|_| "DSSE signature verification failed".to_string())?;

        let statement: InTotoStatement = serde_json::from_slice(&raw)
            .map_err(|e| format!("DSSE payload is not a valid in-toto statement: {e}"))?;
        if statement._type != STATEMENT_TYPE {
            return Err(format!(
                "unexpected statement type: {} (expected {STATEMENT_TYPE})",
                statement._type
            ));
        }
        if statement.predicate_type != PREDICATE_TYPE {
            return Err(format!(
                "unexpected predicate type: {} (expected {PREDICATE_TYPE})",
                statement.predicate_type
            ));
        }
        if statement.predicate.schema != EXECUTION_RECEIPT_SCHEMA {
            return Err(format!(
                "unexpected predicate schema: {}",
                statement.predicate.schema
            ));
        }
        Ok(statement)
    }

    /// Verify against a hex-encoded Ed25519 public key (the format
    /// `receipt.ed25519.pub` publishes).
    pub fn verify_public_hex(&self, public_key_hex: &str) -> Result<InTotoStatement, String> {
        let key: [u8; 32] = hex::decode(public_key_hex.trim())
            .map_err(|_| "receipt public key is not hexadecimal".to_string())?
            .try_into()
            .map_err(|_| "receipt public key must be 32 bytes".to_string())?;
        let verifying_key = VerifyingKey::from_bytes(&key)
            .map_err(|_| "receipt public key is invalid".to_string())?;
        self.verify(&verifying_key)
    }
}

/// Build the in-toto statement for a receipt payload: subject is the image
/// manifest the task ran from, predicate is the receipt itself.
pub fn statement_from_payload(payload: ExecutionReceiptPayload) -> InTotoStatement {
    let digest_hex = payload
        .image
        .manifest_digest
        .strip_prefix("sha256:")
        .unwrap_or(&payload.image.manifest_digest)
        .to_string();
    InTotoStatement {
        _type: STATEMENT_TYPE.to_string(),
        subject: vec![StatementSubject {
            name: payload.image.reference.clone(),
            digest: [("sha256".to_string(), digest_hex)].into(),
        }],
        predicate_type: PREDICATE_TYPE.to_string(),
        predicate: payload,
    }
}

/// DSSE pre-authentication encoding:
/// `"DSSEv1 " || SP(L) || SP("mysha256") || ... ` — concretely
/// `"DSSEv1 <len(payload_type)> <payload_type> <len(payload)> <payload>`
/// over raw bytes. Lengths are ASCII decimal of the byte counts.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        "DSSEv1 ".len()
            + payload_type.len()
            + payload.len()
            + 2 * 10 // two decimal lengths, generous
            + 2,
    );
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// DSSE keyid convention: `sha256:<hex>` of the raw verifying key bytes.
pub fn keyid(verifying_key: &VerifyingKey) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(verifying_key.as_bytes()))
    )
}

/// Export the verifying key as SPKI DER wrapped in PEM — the public-key
/// format `cosign` and most ecosystem tooling expects.
pub fn verifying_key_spki_pem(verifying_key: &VerifyingKey) -> String {
    // Ed25519 SubjectPublicKeyInfo, DER:
    // SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING <32-byte key> }
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[0x30, 0x2a]); // SEQUENCE, 42 bytes
    spki.extend_from_slice(&[0x30, 0x05]); // algorithm SEQUENCE
    spki.extend_from_slice(&[0x06, 0x03, 0x2b, 0x65, 0x70]); // OID ed25519
    spki.extend_from_slice(&[0x03, 0x21, 0x00]); // BIT STRING, 33 bytes, 0 unused bits
    spki.extend_from_slice(verifying_key.as_bytes());

    let b64 = base64_encode(&spki);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ImageAdmission;
    use ed25519_dalek::SigningKey;

    fn sample_payload() -> ExecutionReceiptPayload {
        ExecutionReceiptPayload {
            schema: EXECUTION_RECEIPT_SCHEMA.into(),
            task_id: "task-1".into(),
            zone_id: "zone-1".into(),
            image: ImageAdmission {
                reference: "alpine@sha256:abc123".into(),
                manifest_digest: "sha256:def456".into(),
                digest_verified: true,
            },
            policy_sha256: "sha256:1111".into(),
            inputs_sha256: "sha256:2222".into(),
            outputs_sha256: "sha256:3333".into(),
            status: "succeeded".into(),
            exit_code: Some(0),
            started_at: Some("2026-09-28T10:00:00Z".into()),
            finished_at: Some("2026-09-28T10:00:01Z".into()),
            enforcement: Default::default(),
            unavailable_controls: vec!["ebpf:cgroup_attach_task".into()],
            capture_issues: Vec::new(),
        }
    }

    #[test]
    fn pae_matches_the_dsse_spec_example() {
        // The spec's canonical PAE example: payloadType "myschema",
        // payload "hello" (the spec uses "123" for one and this shape
        // generally) — the exact byte layout is what matters:
        // "DSSEv1 <len(type)> <type> <len(body)> <body>".
        assert_eq!(
            pae("myschema", b"hello"),
            b"DSSEv1 8 myschema 5 hello".to_vec()
        );
        // Empty body still encodes its zero length.
        assert_eq!(pae("t", b""), b"DSSEv1 1 t 0 ".to_vec());
        // Binary payloads are length-delimited, never escaped.
        assert_eq!(
            pae("t", &[0u8, 255, 10]),
            b"DSSEv1 1 t 3 \x00\xff\x0a".to_vec()
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let signer = ReceiptSigner::from_signing_key(SigningKey::from_bytes(&[7u8; 32]));
        let envelope = signer.sign_dsse(sample_payload());
        assert_eq!(envelope.payload_type, DSSE_PAYLOAD_TYPE);

        let statement = envelope
            .verify_public_hex(&hex::encode(signer.verifying_key().as_bytes()))
            .expect("round trip verifies");
        assert_eq!(statement.predicate.task_id, "task-1");
        // Subject is the image manifest, digest-set form without prefix.
        assert_eq!(statement.subject.len(), 1);
        assert_eq!(statement.subject[0].name, "alpine@sha256:abc123");
        assert_eq!(statement.subject[0].digest["sha256"], "def456");
        assert_eq!(statement.predicate_type, PREDICATE_TYPE);
    }

    #[test]
    fn tampered_payload_fails() {
        let signer = ReceiptSigner::from_signing_key(SigningKey::from_bytes(&[7u8; 32]));
        let mut envelope = signer.sign_dsse(sample_payload());

        // Decode, tamper with the task id, re-encode.
        let mut raw = base64_decode(&envelope.payload).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value["predicate"]["task_id"] = "task-evil".into();
        raw = serde_json::to_vec(&value).unwrap();
        envelope.payload = base64_encode(&raw);

        let err = envelope
            .verify_public_hex(&hex::encode(signer.verifying_key().as_bytes()))
            .unwrap_err();
        assert!(err.contains("verification failed"), "{err}");
    }

    #[test]
    fn swapped_payload_type_fails() {
        let signer = ReceiptSigner::from_signing_key(SigningKey::from_bytes(&[7u8; 32]));
        let mut envelope = signer.sign_dsse(sample_payload());
        envelope.payload_type = "application/vnd.other+json".into();
        // The signature covers the PAE including the type — a swapped type
        // fails either the type check or the signature.
        assert!(envelope
            .verify_public_hex(&hex::encode(signer.verifying_key().as_bytes()))
            .is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let signer = ReceiptSigner::from_signing_key(SigningKey::from_bytes(&[7u8; 32]));
        let envelope = signer.sign_dsse(sample_payload());
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(envelope
            .verify_public_hex(&hex::encode(other.verifying_key().as_bytes()))
            .is_err());
    }

    #[test]
    fn signature_is_over_pae_not_raw_payload() {
        // A signature over the payload bytes alone (the DSSE
        // confusion attack) must NOT verify through our PAE path.
        let signer = ReceiptSigner::from_signing_key(SigningKey::from_bytes(&[7u8; 32]));
        let statement = statement_from_payload(sample_payload());
        let raw = serde_json::to_vec(&statement).unwrap();
        let naive_sig = signer.signing_key().sign(&raw); // wrong: over raw payload
        let envelope = DsseEnvelope {
            payload_type: DSSE_PAYLOAD_TYPE.into(),
            payload: base64_encode(&raw),
            signatures: vec![DsseSignature {
                keyid: keyid(&signer.verifying_key()),
                sig: base64_encode(&naive_sig.to_bytes()),
            }],
        };
        assert!(envelope
            .verify_public_hex(&hex::encode(signer.verifying_key().as_bytes()))
            .is_err());
    }

    #[test]
    fn spki_pem_has_the_ed25519_shape() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pem = verifying_key_spki_pem(&key.verifying_key());
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
        // 44-byte DER body base64s to exactly 60 chars (one 64-col line).
        let body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("---")).collect();
        assert_eq!(body.len(), 1);
        assert_eq!(body[0].len(), 60);
    }

    #[test]
    fn envelope_serializes_with_the_dsse_camelcase_field_names() {
        // The DSSE/in-toto JSON wire format is camelCase (payloadType,
        // predicateType); snake_case here would break every external
        // verifier silently.
        let signer = ReceiptSigner::from_signing_key(SigningKey::from_bytes(&[7u8; 32]));
        let envelope = signer.sign_dsse(sample_payload());
        let json = serde_json::to_value(&envelope).unwrap();
        assert!(
            json.get("payloadType").is_some(),
            "payloadType missing: {json}"
        );
        assert!(json.get("signatures").is_some());
        let raw = base64_decode(json["payload"].as_str().unwrap()).unwrap();
        let statement: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(
            statement.get("predicateType").is_some(),
            "predicateType missing"
        );
        assert!(statement.get("_type").is_some(), "_type must stay literal");
    }

    #[test]
    fn keyid_is_sha256_of_verifying_key() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let expected = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(key.verifying_key().as_bytes()))
        );
        assert_eq!(keyid(&key.verifying_key()), expected);
    }
}
