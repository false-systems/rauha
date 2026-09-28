use std::path::PathBuf;

use clap::Args;
use rauha_evidence::receipt::SignedExecutionReceipt;

use super::output::{self, OutputMode};

#[derive(Args)]
pub struct ReceiptArgs {
    /// Receipt JSON or `rauha sandbox --json` output containing a receipt.
    /// Both forms are accepted: the legacy signed receipt and the DSSE
    /// in-toto envelope.
    pub file: PathBuf,
    /// Trusted daemon Ed25519 public-key file (hex, as published by rauhad).
    #[arg(long)]
    pub public_key: PathBuf,
}

pub fn verify(args: ReceiptArgs, out: OutputMode) -> anyhow::Result<()> {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&args.file)?)?;
    let trusted_public_key = std::fs::read_to_string(&args.public_key)?;

    // A `rauha sandbox --json` output wraps the receipt under "result"; a
    // bare receipt file is used directly.
    let candidate = value
        .get("result")
        .or_else(|| value.get("receipt"))
        .cloned()
        .unwrap_or(value);
    if candidate.get("payloadType").is_some() && candidate.get("signatures").is_some() {
        return verify_dsse(candidate, &trusted_public_key, out);
    }
    verify_legacy(candidate, &trusted_public_key, out)
}

/// Verify the legacy `rauha.execution-receipt.v1` signed receipt.
fn verify_legacy(
    value: serde_json::Value,
    trusted_public_key: &str,
    out: OutputMode,
) -> anyhow::Result<()> {
    let receipt: SignedExecutionReceipt = serde_json::from_value(value)?;
    receipt
        .verify_trusted(trusted_public_key)
        .map_err(anyhow::Error::msg)?;
    let digest = receipt.sha256();
    let result = output::ReceiptVerification {
        ok: true,
        schema: receipt.payload.schema,
        task_id: receipt.payload.task_id,
        digest,
    };
    output::print(out, &result, || {
        println!("verified: {} {}", result.task_id, result.digest)
    });
    Ok(())
}

/// Verify a DSSE envelope wrapping an in-toto statement (subject = image
/// manifest digest, predicate = the execution receipt).
fn verify_dsse(
    value: serde_json::Value,
    trusted_public_key: &str,
    out: OutputMode,
) -> anyhow::Result<()> {
    let envelope: rauha_evidence::dsse::DsseEnvelope = serde_json::from_value(value)?;
    let statement = envelope
        .verify_public_hex(trusted_public_key)
        .map_err(anyhow::Error::msg)?;
    let subject = statement
        .subject
        .first()
        .map(|s| {
            format!(
                "{}@{}",
                s.name,
                s.digest.get("sha256").cloned().unwrap_or_default()
            )
        })
        .unwrap_or_default();
    let result = output::ReceiptVerification {
        ok: true,
        schema: format!(
            "{} ({} dsse)",
            statement.predicate.schema, envelope.payload_type
        ),
        task_id: statement.predicate.task_id,
        digest: format!("sha256:{}", sha256_hex(envelope.payload.as_bytes())),
    };
    output::print(out, &result, || {
        println!(
            "verified: {} {} [{}] {}",
            result.task_id, result.digest, envelope.payload_type, subject
        )
    });
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(bytes))
}
