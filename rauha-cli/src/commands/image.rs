use clap::Subcommand;

pub mod pb {
    pub mod image {
        tonic::include_proto!("rauha.image.v1");
    }
}

use pb::image::image_service_client::ImageServiceClient;

use super::output::{self, OutputMode};

#[derive(Subcommand)]
pub enum ImageAction {
    /// Pull an image from a registry
    Pull { reference: String },
    /// List local images
    #[command(name = "ls")]
    List,
    /// Remove a local image
    Remove { reference: String },
    /// Show image details
    Inspect { reference: String },
}

pub async fn handle(action: ImageAction, out: OutputMode) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ImageServiceClient::new(channel);

    match action {
        ImageAction::Pull { reference } => {
            if out == OutputMode::Human {
                println!("Pulling {reference}...");
            }

            let stream = client
                .pull(pb::image::PullRequest {
                    reference: reference.clone(),
                })
                .await?
                .into_inner();
            consume_pull_progress(stream, &reference, out).await?;
            output::print(
                out,
                &output::ImagePulled {
                    ok: true,
                    reference,
                },
                || {},
            );
        }
        ImageAction::List => {
            let resp = client
                .list(pb::image::ListImagesRequest {})
                .await?
                .into_inner();

            let images: Vec<output::ImageInfo> = resp
                .images
                .iter()
                .map(|img| output::ImageInfo {
                    reference: img.tags.first().cloned().unwrap_or_default(),
                    digest: img.digest.clone(),
                    size: img.size,
                    tags: img.tags.clone(),
                })
                .collect();

            output::print(out, &output::ImageList { ok: true, images }, || {
                if resp.images.is_empty() {
                    println!("No images.");
                } else {
                    println!("{:<50} {:<20} {:<10}", "REFERENCE", "DIGEST", "SIZE");
                    for img in &resp.images {
                        let tag = img.tags.first().cloned().unwrap_or_default();
                        let digest_short = if img.digest.len() > 19 {
                            format!("{}...", &img.digest[..19])
                        } else {
                            img.digest.clone()
                        };
                        let size_mb = img.size as f64 / 1_048_576.0;
                        println!("{:<50} {:<20} {:.1}MB", tag, digest_short, size_mb);
                    }
                }
            });
        }
        ImageAction::Remove { reference } => {
            client
                .remove(pb::image::RemoveImageRequest {
                    reference: reference.clone(),
                })
                .await?;

            output::print(
                out,
                &output::ImageRemoved {
                    ok: true,
                    reference: reference.clone(),
                },
                || println!("Removed: {reference}"),
            );
        }
        ImageAction::Inspect { reference } => {
            let resp = client
                .inspect(pb::image::InspectImageRequest {
                    reference: reference.clone(),
                })
                .await?
                .into_inner();

            let config: serde_json::Value = if resp.config_json.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&resp.config_json).unwrap_or(serde_json::Value::Null)
            };

            output::print(
                out,
                &output::ImageInspect {
                    ok: true,
                    reference: reference.clone(),
                    digest: resp.digest.clone(),
                    size: resp.size,
                    config,
                },
                || {
                    println!("Reference: {reference}");
                    if !resp.digest.is_empty() {
                        println!("Digest:    {}", resp.digest);
                    }
                    println!("Size:      {} bytes", resp.size);
                    if !resp.config_json.is_empty() {
                        println!("Config:");
                        println!("{}", resp.config_json);
                    }
                },
            );
        }
    }
    Ok(())
}

/// Consume a pull progress stream: human mode prints a single-line progress
/// display, JSON mode stays silent (the caller emits the structured result).
/// Shared by `rauha image pull` and the sandbox pull-if-absent path.
pub(super) async fn consume_pull_progress(
    mut stream: tonic::Streaming<pb::image::PullProgress>,
    reference: &str,
    out: OutputMode,
) -> anyhow::Result<()> {
    use tokio_stream::StreamExt;

    if out != OutputMode::Human {
        while let Some(progress) = stream.next().await {
            progress?;
        }
        return Ok(());
    }

    use std::io::Write;
    let mut last_status = String::new();
    while let Some(progress) = stream.next().await {
        match progress {
            Ok(p) => {
                if p.done {
                    if !last_status.is_empty() {
                        print!("\r{}\r", " ".repeat(60));
                    }
                    println!("Pull complete: {reference}");
                } else if p.total > 0 {
                    let pct = (p.current as f64 / p.total as f64 * 100.0) as u32;
                    let size_mb = p.total as f64 / 1_048_576.0;
                    let msg = format!("  {} {:.1}MB {pct}%", p.status, size_mb);
                    print!("\r{msg:<60}");
                    let _ = std::io::stdout().flush();
                    last_status = msg;
                } else {
                    if !last_status.is_empty() {
                        print!("\r{}\r", " ".repeat(60));
                        let _ = std::io::stdout().flush();
                    }
                    println!("  {}", p.status);
                    last_status.clear();
                }
            }
            Err(e) => {
                println!();
                return Err(e.into());
            }
        }
    }
    Ok(())
}
