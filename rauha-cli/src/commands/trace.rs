use clap::Args;
use serde::Serialize;
use tokio_stream::StreamExt;

use super::{connect, output::OutputMode};

mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
}

#[derive(Args)]
pub struct TraceArgs {
    #[arg(long)]
    pub zone: String,
}

#[derive(Args)]
pub struct TopArgs {
    #[arg(long)]
    pub zone: Option<String>,
}

#[derive(Args)]
pub struct EventsArgs {
    /// Filter events by zone name.
    #[arg(long)]
    pub zone: Option<String>,
}

#[derive(Serialize)]
struct TracePlaceholder<'a> {
    ok: bool,
    zone: &'a str,
    status: &'a str,
}

pub async fn handle_trace(args: TraceArgs, out: OutputMode) -> anyhow::Result<()> {
    match out {
        OutputMode::Human => {
            println!("Tracing zone {}... (not yet implemented)", args.zone);
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string(&TracePlaceholder {
                    ok: false,
                    zone: &args.zone,
                    status: "not_implemented",
                })?
            );
        }
    }
    Ok(())
}

pub async fn handle_top(_args: TopArgs) -> anyhow::Result<()> {
    println!("Per-zone resource monitoring (not yet implemented)");
    Ok(())
}

#[derive(Serialize)]
struct StreamEvent<'a> {
    timestamp: &'a str,
    zone_name: &'a str,
    event_type: &'a str,
    event: serde_json::Value,
}

pub async fn handle_events(args: EventsArgs, out: OutputMode) -> anyhow::Result<()> {
    let channel = connect().await?;
    let mut client = pb::zone::zone_service_client::ZoneServiceClient::new(channel);

    let request = pb::zone::WatchEventsRequest {
        zone_name: args.zone.unwrap_or_default(),
    };

    let mut stream = client.watch_events(request).await?.into_inner();

    if out == OutputMode::Human {
        eprintln!("streaming enforcement events (Ctrl+C to stop)...");
        eprintln!();
    }

    while let Some(event) = stream.next().await {
        match event {
            Ok(e) => match out {
                OutputMode::Human => {
                    println!(
                        "{}  {}  {}",
                        format_timestamp(&e.timestamp),
                        e.event_type,
                        e.message,
                    );
                }
                OutputMode::Json => {
                    let event = serde_json::from_str(&e.message).unwrap_or_else(|_| {
                        serde_json::json!({
                            "message": e.message,
                        })
                    });
                    println!(
                        "{}",
                        serde_json::to_string(&StreamEvent {
                            timestamp: &e.timestamp,
                            zone_name: &e.zone_name,
                            event_type: &e.event_type,
                            event,
                        })?
                    );
                }
            },
            Err(e) => {
                eprintln!("stream error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn format_timestamp(ts: &str) -> String {
    // Timestamp is nanoseconds from bpf_ktime_get_ns (monotonic).
    // Show as relative seconds for readability.
    if let Ok(ns) = ts.parse::<u64>() {
        let secs = ns / 1_000_000_000;
        let ms = (ns % 1_000_000_000) / 1_000_000;
        format!("{secs:>6}.{ms:03}")
    } else {
        ts.to_string()
    }
}
