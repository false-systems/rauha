//! `rauha sandbox` — task-level sandbox execution.
//!
//! Public contract for running one agent task inside a Rauha zone and getting
//! back a structured result. The daemon currently returns Unimplemented for
//! RunSandbox; this command exists to land the wire-protocol contract so the
//! runtime path can fill it in without changing the user-facing surface.

use clap::Args;

pub mod pb {
    pub mod sandbox {
        tonic::include_proto!("rauha.sandbox.v1");
    }
}

use pb::sandbox::sandbox_service_client::SandboxServiceClient;

use super::output::{self, OutputMode};

fn parse_env_pair(value: &str) -> Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "environment variables must use KEY=VALUE".to_string())?;

    if key.is_empty() {
        return Err("environment variable key must not be empty".to_string());
    }

    Ok((key.to_string(), value.to_string()))
}

#[derive(Args)]
pub struct SandboxArgs {
    /// Container image to run the task in.
    #[arg(long)]
    pub image: String,
    /// Optional zone name. If omitted, the daemon allocates a temporary zone.
    #[arg(long)]
    pub name: Option<String>,
    /// Host path to expose into the zone as a read/write source.
    #[arg(long, alias = "repo")]
    pub repo_path: Option<String>,
    /// Working directory inside the zone.
    #[arg(long)]
    pub workdir: Option<String>,
    /// Leave the task zone behind for debugging after the run.
    #[arg(long)]
    pub keep_zone: bool,
    /// Soft timeout in seconds. 0 means no timeout.
    #[arg(long, default_value = "0")]
    pub timeout: u32,
    /// Extra environment variable for the task, in KEY=VALUE form.
    #[arg(long = "env", short = 'e', value_parser = parse_env_pair)]
    pub env: Vec<(String, String)>,
    /// Task command. Use `--` before it to disambiguate from sandbox flags.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub async fn handle_sandbox(args: SandboxArgs, out: OutputMode) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = SandboxServiceClient::new(channel);

    let request = pb::sandbox::RunSandboxRequest {
        image: args.image,
        command: args.command,
        name: args.name.unwrap_or_default(),
        repo_path: args.repo_path.unwrap_or_default(),
        workdir: args.workdir.unwrap_or_default(),
        keep_zone: args.keep_zone,
        timeout_seconds: args.timeout,
        env: args.env.into_iter().collect(),
    };

    // Strip the tonic Status wrapper so the user sees the daemon's message,
    // not the full Status debug formatting. A Status here means the request
    // never produced a result (bad args, daemon down) — distinct from a task
    // that ran and failed, which comes back as a normal result below.
    let result = client
        .run_sandbox(request)
        .await
        .map_err(|s| anyhow::anyhow!("{}", s.message()))?
        .into_inner();

    // `rauha sandbox` mirrors the task: its exit code is the task's exit code.
    // When the task produced no code (timed out, or never started), map the
    // status to a conventional code: 137 (SIGKILL) for timeout, 1 otherwise.
    let exit_code = result.exit_code.unwrap_or(match result.status.as_str() {
        "timed_out" => 137,
        _ => 1,
    });

    let view = output::SandboxRun {
        ok: result.status == "succeeded",
        task_id: result.task_id,
        zone_id: result.zone_id,
        status: result.status,
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
        duration_ms: result.duration_ms,
        events: result
            .events
            .into_iter()
            .map(|e| output::SandboxEvent {
                timestamp: e.timestamp,
                kind: e.kind,
                message: e.message,
            })
            .collect(),
        enforcement_events: result
            .enforcement_events
            .into_iter()
            .map(|e| output::SandboxEnforcementEvent {
                timestamp: e.timestamp,
                hook: e.hook,
                action: e.action,
                decision: e.decision,
                message: e.message,
                pid: e.pid,
                source_zone: e.source_zone,
                target_zone: e.target_zone,
                object: e.object,
            })
            .collect(),
    };

    output::print(out, &view, || {
        // Stream the task's own output through unchanged — stdout to stdout,
        // stderr to stderr — then a one-line summary on stderr so it never
        // pollutes captured task output.
        print!("{}", view.stdout);
        eprint!("{}", view.stderr);
        let code = view
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into());
        let enforcement = if view.enforcement_events.is_empty() {
            String::new()
        } else {
            format!("  enforcement: {} event(s)", view.enforcement_events.len())
        };
        eprintln!(
            "status: {}  exit: {}  ({:.1}s){}",
            view.status,
            code,
            view.duration_ms as f64 / 1000.0,
            enforcement,
        );
    });

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, Subcommand};

    #[derive(Parser)]
    #[command(no_binary_name = true)]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCmd,
    }

    #[derive(Subcommand)]
    enum TestCmd {
        Sandbox(SandboxArgs),
    }

    #[test]
    fn parses_image_and_trailing_command() {
        let parsed =
            TestCli::try_parse_from(["sandbox", "--image", "alpine:latest", "--", "echo", "hello"])
                .expect("parse");
        let TestCmd::Sandbox(args) = parsed.cmd;
        assert_eq!(args.image, "alpine:latest");
        assert_eq!(args.command, vec!["echo".to_string(), "hello".to_string()]);
        assert_eq!(args.timeout, 0);
        assert!(!args.keep_zone);
        assert!(args.name.is_none());
    }

    #[test]
    fn parses_optional_flags() {
        let parsed = TestCli::try_parse_from([
            "sandbox",
            "--image",
            "python:3.12",
            "--name",
            "task-1",
            "--repo-path",
            ".",
            "--workdir",
            "/workspace",
            "--env",
            "RUST_LOG=debug",
            "-e",
            "EMPTY=",
            "--keep-zone",
            "--timeout",
            "300",
            "--",
            "pytest",
            "tests/",
        ])
        .expect("parse");
        let TestCmd::Sandbox(args) = parsed.cmd;
        assert_eq!(args.image, "python:3.12");
        assert_eq!(args.name.as_deref(), Some("task-1"));
        assert_eq!(args.repo_path.as_deref(), Some("."));
        assert_eq!(args.workdir.as_deref(), Some("/workspace"));
        assert_eq!(
            args.env,
            vec![
                ("RUST_LOG".to_string(), "debug".to_string()),
                ("EMPTY".to_string(), String::new()),
            ]
        );
        assert!(args.keep_zone);
        assert_eq!(args.timeout, 300);
        assert_eq!(
            args.command,
            vec!["pytest".to_string(), "tests/".to_string()]
        );
    }

    #[test]
    fn rejects_missing_command() {
        let result = TestCli::try_parse_from(["sandbox", "--image", "alpine:latest"]);
        assert!(result.is_err(), "command should be required");
    }

    #[test]
    fn rejects_missing_image() {
        let result = TestCli::try_parse_from(["sandbox", "--", "echo", "hello"]);
        assert!(result.is_err(), "image should be required");
    }

    #[test]
    fn accepts_repo_alias() {
        let parsed = TestCli::try_parse_from([
            "sandbox",
            "--image",
            "python:3.12",
            "--repo",
            ".",
            "--",
            "pytest",
        ])
        .expect("parse");
        let TestCmd::Sandbox(args) = parsed.cmd;
        assert_eq!(args.repo_path.as_deref(), Some("."));
    }

    #[test]
    fn rejects_malformed_env() {
        let result = TestCli::try_parse_from([
            "sandbox",
            "--image",
            "alpine:latest",
            "--env",
            "NOPE",
            "--",
            "env",
        ]);
        assert!(result.is_err(), "env should require KEY=VALUE");
    }
}
