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

use super::output::OutputMode;

#[derive(Args)]
pub struct SandboxArgs {
    /// Container image to run the task in.
    #[arg(long)]
    pub image: String,
    /// Optional zone name. If omitted, the daemon allocates a temporary zone.
    #[arg(long)]
    pub name: Option<String>,
    /// Host path to expose into the zone as a read/write source.
    #[arg(long)]
    pub repo: Option<String>,
    /// Working directory inside the zone.
    #[arg(long)]
    pub workdir: Option<String>,
    /// Leave the task zone behind for debugging after the run.
    #[arg(long)]
    pub keep_zone: bool,
    /// Soft timeout in seconds. 0 means no timeout.
    #[arg(long, default_value = "0")]
    pub timeout: u32,
    /// Task command. Use `--` before it to disambiguate from sandbox flags.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

pub async fn handle_sandbox(args: SandboxArgs, _out: OutputMode) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = SandboxServiceClient::new(channel);

    let request = pb::sandbox::RunSandboxRequest {
        image: args.image,
        command: args.command,
        name: args.name.unwrap_or_default(),
        repo_path: args.repo.unwrap_or_default(),
        workdir: args.workdir.unwrap_or_default(),
        keep_zone: args.keep_zone,
        timeout_seconds: args.timeout,
        env: Default::default(),
    };

    // Strip the tonic Status wrapper so the user sees the daemon's message
    // ("sandbox execution is not implemented yet; ...") not the full Status
    // debug formatting. Result-handling for the success path lives in the
    // next PR, when the daemon actually returns a SandboxResult.
    client
        .run_sandbox(request)
        .await
        .map_err(|s| anyhow::anyhow!("{}", s.message()))?;

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
        let parsed = TestCli::try_parse_from([
            "sandbox",
            "--image",
            "alpine:latest",
            "--",
            "echo",
            "hello",
        ])
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
            "--repo",
            ".",
            "--workdir",
            "/workspace",
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
        assert_eq!(args.repo.as_deref(), Some("."));
        assert_eq!(args.workdir.as_deref(), Some("/workspace"));
        assert!(args.keep_zone);
        assert_eq!(args.timeout, 300);
        assert_eq!(args.command, vec!["pytest".to_string(), "tests/".to_string()]);
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
}
