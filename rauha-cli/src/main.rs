mod commands;

use clap::{Parser, Subcommand};
use commands::output::OutputMode;

#[derive(Parser)]
#[command(name = "rauha", version, about = "Agent sandbox runtime built on controlled execution zones")]
struct Cli {
    /// Output JSON instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage isolation zones
    Zone {
        #[command(subcommand)]
        action: commands::zone::ZoneAction,
    },
    /// Run an agent task in a sandbox zone (API contract; runtime planned)
    Sandbox(commands::sandbox::SandboxArgs),
    /// Run a container in a zone
    Run(commands::run::RunArgs),
    /// List containers
    Ps(commands::run::PsArgs),
    /// Stop a container
    Stop(commands::run::StopArgs),
    /// Delete a container
    Delete(commands::run::DeleteArgs),
    /// Manage images
    #[command(subcommand)]
    Image(commands::image::ImageAction),
    /// Manage zone policies
    Policy {
        #[command(subcommand)]
        action: commands::policy::PolicyAction,
    },
    /// Trace syscalls in a zone
    Trace(commands::trace::TraceArgs),
    /// Show per-zone resource usage
    Top(commands::trace::TopArgs),
    /// Stream zone events
    Events(commands::trace::EventsArgs),
    /// Stream container logs
    Logs(commands::logs::LogsArgs),
    /// Execute a command in a running container
    Exec(commands::exec::ExecArgs),
    /// Attach to a running container
    Attach(commands::exec::AttachArgs),
    /// Set up macOS environment (VM assets, pf firewall, entitlements)
    Setup(commands::setup::SetupArgs),
}

/// Commands that do not support --json (streaming or interactive).
fn is_streaming_command(cmd: &Commands) -> bool {
    matches!(
        cmd,
        Commands::Trace(_)
            | Commands::Top(_)
            | Commands::Events(_)
            | Commands::Logs(_)
            | Commands::Exec(_)
            | Commands::Attach(_)
            | Commands::Setup(_)
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rauha=info".parse().expect("valid log directive")),
        )
        .init();

    let cli = Cli::parse();
    let out = if cli.json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    // Reject --json for streaming/interactive commands.
    if out == OutputMode::Json && is_streaming_command(&cli.command) {
        commands::output::print_error("--json is not supported for streaming/interactive commands (trace, top, events, logs, exec, attach, setup)");
        std::process::exit(1);
    }

    let result = match cli.command {
        Commands::Zone { action } => commands::zone::handle(action, out).await,
        Commands::Sandbox(args) => commands::sandbox::handle_sandbox(args, out).await,
        Commands::Run(args) => commands::run::handle_run(args, out).await,
        Commands::Ps(args) => commands::run::handle_ps(args, out).await,
        Commands::Stop(args) => commands::run::handle_stop(args, out).await,
        Commands::Delete(args) => commands::run::handle_delete(args, out).await,
        Commands::Image(action) => commands::image::handle(action, out).await,
        Commands::Policy { action } => commands::policy::handle(action, out).await,
        Commands::Trace(args) => commands::trace::handle_trace(args).await,
        Commands::Top(args) => commands::trace::handle_top(args).await,
        Commands::Events(args) => commands::trace::handle_events(args).await,
        Commands::Logs(args) => commands::logs::handle_logs(args).await,
        Commands::Exec(args) => commands::exec::handle_exec(args).await,
        Commands::Attach(args) => commands::exec::handle_attach(args).await,
        Commands::Setup(args) => commands::setup::handle(args).await,
    };

    if let Err(e) = result {
        if out == OutputMode::Json {
            commands::output::print_error(&e.to_string());
        } else {
            eprintln!("Error: {e}");
        }
        std::process::exit(1);
    }
}
