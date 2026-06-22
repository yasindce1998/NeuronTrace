mod bpf;
mod cgroup;
mod cli;
mod events;
mod feedback;
mod labels;
mod policy;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            policy,
            cgroup,
            feedback: feedback_path,
        } => {
            info!("loading policy from {}", policy.display());
            let policy_set = policy::load_policy(&policy)?;

            info!("attaching to cgroup {}", cgroup.display());
            let mut engine = bpf::BpfEngine::new()?;
            engine.load_and_attach()?;
            engine.apply_policy(&policy_set)?;

            let cgroup_id = cgroup::setup_cgroup(&cgroup)?;
            info!(cgroup_id, "cgroup configured");

            let mut feedback_sender = feedback::FeedbackSender::new(&feedback_path);

            info!("neurontrace enforcement active — default-deny enabled");
            engine.run_event_loop(&mut feedback_sender).await?;
        }
        Command::Validate { policy } => {
            info!("validating policy: {}", policy.display());
            let policy_set = policy::load_policy(&policy)?;
            println!(
                "Policy valid: {} rules across {} event types",
                policy_set.rules.len(),
                policy_set.event_types_covered(),
            );
        }
        Command::Bump => {
            info!("bumping generation counter");
            let mut engine = bpf::BpfEngine::new()?;
            engine.load_and_attach()?;
            let new_gen = engine.bump_generation()?;
            println!("Generation bumped to {new_gen}");
        }
        Command::Unload => {
            info!("unloading pinned BPF programs");
            bpf::BpfEngine::unload()?;
            println!("NeuronTrace enforcement stopped — BPF programs unpinned");
        }
    }

    Ok(())
}
