mod bpf;
mod cgroup;
mod cli;
mod config;
mod events;
mod feedback;
mod labels;
mod policy;
mod preflight;

use anyhow::Result;
use clap::Parser;
use tokio::signal;
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
    let defaults = config::Config::load();

    match cli.command {
        Command::Run {
            policy,
            cgroup,
            feedback: feedback_path,
            feedback_stdout,
            audit_only,
            dry_run,
        } => {
            if !dry_run {
                preflight::check()?;
            }

            let policy = policy.or(defaults.policy).ok_or_else(|| {
                anyhow::anyhow!(
                    "no policy specified: use --policy or set NEURONTRACE_POLICY env var"
                )
            })?;
            let cgroup = cgroup.or(defaults.cgroup).ok_or_else(|| {
                anyhow::anyhow!(
                    "no cgroup specified: use --cgroup or set NEURONTRACE_CGROUP env var"
                )
            })?;
            let feedback_path = feedback_path.unwrap_or_else(|| {
                defaults
                    .feedback
                    .unwrap_or_else(|| "/run/neurontrace/feedback.sock".into())
            });

            info!("loading policy from {}", policy.display());
            let policy_set = policy::load_policy(&policy)?;
            let compiled = policy_set.compile();

            if audit_only {
                info!("AUDIT-ONLY mode: all enforcement actions overridden to audit");
            }

            if dry_run {
                println!("Dry-run complete — configuration and policy valid");
                println!(
                    "  Policy: {} ({} rules)",
                    policy.display(),
                    policy_set.rules.len()
                );
                println!("  Cgroup: {}", cgroup.display());
                if feedback_stdout {
                    println!("  Feedback: stdout");
                } else {
                    println!("  Feedback: {}", feedback_path.display());
                }
                println!("  Audit-only: {}", audit_only);
                return Ok(());
            }

            info!("attaching to cgroup {}", cgroup.display());
            let mut engine = bpf::BpfEngine::new()?;
            engine.load_and_attach()?;
            engine.apply_policy(&policy_set, audit_only)?;

            let cgroup_id = cgroup::setup_cgroup(&cgroup)?;
            info!(cgroup_id, "cgroup configured");

            let mut feedback_sender = if feedback_stdout {
                feedback::FeedbackSender::new_stdout()
            } else {
                feedback::FeedbackSender::new(&feedback_path)
            };

            info!("neurontrace enforcement active — default-deny enabled");

            tokio::select! {
                result = engine.run_event_loop(&mut feedback_sender, Some(&compiled)) => {
                    result?;
                }
                _ = signal::ctrl_c() => {
                    info!("received SIGINT — shutting down gracefully");
                    println!("NeuronTrace stopping (BPF programs remain pinned — use `unload` to remove)");
                }
            }
        }
        Command::Validate { policy } => {
            let policy = policy.or(defaults.policy).ok_or_else(|| {
                anyhow::anyhow!(
                    "no policy specified: use --policy or set NEURONTRACE_POLICY env var"
                )
            })?;

            info!("validating policy: {}", policy.display());
            let policy_set = policy::load_policy(&policy)?;
            println!(
                "Policy valid: {} rules across {} event types",
                policy_set.rules.len(),
                policy_set.event_types_covered(),
            );
            for rule in &policy_set.rules {
                let filter = match (&rule.path, &rule.argv) {
                    (Some(p), Some(a)) => format!(" [path={}, argv={}]", p, a),
                    (Some(p), None) => format!(" [path={}]", p),
                    (None, Some(a)) => format!(" [argv={}]", a),
                    (None, None) => String::new(),
                };
                println!("  {:?} → {:?}{}", rule.event_type, rule.action, filter);
            }
        }
        Command::Bump => {
            preflight::check()?;
            info!("bumping generation counter");
            let mut engine = bpf::BpfEngine::new()?;
            engine.load_and_attach()?;
            let new_gen = engine.bump_generation()?;
            println!("Generation bumped to {new_gen}");
        }
        Command::Unload => {
            preflight::check_root()?;
            info!("unloading pinned BPF programs");
            bpf::BpfEngine::unload()?;
            println!("NeuronTrace enforcement stopped — BPF programs unpinned");
        }
        Command::Status => {
            let status = bpf::BpfEngine::status()?;
            if status.active {
                println!("NeuronTrace: ACTIVE");
                println!("  Programs ({}):", status.programs.len());
                for prog in &status.programs {
                    println!("    - {}", prog);
                }
                println!("  Maps ({}):", status.maps.len());
                for map in &status.maps {
                    println!("    - {}", map);
                }
            } else {
                println!("NeuronTrace: INACTIVE (no pinned programs found)");
            }
        }
    }

    Ok(())
}
