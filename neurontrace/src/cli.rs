use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "neurontrace",
    about = "Kernel-level behavioral containment for AI agents",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start enforcement with the given policy and cgroup
    Run {
        /// Path to the YAML policy file (or set NEURONTRACE_POLICY)
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Path to the cgroup (or set NEURONTRACE_CGROUP)
        #[arg(short, long)]
        cgroup: Option<PathBuf>,

        /// Unix socket or file path for structured violation feedback
        #[arg(long)]
        feedback: Option<PathBuf>,

        /// Audit-only mode: observe without enforcing (all actions become audit)
        #[arg(long)]
        audit_only: bool,
    },

    /// Validate a policy file without loading BPF
    Validate {
        /// Path to the YAML policy file (or set NEURONTRACE_POLICY)
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },

    /// Bump the generation counter, invalidating all stale labels
    Bump,

    /// Unload pinned BPF programs and maps, stopping enforcement
    Unload,

    /// Show current NeuronTrace enforcement status
    Status,
}
