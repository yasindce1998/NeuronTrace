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
        /// Path to the YAML policy file
        #[arg(short, long)]
        policy: PathBuf,

        /// Path to the cgroup (e.g. /sys/fs/cgroup/neurontrace)
        #[arg(short, long)]
        cgroup: PathBuf,

        /// Unix socket or file path for structured violation feedback
        #[arg(long, default_value = "/run/neurontrace/feedback.sock")]
        feedback: PathBuf,
    },

    /// Validate a policy file without loading BPF
    Validate {
        /// Path to the YAML policy file
        #[arg(short, long)]
        policy: PathBuf,
    },

    /// Bump the generation counter, invalidating all stale labels
    Bump,

    /// Unload pinned BPF programs and maps, stopping enforcement
    Unload,
}
