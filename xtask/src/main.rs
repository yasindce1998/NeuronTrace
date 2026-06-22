use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser)]
#[command(name = "xtask", about = "Build automation for NeuronTrace")]
struct Cli {
    #[command(subcommand)]
    command: XCommand,
}

#[derive(Subcommand)]
enum XCommand {
    /// Build the eBPF program
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build both eBPF and userspace
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Run the userspace binary (builds eBPF first)
    Run {
        /// Arguments to pass to neurontrace
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        XCommand::BuildEbpf { release } => build_ebpf(release),
        XCommand::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
        XCommand::Run { args } => {
            build_ebpf(true)?;
            build_userspace(true)?;
            run_neurontrace(&args)
        }
    }
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = project_root();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(root.join("neurontrace-ebpf"));
    cmd.env("CARGO_CFG_BPF_TARGET_ARCH", "x86_64");
    cmd.args([
        "+nightly",
        "build",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("failed to run cargo build for eBPF program")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let artifact = root
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("neurontrace-ebpf");

    println!("eBPF program built: {}", artifact.display());
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    let root = project_root();

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root);
    cmd.args(["build", "--package", "neurontrace"]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("failed to build userspace binary")?;

    if !status.success() {
        bail!("userspace build failed");
    }

    println!("userspace binary built");
    Ok(())
}

fn run_neurontrace(args: &[String]) -> Result<()> {
    let root = project_root();
    let bin = root.join("target/release/neurontrace");

    let mut cmd = Command::new(bin);
    cmd.args(args);

    let status = cmd.status().context("failed to run neurontrace")?;

    if !status.success() {
        bail!("neurontrace exited with error");
    }

    Ok(())
}
