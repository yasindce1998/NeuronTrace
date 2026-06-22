use anyhow::{bail, Context, Result};
use std::path::Path;

pub fn check() -> Result<()> {
    check_root()?;
    check_bpf_lsm()?;
    Ok(())
}

pub fn check_root() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        bail!(
            "NeuronTrace requires root privileges to load BPF programs.\n\
             Run with: sudo neurontrace ..."
        );
    }
    Ok(())
}

fn check_bpf_lsm() -> Result<()> {
    let lsm_path = Path::new("/sys/kernel/security/lsm");
    if !lsm_path.exists() {
        bail!(
            "cannot read /sys/kernel/security/lsm — is securityfs mounted?\n\
             Try: mount -t securityfs none /sys/kernel/security"
        );
    }

    let lsm_list = std::fs::read_to_string(lsm_path)
        .context("failed to read /sys/kernel/security/lsm")?;

    if !lsm_list.contains("bpf") {
        bail!(
            "BPF LSM is not enabled on this kernel.\n\
             Current LSMs: {}\n\
             Fix: add 'lsm=...,bpf' to your kernel boot parameters\n\
             and ensure CONFIG_BPF_LSM=y in your kernel config.",
            lsm_list.trim()
        );
    }

    Ok(())
}
