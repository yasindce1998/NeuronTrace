use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tracing::info;

pub fn setup_cgroup(path: &Path) -> Result<u64> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create cgroup at {}", path.display()))?;
        info!(path = %path.display(), "created cgroup directory");
    }

    let cgroup_id = get_cgroup_id(path)?;
    Ok(cgroup_id)
}

fn get_cgroup_id(path: &Path) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        fs::metadata(path).with_context(|| format!("failed to stat cgroup {}", path.display()))?;
    Ok(meta.ino())
}

pub fn add_pid_to_cgroup(cgroup_path: &Path, pid: u32) -> Result<()> {
    let procs_file = cgroup_path.join("cgroup.procs");
    fs::write(&procs_file, pid.to_string()).with_context(|| {
        format!(
            "failed to add pid {pid} to cgroup {}",
            cgroup_path.display()
        )
    })?;
    info!(pid, cgroup = %cgroup_path.display(), "added process to cgroup");
    Ok(())
}
