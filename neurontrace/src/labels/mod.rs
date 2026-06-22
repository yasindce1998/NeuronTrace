pub mod generation;

use anyhow::{Context, Result};
use aya::maps::HashMap;
use aya::Ebpf;
use neurontrace_common::{LabelEntry, ProcessLabels, MAX_LABELS_PER_PROCESS, MAX_LABEL_LEN};
use tracing::info;

pub fn assign_label(bpf: &mut Ebpf, pid: u32, label: &str, generation: u32) -> Result<()> {
    let mut label_map: HashMap<_, u32, ProcessLabels> = HashMap::try_from(
        bpf.map_mut("LABEL_MAP")
            .context("LABEL_MAP not found")?,
    )?;

    let mut process_labels = label_map
        .get(&pid, 0)
        .unwrap_or_else(|_| ProcessLabels {
            labels: [LabelEntry {
                label: [0u8; MAX_LABEL_LEN],
                label_len: 0,
                generation: 0,
                _padding: 0,
            }; MAX_LABELS_PER_PROCESS],
            count: 0,
            _padding: [0u8; 7],
        });

    let idx = process_labels.count as usize;
    if idx >= MAX_LABELS_PER_PROCESS {
        anyhow::bail!("process {pid} already has maximum labels ({MAX_LABELS_PER_PROCESS})");
    }

    let mut label_buf = [0u8; MAX_LABEL_LEN];
    let bytes = label.as_bytes();
    let copy_len = bytes.len().min(MAX_LABEL_LEN);
    label_buf[..copy_len].copy_from_slice(&bytes[..copy_len]);

    process_labels.labels[idx] = LabelEntry {
        label: label_buf,
        label_len: copy_len as u16,
        generation,
        _padding: 0,
    };
    process_labels.count += 1;

    label_map.insert(&pid, &process_labels, 0)?;
    info!(pid, label, generation, "label assigned to process");
    Ok(())
}

pub fn clear_labels(bpf: &mut Ebpf, pid: u32) -> Result<()> {
    let mut label_map: HashMap<_, u32, ProcessLabels> = HashMap::try_from(
        bpf.map_mut("LABEL_MAP")
            .context("LABEL_MAP not found")?,
    )?;

    label_map.remove(&pid)?;
    info!(pid, "labels cleared for process");
    Ok(())
}
