use anyhow::{Context, Result};
use aya::maps::Array;
use aya::Ebpf;
use neurontrace_common::GenerationCounter;
use tracing::info;

pub fn get_current_generation(bpf: &Ebpf) -> Result<u32> {
    let gen_map: Array<_, GenerationCounter> = Array::try_from(
        bpf.map("GENERATION")
            .context("GENERATION map not found")?,
    )?;

    let counter = gen_map.get(&0, 0).unwrap_or(GenerationCounter { current: 0 });
    Ok(counter.current)
}

pub fn set_generation(bpf: &mut Ebpf, value: u32) -> Result<()> {
    let mut gen_map: Array<_, GenerationCounter> = Array::try_from(
        bpf.map_mut("GENERATION")
            .context("GENERATION map not found")?,
    )?;

    gen_map.set(0, GenerationCounter { current: value }, 0)?;
    info!(generation = value, "generation counter set");
    Ok(())
}
