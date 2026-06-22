use std::path::Path;

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, RingBuf};
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use neurontrace_common::{GenerationCounter, PolicyKey, PolicyValue};
use tracing::info;

use crate::events;
use crate::feedback::FeedbackSender;
use crate::policy::PolicySet;

const PIN_BASE: &str = "/sys/fs/bpf/neurontrace";
const PIN_PROGS: &str = "/sys/fs/bpf/neurontrace/progs";
const PIN_MAPS: &str = "/sys/fs/bpf/neurontrace/maps";

const LSM_HOOKS: &[(&str, &str)] = &[
    ("nt_exec_check", "bprm_check_security"),
    ("nt_file_open", "file_open"),
    ("nt_inode_unlink", "inode_unlink"),
    ("nt_inode_rename", "inode_rename"),
    ("nt_socket_connect", "socket_connect"),
    ("nt_ptrace_check", "ptrace_access_check"),
    ("nt_task_kill", "task_kill"),
];

const MAP_NAMES: &[&str] = &[
    "POLICY_MAP",
    "LABEL_MAP",
    "GENERATION",
    "EVENTS",
    "PID_ALLOWLIST",
];

pub struct BpfEngine {
    bpf: Ebpf,
}

impl BpfEngine {
    pub fn new() -> Result<Self> {
        let bpf = Ebpf::load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/neurontrace-ebpf"
        )))
        .context("failed to load BPF program")?;

        Ok(Self { bpf })
    }

    pub fn load_and_attach(&mut self) -> Result<()> {
        let btf = Btf::from_sys_fs()?;

        std::fs::create_dir_all(PIN_PROGS)
            .context("failed to create BPF pin directory for programs")?;
        std::fs::create_dir_all(PIN_MAPS).context("failed to create BPF pin directory for maps")?;

        for (prog_name, hook_name) in LSM_HOOKS {
            let program: &mut Lsm = self
                .bpf
                .program_mut(prog_name)
                .context(format!("BPF program '{prog_name}' not found"))?
                .try_into()?;

            program.load(hook_name, &btf)?;
            program.attach()?;

            let pin_path = format!("{PIN_PROGS}/{prog_name}");
            program
                .pin(&pin_path)
                .with_context(|| format!("failed to pin program '{prog_name}' to {pin_path}"))?;
            info!(program = prog_name, hook = hook_name, pin = %pin_path, "attached and pinned LSM hook");
        }

        for map_name in MAP_NAMES {
            let map = self
                .bpf
                .map_mut(map_name)
                .with_context(|| format!("map '{map_name}' not found"))?;
            let pin_path = format!("{PIN_MAPS}/{map_name}");
            map.pin(&pin_path)
                .with_context(|| format!("failed to pin map '{map_name}' to {pin_path}"))?;
            info!(map = map_name, pin = %pin_path, "pinned BPF map");
        }

        self.register_self_in_allowlist()?;
        Ok(())
    }

    pub fn unload() -> Result<()> {
        let pin_base = Path::new(PIN_BASE);
        if pin_base.exists() {
            std::fs::remove_dir_all(pin_base)
                .context("failed to remove pinned BPF programs/maps")?;
            info!(path = PIN_BASE, "removed all pinned BPF programs and maps");
        } else {
            info!(
                path = PIN_BASE,
                "no pinned programs found — nothing to unload"
            );
        }
        Ok(())
    }

    pub fn apply_policy(&mut self, policy_set: &PolicySet) -> Result<()> {
        let mut policy_map: HashMap<_, PolicyKey, PolicyValue> = HashMap::try_from(
            self.bpf
                .map_mut("POLICY_MAP")
                .context("POLICY_MAP not found")?,
        )?;

        for rule in &policy_set.rules {
            let key = rule.to_policy_key();
            let value = rule.to_policy_value();
            policy_map.insert(key, value, 0)?;
        }

        info!(count = policy_set.rules.len(), "policy rules loaded");
        Ok(())
    }

    pub fn bump_generation(&mut self) -> Result<u32> {
        let mut gen_map: Array<_, GenerationCounter> = Array::try_from(
            self.bpf
                .map_mut("GENERATION")
                .context("GENERATION map not found")?,
        )?;

        let current = gen_map
            .get(&0, 0)
            .unwrap_or(GenerationCounter { current: 0 });

        let new_gen = current.current.wrapping_add(1);
        gen_map.set(0, GenerationCounter { current: new_gen }, 0)?;

        info!(generation = new_gen, "generation counter bumped");
        Ok(new_gen)
    }

    pub async fn run_event_loop(&mut self, feedback: &mut FeedbackSender) -> Result<()> {
        let ring_buf = RingBuf::try_from(
            self.bpf
                .map_mut("EVENTS")
                .context("EVENTS ring buffer not found")?,
        )?;

        events::consume_events(ring_buf, feedback).await
    }

    fn register_self_in_allowlist(&mut self) -> Result<()> {
        let mut allowlist: HashMap<_, u32, u8> = HashMap::try_from(
            self.bpf
                .map_mut("PID_ALLOWLIST")
                .context("PID_ALLOWLIST not found")?,
        )?;

        let my_pid = std::process::id();
        allowlist.insert(my_pid, 1u8, 0)?;
        info!(pid = my_pid, "registered controller in PID allowlist");
        Ok(())
    }
}

macro_rules! include_bytes_aligned {
    ($path:expr) => {{
        #[repr(C, align(8))]
        struct Aligned<Bytes: ?Sized>(Bytes);
        static ALIGNED: &Aligned<[u8]> = &Aligned(*include_bytes!($path));
        &ALIGNED.0
    }};
}
use include_bytes_aligned;
