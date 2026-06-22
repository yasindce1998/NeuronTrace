#![cfg_attr(not(feature = "user"), no_std)]

pub const MAX_LABEL_LEN: usize = 64;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_ARGV_LEN: usize = 128;
pub const MAX_LABELS_PER_PROCESS: usize = 8;
pub const RING_BUF_SIZE: u32 = 1024 * 1024; // 1MB

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyAction {
    Allow = 0,
    Block = 1,
    Kill = 2,
    Audit = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    Exec = 0,
    Open = 1,
    Unlink = 2,
    Rename = 3,
    Connect = 4,
    Ptrace = 5,
    Fork = 6,
    Exit = 7,
    TaskKill = 8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LabelEntry {
    pub label: [u8; MAX_LABEL_LEN],
    pub label_len: u16,
    pub generation: u32,
    pub _padding: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyKey {
    pub cgroup_id: u64,
    pub event_type: u8,
    pub _padding: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyValue {
    pub action: u8,
    pub _padding: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NtEvent {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub event_type: u8,
    pub action_taken: u8,
    pub _padding: [u8; 2],
    pub cgroup_id: u64,
    pub timestamp_ns: u64,
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: u16,
    pub argv: [u8; MAX_ARGV_LEN],
    pub argv_len: u16,
    pub _tail_padding: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GenerationCounter {
    pub current: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessLabels {
    pub labels: [LabelEntry; MAX_LABELS_PER_PROCESS],
    pub count: u8,
    pub _padding: [u8; 7],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicyValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for GenerationCounter {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessLabels {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NtEvent {}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    #[derive(Debug, Clone, serde::Serialize)]
    pub struct ViolationFeedback {
        pub version: u8,
        pub kind: &'static str,
        pub timestamp_ns: u64,
        pub pid: u32,
        pub hook: String,
        pub target: String,
        pub effect: String,
        pub rule: String,
        pub severity: Severity,
        pub suggested_retry: bool,
        pub message: String,
    }

    #[derive(Debug, Clone, Copy, serde::Serialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Severity {
        Low,
        Medium,
        High,
        Critical,
    }

    impl From<u8> for PolicyAction {
        fn from(v: u8) -> Self {
            match v {
                0 => PolicyAction::Allow,
                1 => PolicyAction::Block,
                2 => PolicyAction::Kill,
                3 => PolicyAction::Audit,
                _ => PolicyAction::Block,
            }
        }
    }

    impl From<u8> for EventType {
        fn from(v: u8) -> Self {
            match v {
                0 => EventType::Exec,
                1 => EventType::Open,
                2 => EventType::Unlink,
                3 => EventType::Rename,
                4 => EventType::Connect,
                5 => EventType::Ptrace,
                6 => EventType::Fork,
                7 => EventType::Exit,
                8 => EventType::TaskKill,
                _ => EventType::Exec,
            }
        }
    }

    impl core::fmt::Display for EventType {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                EventType::Exec => write!(f, "exec"),
                EventType::Open => write!(f, "open"),
                EventType::Unlink => write!(f, "unlink"),
                EventType::Rename => write!(f, "rename"),
                EventType::Connect => write!(f, "connect"),
                EventType::Ptrace => write!(f, "ptrace"),
                EventType::Fork => write!(f, "fork"),
                EventType::Exit => write!(f, "exit"),
                EventType::TaskKill => write!(f, "task_kill"),
            }
        }
    }

    impl core::fmt::Display for PolicyAction {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                PolicyAction::Allow => write!(f, "allow"),
                PolicyAction::Block => write!(f, "block"),
                PolicyAction::Kill => write!(f, "kill"),
                PolicyAction::Audit => write!(f, "audit"),
            }
        }
    }
}
