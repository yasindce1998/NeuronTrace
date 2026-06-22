use neurontrace_common::{EventType, PolicyAction, PolicyKey, PolicyValue};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PolicySet {
    pub name: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    pub fn event_types_covered(&self) -> usize {
        let mut seen = [false; 8];
        for rule in &self.rules {
            let idx = rule.event_type.to_u8() as usize;
            if idx < seen.len() {
                seen[idx] = true;
            }
        }
        seen.iter().filter(|&&v| v).count()
    }
}

#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    pub event_type: PolicyEventType,
    pub action: PolicyActionType,
    #[serde(default)]
    pub cgroup_id: u64,
    #[serde(default)]
    pub description: String,
}

impl PolicyRule {
    pub fn to_policy_key(&self) -> PolicyKey {
        PolicyKey {
            cgroup_id: self.cgroup_id,
            event_type: self.event_type.to_u8(),
            _padding: [0u8; 7],
        }
    }

    pub fn to_policy_value(&self) -> PolicyValue {
        PolicyValue {
            action: self.action.to_u8(),
            _padding: [0u8; 7],
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEventType {
    Exec,
    Open,
    Unlink,
    Rename,
    Connect,
    Ptrace,
    Fork,
    Exit,
}

impl PolicyEventType {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Exec => EventType::Exec as u8,
            Self::Open => EventType::Open as u8,
            Self::Unlink => EventType::Unlink as u8,
            Self::Rename => EventType::Rename as u8,
            Self::Connect => EventType::Connect as u8,
            Self::Ptrace => EventType::Ptrace as u8,
            Self::Fork => EventType::Fork as u8,
            Self::Exit => EventType::Exit as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyActionType {
    Allow,
    Block,
    Kill,
    Audit,
}

impl PolicyActionType {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Allow => PolicyAction::Allow as u8,
            Self::Block => PolicyAction::Block as u8,
            Self::Kill => PolicyAction::Kill as u8,
            Self::Audit => PolicyAction::Audit as u8,
        }
    }
}
