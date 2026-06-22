use globset::{Glob, GlobMatcher};
use neurontrace_common::{EventType, PolicyAction, PolicyKey, PolicyValue};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PolicySet {
    pub name: String,
    #[allow(dead_code)]
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    pub fn event_types_covered(&self) -> usize {
        let mut seen = [false; 9];
        for rule in &self.rules {
            let idx = rule.event_type.to_u8() as usize;
            if idx < seen.len() {
                seen[idx] = true;
            }
        }
        seen.iter().filter(|&&v| v).count()
    }

    pub fn compile(&self) -> CompiledPolicy {
        let mut entries = Vec::new();
        for rule in &self.rules {
            let path_matcher = rule
                .path
                .as_ref()
                .and_then(|p| Glob::new(p).ok())
                .map(|g| g.compile_matcher());
            let argv_matcher = rule
                .argv
                .as_ref()
                .and_then(|a| Glob::new(a).ok())
                .map(|g| g.compile_matcher());
            entries.push(CompiledRule {
                event_type: rule.event_type.to_u8(),
                action: rule.action,
                path_matcher,
                argv_matcher,
            });
        }
        CompiledPolicy { entries }
    }
}

pub struct CompiledPolicy {
    entries: Vec<CompiledRule>,
}

struct CompiledRule {
    event_type: u8,
    action: PolicyActionType,
    path_matcher: Option<GlobMatcher>,
    argv_matcher: Option<GlobMatcher>,
}

impl CompiledPolicy {
    pub fn match_event(&self, event_type: u8, path: &str, argv: &str) -> Option<PolicyActionType> {
        let mut default_action = None;
        for rule in &self.entries {
            if rule.event_type != event_type {
                continue;
            }
            match (&rule.path_matcher, &rule.argv_matcher) {
                (None, None) => {
                    default_action = Some(rule.action);
                }
                (Some(pm), None) => {
                    if pm.is_match(path) {
                        return Some(rule.action);
                    }
                }
                (None, Some(am)) => {
                    if am.is_match(argv) {
                        return Some(rule.action);
                    }
                }
                (Some(pm), Some(am)) => {
                    if pm.is_match(path) && am.is_match(argv) {
                        return Some(rule.action);
                    }
                }
            }
        }
        default_action
    }
}

#[derive(Debug, Deserialize)]
pub struct PolicyRule {
    pub event_type: PolicyEventType,
    pub action: PolicyActionType,
    #[serde(default)]
    pub cgroup_id: u64,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub argv: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
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
    TaskKill,
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
            Self::TaskKill => EventType::TaskKill as u8,
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
