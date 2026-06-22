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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(yaml: &str) -> PolicySet {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn parse_minimal_policy() {
        let p = make_policy(
            r#"
name: test
description: minimal
rules:
  - event_type: exec
    action: block
"#,
        );
        assert_eq!(p.name, "test");
        assert_eq!(p.rules.len(), 1);
    }

    #[test]
    fn parse_path_and_argv_fields() {
        let p = make_policy(
            r#"
name: test
description: with filters
rules:
  - event_type: exec
    action: allow
    path: "/usr/bin/git"
  - event_type: exec
    action: allow
    argv: "python*"
  - event_type: exec
    action: block
"#,
        );
        assert_eq!(p.rules[0].path.as_deref(), Some("/usr/bin/git"));
        assert_eq!(p.rules[0].argv, None);
        assert_eq!(p.rules[1].argv.as_deref(), Some("python*"));
        assert_eq!(p.rules[2].path, None);
    }

    #[test]
    fn event_types_covered_counts_unique() {
        let p = make_policy(
            r#"
name: test
description: coverage
rules:
  - event_type: exec
    action: allow
    path: "/usr/bin/git"
  - event_type: exec
    action: block
  - event_type: connect
    action: block
"#,
        );
        assert_eq!(p.event_types_covered(), 2);
    }

    #[test]
    fn compiled_policy_exact_path_match() {
        let p = make_policy(
            r#"
name: test
description: exact
rules:
  - event_type: exec
    action: allow
    path: "/usr/bin/git"
  - event_type: exec
    action: block
"#,
        );
        let compiled = p.compile();
        let exec = EventType::Exec as u8;

        let result = compiled.match_event(exec, "/usr/bin/git", "");
        assert!(matches!(result, Some(PolicyActionType::Allow)));

        let result = compiled.match_event(exec, "/usr/bin/curl", "");
        assert!(matches!(result, Some(PolicyActionType::Block)));
    }

    #[test]
    fn compiled_policy_glob_wildcard() {
        let p = make_policy(
            r#"
name: test
description: glob
rules:
  - event_type: exec
    action: allow
    path: "/usr/bin/python*"
  - event_type: exec
    action: block
"#,
        );
        let compiled = p.compile();
        let exec = EventType::Exec as u8;

        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/python3", ""),
            Some(PolicyActionType::Allow)
        ));
        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/python3.11", ""),
            Some(PolicyActionType::Allow)
        ));
        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/node", ""),
            Some(PolicyActionType::Block)
        ));
    }

    #[test]
    fn compiled_policy_glob_double_star() {
        let p = make_policy(
            r#"
name: test
description: recursive glob
rules:
  - event_type: unlink
    action: block
    path: "/etc/**"
  - event_type: unlink
    action: audit
"#,
        );
        let compiled = p.compile();
        let unlink = EventType::Unlink as u8;

        assert!(matches!(
            compiled.match_event(unlink, "/etc/shadow", ""),
            Some(PolicyActionType::Block)
        ));
        assert!(matches!(
            compiled.match_event(unlink, "/etc/nginx/nginx.conf", ""),
            Some(PolicyActionType::Block)
        ));
        assert!(matches!(
            compiled.match_event(unlink, "/tmp/foo.txt", ""),
            Some(PolicyActionType::Audit)
        ));
    }

    #[test]
    fn compiled_policy_no_matching_event_type_returns_none() {
        let p = make_policy(
            r#"
name: test
description: exec only
rules:
  - event_type: exec
    action: block
"#,
        );
        let compiled = p.compile();
        let connect = EventType::Connect as u8;

        assert!(compiled.match_event(connect, "", "").is_none());
    }

    #[test]
    fn compiled_policy_argv_matching() {
        let p = make_policy(
            r#"
name: test
description: argv
rules:
  - event_type: exec
    action: block
    argv: "*--dangerous*"
  - event_type: exec
    action: allow
"#,
        );
        let compiled = p.compile();
        let exec = EventType::Exec as u8;

        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/tool", "tool --dangerous-flag"),
            Some(PolicyActionType::Block)
        ));
        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/tool", "tool --safe"),
            Some(PolicyActionType::Allow)
        ));
    }

    #[test]
    fn compiled_policy_path_and_argv_both_must_match() {
        let p = make_policy(
            r#"
name: test
description: both
rules:
  - event_type: exec
    action: allow
    path: "/usr/bin/git"
    argv: "git push*"
  - event_type: exec
    action: block
"#,
        );
        let compiled = p.compile();
        let exec = EventType::Exec as u8;

        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/git", "git push origin main"),
            Some(PolicyActionType::Allow)
        ));
        // path matches but argv doesn't
        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/git", "git status"),
            Some(PolicyActionType::Block)
        ));
        // argv matches but path doesn't
        assert!(matches!(
            compiled.match_event(exec, "/usr/bin/curl", "git push origin main"),
            Some(PolicyActionType::Block)
        ));
    }

    #[test]
    fn policy_action_type_to_u8_roundtrip() {
        assert_eq!(PolicyActionType::Allow.to_u8(), PolicyAction::Allow as u8);
        assert_eq!(PolicyActionType::Block.to_u8(), PolicyAction::Block as u8);
        assert_eq!(PolicyActionType::Kill.to_u8(), PolicyAction::Kill as u8);
        assert_eq!(PolicyActionType::Audit.to_u8(), PolicyAction::Audit as u8);
    }
}
