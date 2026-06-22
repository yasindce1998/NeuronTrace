mod parser;
mod types;

pub use parser::load_policy;
pub use types::{CompiledPolicy, PolicySet};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn starter_policy_claude_code_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/claude-code.yaml");
        let policy = load_policy(&path).expect("claude-code.yaml should parse");
        assert_eq!(policy.name, "claude-code");
        assert!(!policy.rules.is_empty());
        let compiled = policy.compile();
        // git should be allowed
        let exec = neurontrace_common::EventType::Exec as u8;
        let result = compiled.match_event(exec, "/usr/bin/git", "");
        assert!(matches!(result, Some(types::PolicyActionType::Allow)));
    }

    #[test]
    fn starter_policy_codex_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/codex.yaml");
        let policy = load_policy(&path).expect("codex.yaml should parse");
        assert_eq!(policy.name, "codex");
        assert!(!policy.rules.is_empty());
    }

    #[test]
    fn starter_policy_generic_agent_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/generic-agent.yaml");
        let policy = load_policy(&path).expect("generic-agent.yaml should parse");
        assert_eq!(policy.name, "generic-agent");
        assert!(!policy.rules.is_empty());
        let compiled = policy.compile();
        // exec should be blocked
        let exec = neurontrace_common::EventType::Exec as u8;
        let result = compiled.match_event(exec, "/bin/ls", "");
        assert!(matches!(result, Some(types::PolicyActionType::Block)));
    }
}
