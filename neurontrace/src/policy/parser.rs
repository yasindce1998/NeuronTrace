use anyhow::{Context, Result};
use globset::Glob;
use std::path::Path;

use super::types::PolicySet;

pub fn load_policy(path: &Path) -> Result<PolicySet> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file: {}", path.display()))?;

    let policy: PolicySet = serde_yaml::from_str(&content)
        .with_context(|| format!("failed to parse policy file: {}", path.display()))?;

    validate_policy(&policy)?;
    Ok(policy)
}

fn validate_policy(policy: &PolicySet) -> Result<()> {
    anyhow::ensure!(!policy.name.is_empty(), "policy name cannot be empty");
    anyhow::ensure!(
        !policy.rules.is_empty(),
        "policy must have at least one rule"
    );

    for (i, rule) in policy.rules.iter().enumerate() {
        if let Some(ref pattern) = rule.path {
            Glob::new(pattern)
                .with_context(|| format!("invalid path glob in rule {}: '{}'", i + 1, pattern))?;
        }
        if let Some(ref pattern) = rule.argv {
            Glob::new(pattern)
                .with_context(|| format!("invalid argv glob in rule {}: '{}'", i + 1, pattern))?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_policy(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn load_valid_policy_file() {
        let f = write_temp_policy(
            r#"
name: test-policy
description: A test
rules:
  - event_type: exec
    action: block
"#,
        );
        let result = load_policy(f.path());
        assert!(result.is_ok());
        let p = result.unwrap();
        assert_eq!(p.name, "test-policy");
    }

    #[test]
    fn reject_empty_name() {
        let f = write_temp_policy(
            r#"
name: ""
description: bad
rules:
  - event_type: exec
    action: block
"#,
        );
        let result = load_policy(f.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name cannot be empty"));
    }

    #[test]
    fn reject_empty_rules() {
        let f = write_temp_policy(
            r#"
name: test
description: no rules
rules: []
"#,
        );
        let result = load_policy(f.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one rule"));
    }

    #[test]
    fn reject_invalid_path_glob() {
        let f = write_temp_policy(
            r#"
name: test
description: bad glob
rules:
  - event_type: exec
    action: block
    path: "[invalid"
"#,
        );
        let result = load_policy(f.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid path glob"));
    }

    #[test]
    fn reject_invalid_argv_glob() {
        let f = write_temp_policy(
            r#"
name: test
description: bad argv glob
rules:
  - event_type: exec
    action: block
    argv: "[unclosed"
"#,
        );
        let result = load_policy(f.path());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid argv glob"));
    }

    #[test]
    fn accept_valid_globs() {
        let f = write_temp_policy(
            r#"
name: test
description: good globs
rules:
  - event_type: exec
    action: allow
    path: "/usr/bin/python*"
  - event_type: unlink
    action: block
    path: "/etc/**"
  - event_type: connect
    action: allow
    path: "127.0.0.1:*"
"#,
        );
        assert!(load_policy(f.path()).is_ok());
    }

    #[test]
    fn load_nonexistent_file_errors() {
        let result = load_policy(Path::new("/nonexistent/path/policy.yaml"));
        assert!(result.is_err());
    }
}
