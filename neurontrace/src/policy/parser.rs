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
