use std::path::PathBuf;

const CONFIG_FILE: &str = "/etc/neurontrace/config.yaml";

#[derive(Default)]
pub struct Config {
    pub policy: Option<PathBuf>,
    pub cgroup: Option<PathBuf>,
    pub feedback: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
struct ConfigFile {
    policy: Option<PathBuf>,
    cgroup: Option<PathBuf>,
    feedback: Option<PathBuf>,
}

impl Config {
    pub fn load() -> Self {
        let mut config = Self::from_file();
        config.apply_env();
        config
    }

    fn from_file() -> Self {
        let path = std::path::Path::new(CONFIG_FILE);
        if !path.exists() {
            return Self::default();
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };

        let file: ConfigFile = match serde_yaml::from_str(&content) {
            Ok(f) => f,
            Err(_) => return Self::default(),
        };

        Self {
            policy: file.policy,
            cgroup: file.cgroup,
            feedback: file.feedback,
        }
    }

    fn apply_env(&mut self) {
        if let Ok(val) = std::env::var("NEURONTRACE_POLICY") {
            self.policy = Some(PathBuf::from(val));
        }
        if let Ok(val) = std::env::var("NEURONTRACE_CGROUP") {
            self.cgroup = Some(PathBuf::from(val));
        }
        if let Ok(val) = std::env::var("NEURONTRACE_FEEDBACK") {
            self.feedback = Some(PathBuf::from(val));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_has_no_values() {
        let config = Config::default();
        assert!(config.policy.is_none());
        assert!(config.cgroup.is_none());
        assert!(config.feedback.is_none());
    }

    #[test]
    fn env_vars_override_defaults() {
        std::env::set_var("NEURONTRACE_POLICY", "/tmp/test-policy.yaml");
        std::env::set_var("NEURONTRACE_CGROUP", "/sys/fs/cgroup/test");
        std::env::set_var("NEURONTRACE_FEEDBACK", "/tmp/feedback.sock");

        let mut config = Config::default();
        config.apply_env();

        assert_eq!(config.policy.unwrap(), PathBuf::from("/tmp/test-policy.yaml"));
        assert_eq!(config.cgroup.unwrap(), PathBuf::from("/sys/fs/cgroup/test"));
        assert_eq!(config.feedback.unwrap(), PathBuf::from("/tmp/feedback.sock"));

        std::env::remove_var("NEURONTRACE_POLICY");
        std::env::remove_var("NEURONTRACE_CGROUP");
        std::env::remove_var("NEURONTRACE_FEEDBACK");
    }

    #[test]
    fn parses_valid_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "policy: /etc/neurontrace/policy.yaml\ncgroup: /sys/fs/cgroup/nt\nfeedback: /run/nt/fb.sock"
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let file: ConfigFile = serde_yaml::from_str(&content).unwrap();

        assert_eq!(file.policy.unwrap(), PathBuf::from("/etc/neurontrace/policy.yaml"));
        assert_eq!(file.cgroup.unwrap(), PathBuf::from("/sys/fs/cgroup/nt"));
        assert_eq!(file.feedback.unwrap(), PathBuf::from("/run/nt/fb.sock"));
    }

    #[test]
    fn partial_config_file_leaves_missing_as_none() {
        let content = "policy: /etc/neurontrace/policy.yaml\n";
        let file: ConfigFile = serde_yaml::from_str(content).unwrap();

        assert_eq!(file.policy.unwrap(), PathBuf::from("/etc/neurontrace/policy.yaml"));
        assert!(file.cgroup.is_none());
        assert!(file.feedback.is_none());
    }
}

