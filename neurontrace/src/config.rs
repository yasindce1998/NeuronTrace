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
