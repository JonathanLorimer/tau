use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").expect("HOME not set")).join(".config")
        })
        .join("tau")
}

pub fn runtime_dir() -> PathBuf {
    std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

pub fn default_allowlist() -> PathBuf {
    config_dir().join("allow.json")
}

pub fn default_socket() -> PathBuf {
    runtime_dir().join("tau.sock")
}
