use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Entry {
    pub host: String,
    pub port: u16,
}

pub struct Allowlist {
    persistent: HashSet<Entry>,
    session: HashSet<Entry>,
    path: PathBuf,
}

/// Which set an allow decision came from. Surfaced in the audit log so a
/// later sweep can tell "user clicked allow-once during this session" apart
/// from "user has long-term allowlisted this host".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Persistent,
    Session,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Persistent => "persistent",
            Source::Session => "session",
        }
    }
}

impl Allowlist {
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let persistent = if path.exists() {
            let data = std::fs::read_to_string(path)?;
            serde_json::from_str::<Vec<Entry>>(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
                .into_iter()
                .collect()
        } else {
            HashSet::new()
        };
        Ok(Self {
            persistent,
            session: HashSet::new(),
            path: path.to_owned(),
        })
    }

    /// Returns which set (persistent vs session) holds the entry, or
    /// `None` if neither does. Persistent is checked first: an entry
    /// promoted from session to persistent (or duplicated across both)
    /// classifies as `persistent`.
    pub fn classify(&self, host: &str, port: u16) -> Option<Source> {
        let entry = Entry { host: host.to_owned(), port };
        if self.persistent.contains(&entry) {
            Some(Source::Persistent)
        } else if self.session.contains(&entry) {
            Some(Source::Session)
        } else {
            None
        }
    }

    pub fn add_session(&mut self, host: String, port: u16) {
        self.session.insert(Entry { host, port });
    }

    pub async fn add_persist(&mut self, host: String, port: u16) -> std::io::Result<()> {
        self.persistent.insert(Entry { host, port });
        self.save().await
    }

    pub async fn remove(&mut self, host: &str, port: u16) -> std::io::Result<()> {
        let entry = Entry { host: host.to_owned(), port };
        self.session.remove(&entry);
        if self.persistent.remove(&entry) {
            self.save().await?;
        }
        Ok(())
    }

    pub fn entries(&self) -> Vec<Entry> {
        let mut v: Vec<Entry> = self.persistent.iter().cloned().collect();
        v.sort_by(|a, b| a.host.cmp(&b.host));
        v
    }

    async fn save(&self) -> std::io::Result<()> {
        let entries = self.entries();
        let json = serde_json::to_string_pretty(&entries)
            .map_err(std::io::Error::other)?;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let tmp = self.path.with_extension("tmp");
        tokio::fs::write(&tmp, &json).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }
}
