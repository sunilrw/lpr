use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Default, Serialize, Deserialize)]
pub struct CheckpointStore {
    pub offsets: HashMap<String, u64>,
}

impl CheckpointStore {
    pub fn load(path: Option<&str>) -> Self {
        if let Some(p) = path {
            if let Ok(data) = fs::read_to_string(p) {
                if let Ok(store) = serde_json::from_str(&data) {
                    return store;
                }
            }
        }
        Self::default()
    }

    pub fn get_offset(&self, file_path: &Path) -> u64 {
        let key = file_path.to_string_lossy().to_string();
        self.offsets.get(&key).copied().unwrap_or(0)
    }

    pub fn update_offset(&mut self, file_path: &Path, new_offset: u64) {
        let key = file_path.to_string_lossy().to_string();
        self.offsets.insert(key, new_offset);
    }

    pub fn save(&self, path: Option<&str>) -> Result<()> {
        if let Some(p) = path {
            let json = serde_json::to_string_pretty(self)?;
            fs::write(p, json)?;
        }
        Ok(())
    }
}
