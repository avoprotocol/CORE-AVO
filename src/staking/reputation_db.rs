//! Reputation persistence layer using RocksDB

use crate::staking::reputation::*;
use rocksdb::{DB, Options, IteratorMode};
use serde::{Serialize, Deserialize};
use std::path::Path;

/// Reputation database wrapper
pub struct ReputationDB {
    db: DB,
}

impl ReputationDB {
    /// Open or create reputation database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        
        let db = DB::open(&opts, path)
            .map_err(|e| format!("Failed to open reputation DB: {}", e))?;
            
        Ok(Self { db })
    }
    
    /// Save validator reputation
    pub fn save_reputation(&self, validator_id: u64, reputation: &ValidatorReputation) -> Result<(), String> {
        let key = format!("rep_{}", validator_id);
        let value = serde_json::to_vec(reputation)
            .map_err(|e| format!("Failed to serialize reputation: {}", e))?;
            
        self.db.put(key.as_bytes(), value)
            .map_err(|e| format!("Failed to save reputation: {}", e))?;
            
        Ok(())
    }
    
    /// Load validator reputation
    pub fn load_reputation(&self, validator_id: u64) -> Result<Option<ValidatorReputation>, String> {
        let key = format!("rep_{}", validator_id);
        
        match self.db.get(key.as_bytes()) {
            Ok(Some(value)) => {
                let reputation: ValidatorReputation = serde_json::from_slice(&value)
                    .map_err(|e| format!("Failed to deserialize reputation: {}", e))?;
                Ok(Some(reputation))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to load reputation: {}", e))
        }
    }
    
    /// Load all reputations
    pub fn load_all_reputations(&self) -> Result<Vec<(u64, ValidatorReputation)>, String> {
        let mut reputations = Vec::new();
        
        let iter = self.db.iterator(IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| format!("Iterator error: {}", e))?;
            
            // Only process reputation keys (rep_*)
            if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                if key_str.starts_with("rep_") {
                    if let Ok(validator_id) = key_str.trim_start_matches("rep_").parse::<u64>() {
                        if let Ok(reputation) = serde_json::from_slice::<ValidatorReputation>(&value) {
                            reputations.push((validator_id, reputation));
                        }
                    }
                }
            }
        }
        
        Ok(reputations)
    }
    
    /// Delete validator reputation
    pub fn delete_reputation(&self, validator_id: u64) -> Result<(), String> {
        let key = format!("rep_{}", validator_id);
        self.db.delete(key.as_bytes())
            .map_err(|e| format!("Failed to delete reputation: {}", e))?;
        Ok(())
    }
    
    /// Get total count of reputations
    pub fn count(&self) -> usize {
        let iter = self.db.iterator(IteratorMode::Start);
        iter.filter(|item| {
            if let Ok((key, _)) = item {
                if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                    return key_str.starts_with("rep_");
                }
            }
            false
        }).count()
    }
}
