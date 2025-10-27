use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
struct CacheEntry {
    value: Value,
    expires_at: Instant,
    hits: u64,
}

#[derive(Debug)]
pub struct RpcCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    default_ttl: Duration,
    max_entries: usize,
    stats: RwLock<CacheStats>,
}

#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub total_requests: u64,
}

impl RpcCache {
    pub fn new(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            default_ttl,
            max_entries,
            stats: RwLock::new(CacheStats::default()),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Value> {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;

        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(key) {
            if entry.expires_at > Instant::now() {
                entry.hits += 1;
                stats.hits += 1;
                return Some(entry.value.clone());
            } else {
                // Entry expired
                entries.remove(key);
            }
        }

        stats.misses += 1;
        None
    }

    pub async fn set(&self, key: String, value: Value, ttl: Option<Duration>) -> bool {
        let mut entries = self.entries.write().await;

        // Check if we need to evict entries
        if entries.len() >= self.max_entries {
            self.evict_expired(&mut entries).await;

            if entries.len() >= self.max_entries {
                self.evict_lru(&mut entries).await;
            }
        }

        let expires_at = Instant::now() + ttl.unwrap_or(self.default_ttl);
        let entry = CacheEntry {
            value,
            expires_at,
            hits: 0,
        };

        entries.insert(key, entry);
        true
    }

    async fn evict_expired(&self, entries: &mut HashMap<String, CacheEntry>) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for (key, entry) in entries.iter() {
            if entry.expires_at <= now {
                to_remove.push(key.clone());
            }
        }

        let mut stats = self.stats.write().await;
        for key in to_remove {
            entries.remove(&key);
            stats.evictions += 1;
        }
    }

    async fn evict_lru(&self, entries: &mut HashMap<String, CacheEntry>) {
        // Find the entry with the least hits
        if let Some((lru_key, _)) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.hits)
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            entries.remove(&lru_key);
            let mut stats = self.stats.write().await;
            stats.evictions += 1;
        }
    }

    pub async fn invalidate(&self, key: &str) -> bool {
        let mut entries = self.entries.write().await;
        entries.remove(key).is_some()
    }

    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        let mut stats = self.stats.write().await;
        *stats = CacheStats::default();
    }

    pub async fn stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }

    pub async fn size(&self) -> usize {
        self.entries.read().await.len()
    }

    pub fn hit_rate(&self) -> f64 {
        let stats = futures::executor::block_on(self.stats.read());
        if stats.total_requests == 0 {
            0.0
        } else {
            stats.hits as f64 / stats.total_requests as f64
        }
    }

    // Cache keys for different types of data
    pub fn balance_key(address: &str) -> String {
        format!("balance:{}", address)
    }

    pub fn block_key(number: u64) -> String {
        format!("block:{}", number)
    }

    pub fn transaction_key(hash: &str) -> String {
        format!("tx:{}", hash)
    }

    pub fn account_key(address: &str) -> String {
        format!("account:{}", address)
    }

    pub fn shard_info_key(shard_id: u32) -> String {
        format!("shard:{}", shard_id)
    }
}
