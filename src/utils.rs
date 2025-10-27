use crate::error::{AvoError, AvoResult};
use crate::types::{Epoch, Hash, ShardId, Timestamp, ValidatorId};
use rand::{thread_rng, Rng};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Utility functions for hashing
pub mod hash {
    use super::*;

    pub fn hash_bytes(data: &[u8]) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    pub fn hash_multiple(data_parts: &[&[u8]]) -> Hash {
        let mut hasher = Sha3_256::new();
        for part in data_parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }

    pub fn merkle_root(leaves: &[Hash]) -> Hash {
        if leaves.is_empty() {
            return [0; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_multiple(&[&chunk[0], &chunk[1]])
                } else {
                    chunk[0] // Odd number of elements, last one goes up unchanged
                };
                next_level.push(hash);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Crea un Merkle proof para un leaf en una posición específica
    pub fn merkle_proof(leaves: &[Hash], index: usize) -> AvoResult<Vec<Hash>> {
        if index >= leaves.len() {
            return Err(AvoError::internal("Merkle proof index out of bounds"));
        }

        let mut proof = Vec::new();
        let mut current_level = leaves.to_vec();
        let mut current_index = index;

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                proof.push(current_level[sibling_index]);
            }

            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_multiple(&[&chunk[0], &chunk[1]])
                } else {
                    chunk[0]
                };
                next_level.push(hash);
            }

            current_level = next_level;
            current_index /= 2;
        }

        Ok(proof)
    }

    /// Verifica un Merkle proof
    pub fn verify_merkle_proof(leaf: &Hash, proof: &[Hash], index: usize, root: &Hash) -> bool {
        let mut current_hash = *leaf;
        let mut current_index = index;

        for sibling in proof {
            current_hash = if current_index % 2 == 0 {
                hash_multiple(&[&current_hash, sibling])
            } else {
                hash_multiple(&[sibling, &current_hash])
            };
            current_index /= 2;
        }

        current_hash == *root
    }
}

/// Utility functions for time management
pub mod time {
    use super::*;

    pub fn current_timestamp() -> Timestamp {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    pub fn timestamp_to_epoch(timestamp: Timestamp, epoch_duration_ms: u64) -> Epoch {
        timestamp / epoch_duration_ms
    }

    pub fn epoch_to_timestamp(epoch: Epoch, epoch_duration_ms: u64) -> Timestamp {
        epoch * epoch_duration_ms
    }

    pub fn is_timeout(start_time: Timestamp, timeout_ms: u64) -> bool {
        current_timestamp() - start_time > timeout_ms
    }

    pub fn sleep_until_epoch(target_epoch: Epoch, epoch_duration_ms: u64) -> std::time::Duration {
        let target_timestamp = epoch_to_timestamp(target_epoch, epoch_duration_ms);
        let current = current_timestamp();

        if target_timestamp > current {
            std::time::Duration::from_millis(target_timestamp - current)
        } else {
            std::time::Duration::from_millis(0)
        }
    }
}

/// Utility functions for validator selection and consensus
pub mod consensus {
    use super::*;

    /// Selecciona validadores usando VRF para evitar bias
    pub fn select_validators_vrf(
        validators: &[ValidatorId],
        seed: &[u8],
        count: usize,
    ) -> Vec<ValidatorId> {
        if count >= validators.len() {
            return validators.to_vec();
        }

        let mut selected = Vec::new();
        let mut used_indices = std::collections::HashSet::new();

        for i in 0..count {
            let input = [seed, &i.to_le_bytes()].concat();
            let hash = hash::hash_bytes(&input);
            let index =
                u64::from_le_bytes(hash[0..8].try_into().unwrap()) as usize % validators.len();

            if !used_indices.contains(&index) {
                selected.push(validators[index]);
                used_indices.insert(index);
            } else {
                // Linear probe for next available validator
                let mut next_index = (index + 1) % validators.len();
                while used_indices.contains(&next_index) && selected.len() < count {
                    next_index = (next_index + 1) % validators.len();
                }
                if !used_indices.contains(&next_index) {
                    selected.push(validators[next_index]);
                    used_indices.insert(next_index);
                }
            }
        }

        selected
    }

    /// Calcula el peso de voto basado en stake
    pub fn calculate_voting_weight(stake: u128, total_stake: u128) -> f64 {
        if total_stake == 0 {
            return 0.0;
        }
        stake as f64 / total_stake as f64
    }

    /// Verifica si se alcanzó el quorum
    pub fn check_quorum(
        votes: &HashMap<ValidatorId, u128>,
        total_stake: u128,
        threshold: f64,
    ) -> bool {
        let total_votes: u128 = votes.values().sum();
        let vote_ratio = total_votes as f64 / total_stake as f64;
        vote_ratio >= threshold
    }

    /// Calcula la puntuación de performance de un validador
    pub fn calculate_performance_score(
        blocks_proposed: u32,
        blocks_validated: u32,
        votes_cast: u32,
        expected_votes: u32,
        uptime_ratio: f64,
    ) -> f64 {
        let proposal_score = if blocks_proposed > 0 { 1.0 } else { 0.8 };
        let validation_score = if blocks_validated > 0 { 1.0 } else { 0.9 };
        let voting_score = if expected_votes > 0 {
            votes_cast as f64 / expected_votes as f64
        } else {
            1.0
        };

        (proposal_score + validation_score + voting_score + uptime_ratio) / 4.0
    }
}

/// Utility functions for sharding operations
pub mod sharding {
    use super::*;

    /// Calcula el shard ID para una dirección usando hash consistente
    pub fn calculate_shard_for_address(address: &[u8], shard_count: u32) -> ShardId {
        if shard_count == 0 {
            return 0;
        }
        let hash = hash::hash_bytes(address);
        let shard_index = u32::from_le_bytes(hash[0..4].try_into().unwrap()) % shard_count;
        shard_index
    }

    /// Verifica si un shard debe dividirse basado en carga
    pub fn should_split_shard(load_factor: f64, threshold: f64) -> bool {
        load_factor > threshold
    }

    /// Verifica si dos shards deben fusionarse
    pub fn should_merge_shards(load1: f64, load2: f64, threshold: f64) -> bool {
        (load1 + load2) / 2.0 < threshold
    }

    /// Calcula la distribución de carga entre shards
    pub fn calculate_load_distribution(shard_loads: &[f64]) -> f64 {
        if shard_loads.is_empty() {
            return 0.0;
        }

        let mean = shard_loads.iter().sum::<f64>() / shard_loads.len() as f64;
        let variance = shard_loads
            .iter()
            .map(|&load| (load - mean).powi(2))
            .sum::<f64>()
            / shard_loads.len() as f64;

        variance.sqrt() / mean // Coefficient of variation
    }

    /// Selecciona el mejor shard para migración
    pub fn select_migration_target(shard_loads: &[(ShardId, f64)]) -> Option<ShardId> {
        shard_loads
            .iter()
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .map(|(id, _)| *id)
    }
}

/// Utility functions for networking and peer management
pub mod network {
    use super::*;

    /// Genera un ID de nodo único
    pub fn generate_node_id() -> String {
        let mut rng = thread_rng();
        let bytes: [u8; 16] = rng.gen();
        hex::encode(bytes)
    }

    /// Verifica si una dirección de red es válida
    pub fn is_valid_network_address(address: &str) -> bool {
        // Verificación básica de formato IP:puerto
        address.contains(':') && !address.is_empty()
    }

    /// Calcula la latencia de red esperada entre nodos
    pub fn estimate_network_latency(distance_km: f64) -> u64 {
        // Estimación basada en velocidad de la luz en fibra óptica
        let speed_of_light_fiber = 200_000.0; // km/s
        let base_latency = (distance_km / speed_of_light_fiber) * 1000.0; // ms
        let processing_overhead = 2.0; // ms

        (base_latency + processing_overhead) as u64
    }

    /// Selecciona peers óptimos para conectar
    pub fn select_optimal_peers(
        available_peers: &[(String, f64)], // (peer_id, score)
        max_connections: usize,
    ) -> Vec<String> {
        let mut peers = available_peers.to_vec();
        peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        peers
            .into_iter()
            .take(max_connections)
            .map(|(id, _)| id)
            .collect()
    }
}

/// Utility functions for mathematical operations
pub mod math {

    /// Calcula el threshold de quorum (2/3 + 1)
    pub fn calculate_quorum_threshold(total_validators: u32) -> u32 {
        (total_validators * 2 / 3) + 1
    }

    /// Calcula el peso de stake
    pub fn calculate_stake_weight(stake: u128, total_stake: u128) -> f64 {
        if total_stake == 0 {
            return 0.0;
        }
        stake as f64 / total_stake as f64
    }

    /// Calcula la media móvil exponencial
    pub fn exponential_moving_average(current: f64, new_value: f64, alpha: f64) -> f64 {
        alpha * new_value + (1.0 - alpha) * current
    }

    /// Calcula el percentil de una lista de valores
    pub fn percentile(values: &mut [f64], percentile: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }

        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let index = (percentile * (values.len() - 1) as f64) as usize;
        values[index.min(values.len() - 1)]
    }

    /// Verifica si un número es potencia de 2
    pub fn is_power_of_two(n: u32) -> bool {
        n > 0 && (n & (n - 1)) == 0
    }

    /// Encuentra el siguiente número que es potencia de 2
    pub fn next_power_of_two(n: u32) -> u32 {
        if n <= 1 {
            return 1;
        }
        (n - 1).next_power_of_two()
    }
}

/// Utility functions for serialization and encoding
pub mod encoding {
    use crate::error::{AvoError, AvoResult};
    use base64::Engine;

    /// Serializa un objeto a bytes usando bincode
    pub fn serialize_to_bytes<T: serde::Serialize>(obj: &T) -> AvoResult<Vec<u8>> {
        bincode::serialize(obj).map_err(AvoError::from)
    }

    /// Deserializa bytes a un objeto usando bincode
    pub fn deserialize_from_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> AvoResult<T> {
        bincode::deserialize(bytes).map_err(AvoError::from)
    }

    /// Codifica bytes a hexadecimal
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Decodifica hexadecimal a bytes
    pub fn hex_to_bytes(hex_str: &str) -> AvoResult<Vec<u8>> {
        hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
            .map_err(|_| AvoError::parse("Invalid hex string"))
    }

    /// Codifica datos usando base64
    pub fn encode_base64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// Decodifica datos de base64
    pub fn decode_base64(encoded: &str) -> AvoResult<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| AvoError::parse("Invalid base64 string"))
    }
}

/// Utility functions for rate limiting and resource management
pub mod rate_limit {
    use super::*;
    use std::collections::HashMap;

    pub struct TokenBucket {
        capacity: u32,
        tokens: u32,
        refill_rate: u32, // tokens per second
        last_refill: Timestamp,
    }

    impl TokenBucket {
        pub fn new(capacity: u32, refill_rate: u32) -> Self {
            Self {
                capacity,
                tokens: capacity,
                refill_rate,
                last_refill: time::current_timestamp(),
            }
        }

        pub fn consume(&mut self, tokens: u32) -> bool {
            self.refill();

            if self.tokens >= tokens {
                self.tokens -= tokens;
                true
            } else {
                false
            }
        }

        fn refill(&mut self) {
            let now = time::current_timestamp();
            let elapsed_ms = now - self.last_refill;
            let new_tokens = (elapsed_ms * self.refill_rate as u64) / 1000;

            if new_tokens > 0 {
                self.tokens = (self.tokens + new_tokens as u32).min(self.capacity);
                self.last_refill = now;
            }
        }
    }

    pub struct RateLimiter {
        buckets: HashMap<String, TokenBucket>,
        default_capacity: u32,
        default_refill_rate: u32,
    }

    impl RateLimiter {
        pub fn new(default_capacity: u32, default_refill_rate: u32) -> Self {
            Self {
                buckets: HashMap::new(),
                default_capacity,
                default_refill_rate,
            }
        }

        pub fn check_rate_limit(&mut self, key: &str, tokens: u32) -> bool {
            let bucket = self.buckets.entry(key.to_string()).or_insert_with(|| {
                TokenBucket::new(self.default_capacity, self.default_refill_rate)
            });

            bucket.consume(tokens)
        }
    }
}

/// Utility functions for random number generation
pub mod random {
    use rand::{thread_rng, Rng};

    /// Genera bytes aleatorios seguros
    pub fn secure_random_bytes(length: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        (0..length).map(|_| rng.gen()).collect()
    }

    /// Genera un entero aleatorio en un rango
    pub fn random_in_range(min: u64, max: u64) -> u64 {
        let mut rng = thread_rng();
        rng.gen_range(min..=max)
    }

    /// Selecciona un elemento aleatorio de una lista
    pub fn random_choice<T: Clone>(items: &[T]) -> Option<T> {
        if items.is_empty() {
            return None;
        }
        let mut rng = thread_rng();
        let index = rng.gen_range(0..items.len());
        Some(items[index].clone())
    }

    /// Barajea una lista usando Fisher-Yates
    pub fn shuffle<T>(items: &mut [T]) {
        let mut rng = thread_rng();
        for i in (1..items.len()).rev() {
            let j = rng.gen_range(0..=i);
            items.swap(i, j);
        }
    }
}

/// Utility functions for performance monitoring
pub mod performance {
    use std::time::Instant;

    pub struct PerformanceTimer {
        start: Instant,
        name: String,
    }

    impl PerformanceTimer {
        pub fn new(name: impl Into<String>) -> Self {
            Self {
                start: Instant::now(),
                name: name.into(),
            }
        }

        pub fn elapsed_ms(&self) -> u64 {
            self.start.elapsed().as_millis() as u64
        }
    }

    impl Drop for PerformanceTimer {
        fn drop(&mut self) {
            let elapsed = self.elapsed_ms();
            tracing::debug!("Performance [{}]: {}ms", self.name, elapsed);
        }
    }

    /// Macro para medir tiempo de ejecución
    #[macro_export]
    macro_rules! measure_time {
        ($name:expr, $block:block) => {{
            let _timer = $crate::utils::performance::PerformanceTimer::new($name);
            $block
        }};
    }

    /// Calcula TPS basado en transacciones y tiempo
    pub fn calculate_tps(transaction_count: u64, duration_ms: u64) -> f64 {
        if duration_ms == 0 {
            return 0.0;
        }
        (transaction_count as f64 * 1000.0) / duration_ms as f64
    }

    /// Calcula latencia promedio
    pub fn calculate_average_latency(latencies: &[u64]) -> f64 {
        if latencies.is_empty() {
            return 0.0;
        }
        latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
    }
}

/// Utility functions for configuration validation
pub mod validation {
    use super::*;

    /// Valida que un puerto esté en rango válido
    pub fn is_valid_port(port: u16) -> bool {
        port > 0 && port < 65535
    }

    /// Valida que un stake esté en rango válido
    pub fn is_valid_stake(stake: u128, min_stake: u128) -> bool {
        stake >= min_stake
    }

    /// Valida que un threshold esté en rango [0.0, 1.0]
    pub fn is_valid_threshold(threshold: f64) -> bool {
        threshold >= 0.0 && threshold <= 1.0
    }

    /// Valida una dirección hexadecimal
    pub fn is_valid_hex_address(address: &str) -> bool {
        if !address.starts_with("0x") {
            return false;
        }

        let hex_part = &address[2..];
        hex_part.len() == 40 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Busca un validador por ID
    pub fn find_validator_by_id(
        validators: &[ValidatorId],
        target_id: ValidatorId,
    ) -> Option<usize> {
        for (index, &validator_id) in validators.iter().enumerate() {
            if validator_id == target_id {
                return Some(index);
            }
        }

        None
    }
}
