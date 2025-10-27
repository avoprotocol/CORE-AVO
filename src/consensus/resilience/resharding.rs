use crate::consensus::flow_consensus::ShardLoadMetrics;
use crate::error::{AvoError, AvoResult};
use crate::state::storage::AvocadoStorage;
use crate::types::{Address, ShardId};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationStep {
    pub address: Address,
    pub from_shard: ShardId,
    pub to_shard: ShardId,
    pub chunk_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationBatch {
    pub steps: Vec<MigrationStep>,
    pub merkle_root: String,
    pub total_steps: usize,
    pub batch_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshardingOutcome {
    pub batch: MigrationBatch,
    pub assignments_updated: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleMountainRangeSnapshot {
    pub root: String,
    pub leaves: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerkleMountainRange {
    peaks: Vec<(usize, [u8; 32])>,
    leaves: usize,
}

impl MerkleMountainRange {
    fn new() -> Self {
        Self {
            peaks: Vec::new(),
            leaves: 0,
        }
    }

    fn push(&mut self, leaf: [u8; 32]) {
        let mut current = (0usize, leaf);
        while let Some((height, hash)) = self.peaks.pop() {
            if height == current.0 {
                let parent = hash_nodes(&hash, &current.1);
                current = (height + 1, parent);
            } else {
                self.peaks.push((height, hash));
                self.peaks.push(current);
                self.leaves += 1;
                return;
            }
        }
        self.peaks.push(current);
        self.leaves += 1;
    }

    fn root(&self) -> [u8; 32] {
        if self.peaks.is_empty() {
            return [0u8; 32];
        }

        let mut result = [0u8; 32];
        for (height, hash) in self.peaks.iter().rev() {
            if *height == 0 && self.leaves == 1 {
                return *hash;
            }
            result = if result == [0u8; 32] {
                *hash
            } else {
                hash_nodes(hash, &result)
            };
        }
        result
    }
}

/// Coordina la reasignación dinámica de shards utilizando MMR
#[derive(Debug)]
pub struct ReshardingCoordinator {
    storage: Arc<AvocadoStorage>,
    assignments: Arc<RwLock<HashMap<Address, ShardId>>>,
    pending: Arc<RwLock<VecDeque<MigrationStep>>>,
    mmr: Arc<RwLock<MerkleMountainRange>>,
    next_batch_id: Arc<RwLock<u64>>,
}

impl ReshardingCoordinator {
    pub async fn initialize(storage: Arc<AvocadoStorage>) -> AvoResult<Self> {
        let assignments = Self::load_assignments(&storage).await?;
        let mmr = Self::load_mmr(&storage).await?;
        let next_batch_id = Self::load_next_batch_id(&storage).await?;
        Ok(Self {
            storage,
            assignments: Arc::new(RwLock::new(assignments)),
            pending: Arc::new(RwLock::new(VecDeque::new())),
            mmr: Arc::new(RwLock::new(mmr)),
            next_batch_id: Arc::new(RwLock::new(next_batch_id)),
        })
    }

    pub async fn register_assignment(&self, address: Address, shard: ShardId) -> AvoResult<()> {
        self.assignments.write().await.insert(address, shard);
        self.append_mmr_leaf(address, shard, 0).await?;
        self.persist_assignments().await
    }

    pub async fn evaluate_and_plan(
        &self,
        metrics: &[(ShardId, ShardLoadMetrics)],
    ) -> AvoResult<Option<MigrationBatch>> {
        if metrics.is_empty() {
            return Ok(None);
        }

        let overloaded: Vec<_> = metrics
            .iter()
            .filter(|(_, m)| m.load_factor > 0.85)
            .collect();
        let underloaded: Vec<_> = metrics
            .iter()
            .filter(|(_, m)| m.load_factor < 0.45)
            .collect();

        if overloaded.is_empty() || underloaded.is_empty() {
            return Ok(None);
        }

        let assignments = self.assignments.read().await;
        if assignments.is_empty() {
            return Ok(None);
        }

        let mut plan_steps = Vec::new();
        let mut chunk_index = 0usize;

        for (from_shard, load) in overloaded {
            let accounts: Vec<_> = assignments
                .iter()
                .filter(|(_, shard)| **shard == *from_shard)
                .map(|(addr, _)| *addr)
                .collect();

            if accounts.is_empty() {
                continue;
            }

            let moves = ((accounts.len() as f64) * 0.25).ceil() as usize;
            let moves = moves.max(1);

            for (i, address) in accounts.into_iter().take(moves).enumerate() {
                let target = Self::select_target_shard(&underloaded, (chunk_index + i) as u64);
                plan_steps.push(MigrationStep {
                    address,
                    from_shard: *from_shard,
                    to_shard: target,
                    chunk_index,
                });
                chunk_index += 1;
            }
        }

        drop(assignments);

        if plan_steps.is_empty() {
            return Ok(None);
        }

        let mut pending = self.pending.write().await;
        for step in plan_steps.iter() {
            pending.push_back(step.clone());
        }
        drop(pending);

        let mut mmr_candidate = self.mmr.read().await.clone();
        for step in plan_steps.iter() {
            mmr_candidate.push(Self::mmr_leaf_hash(step));
        }
        let root_hex = hex::encode(mmr_candidate.root());

        let batch_id = {
            let mut counter = self.next_batch_id.write().await;
            let id = *counter;
            *counter += 1;
            self.persist_next_batch_id(*counter).await?;
            id
        };

        let total_steps = plan_steps.len();
        let batch = MigrationBatch {
            steps: plan_steps,
            merkle_root: root_hex,
            total_steps,
            batch_id,
        };

        info!(
            "📦 Resharding plan created | batch={} steps={} root={}",
            batch_id,
            batch.steps.len(),
            batch.merkle_root
        );

        Ok(Some(batch))
    }

    pub async fn apply_pending_migrations(&self, max_steps: usize) -> AvoResult<ReshardingOutcome> {
        let mut pending = self.pending.write().await;
        if pending.is_empty() {
            return Ok(ReshardingOutcome {
                batch: MigrationBatch {
                    steps: Vec::new(),
                    merkle_root: hex::encode(self.mmr.read().await.root()),
                    total_steps: 0,
                    batch_id: *self.next_batch_id.read().await,
                },
                assignments_updated: 0,
            });
        }

        let mut steps = Vec::new();
        for _ in 0..max_steps {
            if let Some(step) = pending.pop_front() {
                steps.push(step);
            } else {
                break;
            }
        }
        drop(pending);

        if steps.is_empty() {
            return Ok(ReshardingOutcome {
                batch: MigrationBatch {
                    steps: Vec::new(),
                    merkle_root: hex::encode(self.mmr.read().await.root()),
                    total_steps: 0,
                    batch_id: *self.next_batch_id.read().await,
                },
                assignments_updated: 0,
            });
        }

        let mut assignments = self.assignments.write().await;
        for step in steps.iter() {
            assignments.insert(step.address, step.to_shard);
            self.append_mmr_leaf(step.address, step.to_shard, step.chunk_index)
                .await?;
        }
        drop(assignments);

        self.persist_assignments().await?;
        self.persist_mmr().await?;

        let merkle_root = hex::encode(self.mmr.read().await.root());
        Ok(ReshardingOutcome {
            assignments_updated: steps.len(),
            batch: MigrationBatch {
                total_steps: steps.len(),
                merkle_root,
                batch_id: *self.next_batch_id.read().await,
                steps,
            },
        })
    }

    pub async fn current_snapshot(&self) -> MerkleMountainRangeSnapshot {
        let mmr = self.mmr.read().await;
        MerkleMountainRangeSnapshot {
            root: hex::encode(mmr.root()),
            leaves: mmr.leaves,
        }
    }

    async fn append_mmr_leaf(
        &self,
        address: Address,
        shard: ShardId,
        chunk_index: usize,
    ) -> AvoResult<()> {
        let mut mmr = self.mmr.write().await;
        mmr.push(Self::leaf_hash(address, shard, chunk_index));
        self.persist_mmr().await
    }

    fn leaf_hash(address: Address, shard: ShardId, chunk_index: usize) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(address.0);
        hasher.update(shard.to_le_bytes());
        hasher.update(chunk_index.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn mmr_leaf_hash(step: &MigrationStep) -> [u8; 32] {
        Self::leaf_hash(step.address, step.to_shard, step.chunk_index)
    }

    fn select_target_shard(candidates: &[&(ShardId, ShardLoadMetrics)], seed: u64) -> ShardId {
        if candidates.is_empty() {
            return 0;
        }
        let index = (seed as usize) % candidates.len();
        candidates[index].0
    }

    async fn load_assignments(
        storage: &Arc<AvocadoStorage>,
    ) -> AvoResult<HashMap<Address, ShardId>> {
        if let Some(bytes) = storage.get_state("resharding:assignments").await? {
            let map: HashMap<String, ShardId> = serde_json::from_slice(&bytes)?;
            Ok(map
                .into_iter()
                .filter_map(|(addr_hex, shard)| {
                    if addr_hex.len() != 40 {
                        return None;
                    }
                    let mut address = [0u8; 20];
                    if hex::decode_to_slice(addr_hex, &mut address).is_ok() {
                        Some((Address(address), shard))
                    } else {
                        None
                    }
                })
                .collect())
        } else {
            Ok(HashMap::new())
        }
    }

    async fn load_mmr(storage: &Arc<AvocadoStorage>) -> AvoResult<MerkleMountainRange> {
        if let Some(bytes) = storage.get_state("resharding:mmr").await? {
            Ok(serde_json::from_slice(&bytes)?)
        } else {
            Ok(MerkleMountainRange::new())
        }
    }

    async fn load_next_batch_id(storage: &Arc<AvocadoStorage>) -> AvoResult<u64> {
        if let Some(bytes) = storage.get_state("resharding:next_batch_id").await? {
            let id = serde_json::from_slice::<u64>(&bytes)?;
            Ok(id)
        } else {
            Ok(1)
        }
    }

    async fn persist_assignments(&self) -> AvoResult<()> {
        let assignments = self.assignments.read().await;
        let mut serialized = HashMap::new();
        for (address, shard) in assignments.iter() {
            serialized.insert(hex::encode(address.0), *shard);
        }
        let bytes = serde_json::to_vec(&serialized)?;
        self.storage
            .store_state("resharding:assignments", &bytes)
            .await
    }

    async fn persist_mmr(&self) -> AvoResult<()> {
        let mmr = self.mmr.read().await;
        let bytes = serde_json::to_vec(&*mmr)?;
        self.storage.store_state("resharding:mmr", &bytes).await
    }

    async fn persist_next_batch_id(&self, id: u64) -> AvoResult<()> {
        let bytes = serde_json::to_vec(&id)?;
        self.storage
            .store_state("resharding:next_batch_id", &bytes)
            .await
    }
}

fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mmr_updates_and_snapshot() {
        let storage = Arc::new(
            AvocadoStorage::new(crate::state::storage::StorageConfig::with_path(
                "./.tmp_resharding",
            ))
            .expect("storage init"),
        );
        let coordinator = ReshardingCoordinator::initialize(storage.clone())
            .await
            .expect("initialize");
        let address = Address([1u8; 20]);
        coordinator
            .register_assignment(address, 1)
            .await
            .expect("register");
        let snapshot = coordinator.current_snapshot().await;
        assert!(snapshot.leaves >= 1);
    }

    #[tokio::test]
    async fn plan_and_apply_migrations() {
        let storage = Arc::new(
            AvocadoStorage::new(crate::state::storage::StorageConfig::with_path(
                "./.tmp_resharding_plan",
            ))
            .expect("storage init"),
        );
        let coordinator = ReshardingCoordinator::initialize(storage.clone())
            .await
            .expect("initialize");
        let assignments = vec![
            (Address([0u8; 20]), 0u32),
            (Address([1u8; 20]), 0u32),
            (Address([2u8; 20]), 0u32),
        ];
        for (address, shard) in assignments.clone() {
            coordinator
                .register_assignment(address, shard)
                .await
                .expect("assign");
        }

        let metrics = vec![
            (
                0u32,
                ShardLoadMetrics {
                    load_factor: 0.95,
                    capacity_utilization: 0.9,
                    estimated_tps: 100.0,
                    validator_count: 5,
                    pending_transactions: 50,
                    average_block_time_ms: 600,
                },
            ),
            (
                1u32,
                ShardLoadMetrics {
                    load_factor: 0.2,
                    capacity_utilization: 0.3,
                    estimated_tps: 20.0,
                    validator_count: 5,
                    pending_transactions: 5,
                    average_block_time_ms: 400,
                },
            ),
        ];

        let plan = coordinator.evaluate_and_plan(&metrics).await.expect("plan");
        assert!(plan.is_some());

        let outcome = coordinator
            .apply_pending_migrations(10)
            .await
            .expect("apply");
        assert!(outcome.assignments_updated > 0);
    }
}
