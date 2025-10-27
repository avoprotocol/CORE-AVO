use crate::consensus::dag_algorithms::{BlockDAG, DAGStatistics};
use crate::error::{AvoError, AvoResult};
use crate::types::{Block, BlockId, ShardId};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Motor de gestión del BlockDAG por shard.
pub struct ShardDagEngine {
    shard_id: ShardId,
    dag: Arc<RwLock<BlockDAG>>,
    max_tips: usize,
}

impl Clone for ShardDagEngine {
    fn clone(&self) -> Self {
        Self {
            shard_id: self.shard_id,
            dag: self.dag.clone(),
            max_tips: self.max_tips,
        }
    }
}

impl ShardDagEngine {
    /// Crea un nuevo motor DAG para un shard.
    pub fn new(shard_id: ShardId, max_tips: usize) -> Self {
        Self {
            shard_id,
            dag: Arc::new(RwLock::new(BlockDAG::new())),
            max_tips: max_tips.max(1),
        }
    }

    /// Inserta un bloque en el DAG del shard.
    pub async fn insert_block(&self, block: Block) -> AvoResult<()> {
        if block.shard_id != self.shard_id {
            return Err(AvoError::InvalidInput(format!(
                "Block pertenece al shard {} pero el motor gestiona el shard {}",
                block.shard_id, self.shard_id
            )));
        }

        let block_id = block.id;
        let parents = block.parents.clone();

        {
            let mut dag = self.dag.write().await;
            dag.add_block(block)?;
        }

        debug!(
            shard = self.shard_id,
            block = ?hex::encode(block_id.as_bytes()),
            parent_count = parents.len(),
            "Bloque insertado en el DAG del shard"
        );

        Ok(())
    }

    /// Selecciona hasta *k* padres usando la heurística GHOSTDAG.
    pub async fn select_parents(&self, k: usize) -> Vec<BlockId> {
        let dag = self.dag.read().await;
        let limit = k.max(1).min(self.max_tips);
        dag.select_tips_ghostdag(limit)
            .into_iter()
            .filter_map(|bytes| {
                BlockId::from_bytes(&bytes).or_else(|| {
                    warn!("ID de bloque inválido devuelto por GHOSTDAG");
                    None
                })
            })
            .collect()
    }

    /// Devuelve los tips actuales del DAG.
    pub async fn tips(&self) -> Vec<BlockId> {
        let dag = self.dag.read().await;
        dag.get_tips()
            .into_iter()
            .filter_map(|bytes| BlockId::from_bytes(&bytes))
            .collect()
    }

    /// Comprueba si un bloque pertenece al DAG.
    pub async fn contains(&self, block_id: &BlockId) -> bool {
        let dag = self.dag.read().await;
        dag.contains(block_id.as_bytes())
    }

    /// Obtiene un bloque del DAG.
    pub async fn get_block(&self, block_id: &BlockId) -> Option<Block> {
        let dag = self.dag.read().await;
        dag.get_node(block_id.as_bytes())
            .map(|node| node.data.clone())
    }

    /// Prunea todos los nodos con altura inferior a `keep_height`.
    pub async fn prune_below(&self, keep_height: u64) -> usize {
        let mut dag = self.dag.write().await;
        dag.prune_old_nodes(keep_height)
    }

    /// Obtiene métricas resumidas del DAG.
    pub async fn metrics(&self) -> ShardDagMetrics {
        let dag = self.dag.read().await;
        let stats: DAGStatistics = dag.get_statistics();
        ShardDagMetrics::from(stats)
    }

    /// Acceso al identificador del shard.
    pub fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Número máximo de tips considerados al seleccionar padres.
    pub fn max_tips(&self) -> usize {
        self.max_tips
    }
}

/// Métricas del DAG de un shard.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardDagMetrics {
    pub total_nodes: usize,
    pub tips: usize,
    pub roots: usize,
    pub max_height: u64,
    pub has_cycles: bool,
    pub average_parents: f64,
}

impl From<DAGStatistics> for ShardDagMetrics {
    fn from(stats: DAGStatistics) -> Self {
        Self {
            total_nodes: stats.total_nodes,
            tips: stats.tips_count,
            roots: stats.roots_count,
            max_height: stats.max_height,
            has_cycles: stats.has_cycles,
            average_parents: stats.average_parents,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockId, ShardId, Transaction};

    fn dummy_block(shard_id: ShardId, height: u64, parents: Vec<BlockId>) -> Block {
        let mut block = Block {
            id: BlockId::zero(),
            shard_id,
            epoch: 0,
            timestamp: height * 1_000,
            height,
            transactions: Vec::<Transaction>::new(),
            parents,
            state_root: [0u8; 32],
            transaction_merkle_root: [0u8; 32],
            validator_set_hash: [0u8; 32],
            proposer_signature: Vec::new(),
        };
        block.id = block.compute_id();
        block
    }

    #[tokio::test]
    async fn insert_and_retrieve_block() {
        let engine = ShardDagEngine::new(1, 4);
        let block = dummy_block(1, 1, vec![BlockId::zero()]);

        engine.insert_block(block.clone()).await.unwrap();

        assert!(engine.contains(&block.id).await);
        let fetched = engine.get_block(&block.id).await.expect("block missing");
        assert_eq!(fetched.id, block.id);
    }

    #[tokio::test]
    async fn select_parents_ghostdag() {
        let engine = ShardDagEngine::new(2, 2);
        let genesis_child = dummy_block(2, 1, vec![BlockId::zero()]);
        let second_block = dummy_block(2, 2, vec![genesis_child.id]);
        let fork_block = dummy_block(2, 3, vec![genesis_child.id]);

        engine.insert_block(genesis_child.clone()).await.unwrap();
        engine.insert_block(second_block.clone()).await.unwrap();
        engine.insert_block(fork_block.clone()).await.unwrap();

        let parents = engine.select_parents(2).await;
        assert!(!parents.is_empty());
        assert!(parents.contains(&second_block.id) || parents.contains(&fork_block.id));
    }

    #[tokio::test]
    async fn prune_nodes_below_height() {
        let engine = ShardDagEngine::new(3, 4);
        let first = dummy_block(3, 1, vec![BlockId::zero()]);
        let second = dummy_block(3, 2, vec![first.id]);
        let third = dummy_block(3, 3, vec![second.id]);

        engine.insert_block(first.clone()).await.unwrap();
        engine.insert_block(second.clone()).await.unwrap();
        engine.insert_block(third.clone()).await.unwrap();

        let removed = engine.prune_below(2).await;
        assert!(removed >= 1);
        assert!(!engine.contains(&first.id).await);
    }

    #[tokio::test]
    async fn metrics_snapshot_reflects_state() {
        let engine = ShardDagEngine::new(4, 4);
        let block = dummy_block(4, 1, vec![BlockId::zero()]);
        engine.insert_block(block).await.unwrap();

        let metrics = engine.metrics().await;
        assert_eq!(metrics.total_nodes, 1);
        assert_eq!(metrics.max_height, 1);
    }
}
