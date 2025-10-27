pub mod batch_processing;
pub mod dag_algorithms;
pub mod distributed_consensus;
pub mod dynamic_resharding; // FASE 12.3: Dynamic resharding with MMR
pub mod finality;
pub mod flow_consensus;
#[cfg(test)]
pub mod flow_consensus_tests;
pub mod hybrid_clock;
pub mod inter_shard;
pub mod intra_shard;
pub mod l1_checkpoint; // FASE 12.2: L1 checkpointing to Ethereum
pub mod leader_election; // FASE 10.2: VRF-based leader election
pub mod resilience;
pub mod shard_dag_engine;
pub mod threshold_2pc; // FASE 11.2: Threshold encryption for 2PC

#[cfg(test)]
pub mod flow_consensus_basic_tests;

#[cfg(test)]
pub mod flow_consensus_benchmarks;

#[cfg(test)]
pub mod flow_consensus_profiling;

// Re-export key types for Phase 4B
pub use batch_processing::{BatchProcessingConfig, BatchProcessingMetrics, BatchProcessor};
pub use distributed_consensus::{
    ConsensusMessage, ConsensusState, DistributedConsensus, DistributedMetrics, NodeStatus, Vote,
};

pub use dag_algorithms::{BlockDAG, DAGNode, DAGStatistics, TransactionDAG, DAG};
pub use dynamic_resharding::{
    DynamicReshardingManager, MerkleTree, MigrationPlan, MigrationProgress, ReshardingConfig,
    ReshardingOperation, ReshardingState, ReshardingStatistics, ShardLoadMetrics,
};
pub use finality::FinalityEngine;
pub use flow_consensus::FlowConsensus;
pub use hybrid_clock::{HlcTimestamp, HybridLogicalClock, PartitionStatus}; // FASE 12.1: Partition detection
pub use inter_shard::InterShardConsensus;
pub use intra_shard::IntraShardConsensus;
pub use l1_checkpoint::{
    CheckpointChallenge, CheckpointStatus as L1CheckpointStatus, L1Checkpoint, L1CheckpointConfig,
    L1CheckpointManager, L1CheckpointStatistics,
};
pub use leader_election::{LeaderElection, LeaderElectionResult, VrfSortition};
pub use resilience::{
    CheckpointManager, CheckpointRecord, CheckpointStatus as ResilientCheckpointStatus, ExitProof,
    PartitionEvent, PartitionMonitor, PartitionThresholds, ReshardingCoordinator,
    ReshardingOutcome,
};
pub use shard_dag_engine::{ShardDagEngine, ShardDagMetrics};
pub use threshold_2pc::{
    CrossShardDecryptionShare, EncryptedCrossShardTx, Threshold2PCConfig, Threshold2PCManager,
    Threshold2PCState, Threshold2PCStatistics,
};
