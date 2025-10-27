pub mod cross_shard_state;
pub mod merkle_tree;
pub mod persistence;
pub mod state_manager;
pub mod storage;

// Re-export main types from modules, resolving naming conflicts
pub use cross_shard_state::CrossShardStateManager;
pub use merkle_tree::{
    MerkleNode, MerkleProof as MerkleTreeProof, OptimizedMerkleTree,
    StateChange as MerkleTreeStateChange,
};
pub use persistence::ChainState;
pub use state_manager::{StateChange as StateManagerChange, StateManager};
pub use storage::StorageKey;
