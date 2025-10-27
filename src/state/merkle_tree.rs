use crate::error::AvoError;
use crate::types::{AccountId, Hash, TransactionId};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Merkle tree node for state verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MerkleNode {
    pub hash: Hash,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
    pub data: Option<Vec<u8>>,
    pub level: u32,
}

impl MerkleNode {
    /// Create a new leaf node
    pub fn new_leaf(data: Vec<u8>) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        let hash = hasher.finalize().into();

        Self {
            hash,
            left: None,
            right: None,
            data: Some(data),
            level: 0,
        }
    }

    /// Create a new internal node
    pub fn new_internal(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(left.hash);
        hasher.update(right.hash);
        let hash = hasher.finalize().into();

        // Store levels before moving the nodes
        let left_level = left.level;
        let right_level = right.level;

        Self {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            data: None,
            level: std::cmp::max(left_level, right_level) + 1,
        }
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }
}

/// Merkle proof for state verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_hash: Hash,
    pub siblings: Vec<Hash>,
    pub root_hash: Hash,
}

impl MerkleProof {
    /// Verify this proof against a root hash
    pub fn verify(&self, root_hash: &Hash) -> bool {
        if &self.root_hash != root_hash {
            return false;
        }

        let mut current_hash = self.leaf_hash;
        let mut index = self.leaf_index;

        for sibling in &self.siblings {
            let mut hasher = Sha3_256::new();

            if index % 2 == 0 {
                // Current node is left child
                hasher.update(current_hash);
                hasher.update(sibling);
            } else {
                // Current node is right child
                hasher.update(sibling);
                hasher.update(current_hash);
            }

            current_hash = hasher.finalize().into();
            index /= 2;
        }

        current_hash == *root_hash
    }
}

/// State change entry for incremental updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub account_id: AccountId,
    pub field: String,
    pub old_value: Option<Vec<u8>>,
    pub new_value: Vec<u8>,
    pub timestamp: u64,
    pub transaction_id: TransactionId,
}

/// Optimized Merkle tree for blockchain state
#[derive(Debug)]
pub struct OptimizedMerkleTree {
    /// Root node of the tree
    root: Arc<RwLock<Option<MerkleNode>>>,
    /// Leaf nodes for fast access
    leaves: Arc<RwLock<Vec<MerkleNode>>>,
    /// Hash to index mapping for O(1) lookups
    hash_to_index: Arc<RwLock<HashMap<Hash, usize>>>,
    /// Cached proofs for recently accessed leaves
    proof_cache: Arc<RwLock<HashMap<usize, MerkleProof>>>,
    /// Tree depth for optimization
    depth: Arc<RwLock<u32>>,
    /// Incremental update buffer
    pending_changes: Arc<RwLock<Vec<StateChange>>>,
}

impl OptimizedMerkleTree {
    /// Create a new empty Merkle tree
    pub fn new() -> Self {
        Self {
            root: Arc::new(RwLock::new(None)),
            leaves: Arc::new(RwLock::new(Vec::new())),
            hash_to_index: Arc::new(RwLock::new(HashMap::new())),
            proof_cache: Arc::new(RwLock::new(HashMap::new())),
            depth: Arc::new(RwLock::new(0)),
            pending_changes: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Build tree from initial data set
    pub async fn build_from_data(&self, data: Vec<Vec<u8>>) -> Result<(), AvoError> {
        // Building Merkle tree

        if data.is_empty() {
            return Ok(());
        }

        // Create leaf nodes
        let mut leaves = Vec::new();
        let mut hash_to_index = HashMap::new();

        for (index, item) in data.into_iter().enumerate() {
            let leaf = MerkleNode::new_leaf(item);
            hash_to_index.insert(leaf.hash, index);
            leaves.push(leaf);
        }

        // Build tree bottom-up
        let root = self.build_tree_recursive(&leaves).await?;

        // Update state
        {
            let mut tree_root = self.root.write().await;
            *tree_root = Some(root);
        }

        let leaves_len = leaves.len();

        {
            let mut tree_leaves = self.leaves.write().await;
            *tree_leaves = leaves;
        }

        {
            let mut tree_hash_map = self.hash_to_index.write().await;
            *tree_hash_map = hash_to_index;
        }

        {
            let mut tree_depth = self.depth.write().await;
            *tree_depth = (leaves_len as f64).log2().ceil() as u32;
        }

        // Merkle tree built successfully
        Ok(())
    }

    /// Recursively build tree from leaf nodes
    async fn build_tree_recursive(&self, nodes: &[MerkleNode]) -> Result<MerkleNode, AvoError> {
        if nodes.is_empty() {
            return Err(AvoError::InvalidInput(
                "Cannot build tree from empty nodes".to_string(),
            ));
        }

        if nodes.len() == 1 {
            return Ok(nodes[0].clone());
        }

        let mut next_level = Vec::new();

        // Pair up nodes for the next level
        for chunk in nodes.chunks(2) {
            if chunk.len() == 2 {
                let internal = MerkleNode::new_internal(chunk[0].clone(), chunk[1].clone());
                next_level.push(internal);
            } else {
                // Odd number of nodes, duplicate the last one
                let internal = MerkleNode::new_internal(chunk[0].clone(), chunk[0].clone());
                next_level.push(internal);
            }
        }

        Box::pin(self.build_tree_recursive(&next_level)).await
    }

    /// Get the root hash of the tree
    pub async fn get_root_hash(&self) -> Option<Hash> {
        let root = self.root.read().await;
        root.as_ref().map(|node| node.hash)
    }

    /// Generate proof for a specific leaf
    pub async fn generate_proof(&self, leaf_index: usize) -> Result<MerkleProof, AvoError> {
        // Check cache first
        {
            let cache = self.proof_cache.read().await;
            if let Some(cached_proof) = cache.get(&leaf_index) {
                return Ok(cached_proof.clone());
            }
        }

        let leaves = self.leaves.read().await;
        if leaf_index >= leaves.len() {
            return Err(AvoError::InvalidInput(format!(
                "Leaf index {} out of bounds",
                leaf_index
            )));
        }

        let leaf_hash = leaves[leaf_index].hash;
        let root_hash = self
            .get_root_hash()
            .await
            .ok_or_else(|| AvoError::InvalidInput("Tree is empty".to_string()))?;

        // Generate siblings path
        let siblings = self.generate_siblings_path(&leaves, leaf_index).await?;

        let proof = MerkleProof {
            leaf_index,
            leaf_hash,
            siblings,
            root_hash,
        };

        // Cache the proof
        {
            let mut cache = self.proof_cache.write().await;
            cache.insert(leaf_index, proof.clone());
        }

        Ok(proof)
    }

    /// Generate siblings path for proof generation
    async fn generate_siblings_path(
        &self,
        leaves: &[MerkleNode],
        mut index: usize,
    ) -> Result<Vec<Hash>, AvoError> {
        let mut siblings = Vec::new();
        let mut current_level: Vec<_> = leaves.to_vec();

        while current_level.len() > 1 {
            // Find sibling at current level
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };

            if sibling_index < current_level.len() {
                siblings.push(current_level[sibling_index].hash);
            } else {
                // Duplicate node case
                siblings.push(current_level[index].hash);
            }

            // Build next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let internal = MerkleNode::new_internal(chunk[0].clone(), chunk[1].clone());
                    next_level.push(internal);
                } else {
                    let internal = MerkleNode::new_internal(chunk[0].clone(), chunk[0].clone());
                    next_level.push(internal);
                }
            }

            current_level = next_level;
            index /= 2;
        }

        Ok(siblings)
    }

    /// Verify a proof against current tree state
    pub async fn verify_proof(&self, proof: &MerkleProof) -> Result<bool, AvoError> {
        let root_hash = self
            .get_root_hash()
            .await
            .ok_or_else(|| AvoError::InvalidInput("Tree is empty".to_string()))?;

        Ok(proof.verify(&root_hash))
    }

    /// Add incremental state change
    pub async fn add_state_change(&self, change: StateChange) -> Result<(), AvoError> {
        let mut pending = self.pending_changes.write().await;
        pending.push(change);

        // Added state change
        Ok(())
    }

    /// Apply pending changes and rebuild affected parts
    pub async fn apply_pending_changes(&self) -> Result<Hash, AvoError> {
        let changes = {
            let mut pending = self.pending_changes.write().await;
            let changes = pending.clone();
            pending.clear();
            changes
        };

        if changes.is_empty() {
            return self
                .get_root_hash()
                .await
                .ok_or_else(|| AvoError::InvalidInput("No root hash available".to_string()));
        }

        // Applying pending state changes

        // For demo, we'll rebuild the entire tree
        // In production, this would be an incremental update
        let mut leaves = self.leaves.read().await.clone();

        // Apply changes to leaf data
        for change in changes {
            // Update leaf with new data
            let new_leaf = MerkleNode::new_leaf(change.new_value);
            if let Some(index) = self.find_account_leaf_index(&change.account_id).await {
                if index < leaves.len() {
                    leaves[index] = new_leaf;
                }
            } else {
                // Add new leaf
                leaves.push(new_leaf);
            }
        }

        // Rebuild tree
        let root = self.build_tree_recursive(&leaves).await?;
        let new_root_hash = root.hash;

        // Update state
        {
            let mut tree_root = self.root.write().await;
            *tree_root = Some(root);
        }

        {
            let mut tree_leaves = self.leaves.write().await;
            *tree_leaves = leaves;
        }

        // Clear proof cache since tree structure changed
        {
            let mut cache = self.proof_cache.write().await;
            cache.clear();
        }

        // Applied state changes
        Ok(new_root_hash)
    }

    /// Find leaf index for a specific account
    async fn find_account_leaf_index(&self, _account_id: &AccountId) -> Option<usize> {
        // For demo purposes, return None
        // In production, this would maintain an account -> leaf mapping
        None
    }

    /// Get tree statistics
    pub async fn get_stats(&self) -> TreeStats {
        let leaves = self.leaves.read().await;
        let depth = self.depth.read().await;
        let pending = self.pending_changes.read().await;
        let cache = self.proof_cache.read().await;

        TreeStats {
            leaf_count: leaves.len(),
            depth: *depth,
            pending_changes: pending.len(),
            cached_proofs: cache.len(),
            has_root: self.root.read().await.is_some(),
        }
    }

    /// Clear all cached data
    pub async fn clear_cache(&self) {
        let mut cache = self.proof_cache.write().await;
        cache.clear();
        println!("🧹 Cleared proof cache");
    }
}

/// Tree statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeStats {
    pub leaf_count: usize,
    pub depth: u32,
    pub pending_changes: usize,
    pub cached_proofs: usize,
    pub has_root: bool,
}

impl Default for OptimizedMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch proof verification for multiple leaves
pub async fn verify_batch_proofs(
    proofs: &[MerkleProof],
    root_hash: &Hash,
) -> Result<Vec<bool>, AvoError> {
    let results = proofs.iter().map(|proof| proof.verify(root_hash)).collect();

    Ok(results)
}

/// Generate merkle root from leaf hashes
pub fn calculate_merkle_root(mut leaf_hashes: Vec<Hash>) -> Option<Hash> {
    if leaf_hashes.is_empty() {
        return None;
    }

    while leaf_hashes.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in leaf_hashes.chunks(2) {
            let mut hasher = Sha3_256::new();
            hasher.update(chunk[0]);

            if chunk.len() == 2 {
                hasher.update(chunk[1]);
            } else {
                hasher.update(chunk[0]); // Duplicate for odd count
            }

            next_level.push(hasher.finalize().into());
        }

        leaf_hashes = next_level;
    }

    leaf_hashes.into_iter().next()
}
