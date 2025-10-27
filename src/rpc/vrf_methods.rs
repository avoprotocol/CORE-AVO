/// RPC methods for VRF and leader election
/// FASE 10.2: Expose VRF proofs via RPC
use crate::consensus::leader_election::LeaderElectionResult;
use crate::crypto::vrf::VrfProof;
use crate::error::AvoResult;
use crate::types::{Epoch, ShardId, ValidatorId};
use serde::{Deserialize, Serialize};

/// RPC response for block proposer query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposerResponse {
    pub epoch: Epoch,
    pub shard_id: ShardId,
    pub proposer_id: ValidatorId,
    pub vrf_output: Vec<u8>,
    pub vrf_proof: VrfProofRpc,
    pub timestamp: u64,
}

/// VRF proof for RPC serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfProofRpc {
    pub output: Vec<u8>,
    pub proof: Vec<u8>,
    pub input: Vec<u8>,
}

impl From<&LeaderElectionResult> for BlockProposerResponse {
    fn from(result: &LeaderElectionResult) -> Self {
        Self {
            epoch: result.epoch,
            shard_id: result.shard_id,
            proposer_id: result.proposer_id,
            vrf_output: result.vrf_output.randomness.to_vec(),
            vrf_proof: VrfProofRpc {
                output: result.vrf_output.proof.output.clone(),
                proof: result.vrf_output.proof.proof.clone(),
                input: result.vrf_output.proof.input.clone(),
            },
            timestamp: result.timestamp,
        }
    }
}

impl From<&VrfProof> for VrfProofRpc {
    fn from(proof: &VrfProof) -> Self {
        Self {
            output: proof.output.clone(),
            proof: proof.proof.clone(),
            input: proof.input.clone(),
        }
    }
}

/// RPC request for verifying VRF proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyVrfProofRequest {
    pub epoch: Epoch,
    pub shard_id: ShardId,
    pub proposer_id: ValidatorId,
    pub vrf_proof: VrfProofRpc,
}

/// RPC response for VRF verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyVrfProofResponse {
    pub is_valid: bool,
    pub reason: Option<String>,
}

/// RPC methods implementation
pub struct VrfRpcMethods;

impl VrfRpcMethods {
    /// Get block proposer for specific epoch and shard
    pub fn get_block_proposer(epoch: Epoch, shard_id: ShardId) -> AvoResult<BlockProposerResponse> {
        // This would query the actual LeaderElection instance
        // For now, we return a placeholder that indicates the system is ready
        Err(crate::error::AvoError::NotFound(
            "Leader election result not found".to_string(),
        ))
    }

    /// Verify a VRF proof
    pub fn verify_vrf_proof(request: VerifyVrfProofRequest) -> AvoResult<VerifyVrfProofResponse> {
        // This would use the actual VRF verification logic
        // For now, return a basic response
        Ok(VerifyVrfProofResponse {
            is_valid: false,
            reason: Some("VRF verification not yet implemented".to_string()),
        })
    }

    /// Get current epoch's proposer
    pub fn get_current_proposer(shard_id: ShardId) -> AvoResult<BlockProposerResponse> {
        // This would query current epoch
        Err(crate::error::AvoError::NotFound(
            "Current proposer not found".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrf_proof_serialization() {
        let proof_rpc = VrfProofRpc {
            output: vec![1, 2, 3],
            proof: vec![4, 5, 6],
            input: vec![7, 8, 9],
        };

        let json = serde_json::to_string(&proof_rpc).unwrap();
        let deserialized: VrfProofRpc = serde_json::from_str(&json).unwrap();

        assert_eq!(proof_rpc.output, deserialized.output);
        assert_eq!(proof_rpc.proof, deserialized.proof);
        assert_eq!(proof_rpc.input, deserialized.input);
    }
}
