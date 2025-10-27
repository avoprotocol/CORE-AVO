//! RPC methods for validator reputation system

use super::*;
use crate::staking::reputation::*;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::hash::{Hash, Hasher};

// Global reputation manager with RocksDB persistence
lazy_static::lazy_static! {
    static ref REPUTATION_MANAGER: Arc<RwLock<ReputationManager>> = {
        // Use a dedicated path for reputation data
        let db_path = "avo_data/reputation_db";
        Arc::new(RwLock::new(ReputationManager::with_db(db_path)))
    };
}

impl RpcMethods {
    /// Get reputation for a specific validator
    /// 
    /// Params: [validator_id_or_address]
    /// Returns: ValidatorReputation object with score and metrics
    #[allow(non_snake_case)]
    pub async fn avo_getValidatorReputation(&self, params: Option<Value>) -> Result<Value, RpcError> {
        let params_array = params
            .and_then(|p| p.as_array().cloned())
            .ok_or_else(|| RpcError {
                code: -32602,
                message: "Invalid params: expected [validator_id_or_address]".to_string(),
                data: None,
            })?;

        if params_array.is_empty() {
            return Err(RpcError {
                code: -32602,
                message: "Missing validator_id or address parameter".to_string(),
                data: None,
            });
        }

        // Try to parse as u64 (validator_id) or string (address)
        let validator_id = if let Some(id) = params_array[0].as_u64() {
            id
        } else if let Some(address) = params_array[0].as_str() {
            // Hash the address to get a consistent validator_id
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(&address, &mut hasher);
            std::hash::Hasher::finish(&hasher)
        } else {
            return Err(RpcError {
                code: -32602,
                message: "validator_id must be a number or address must be a string".to_string(),
                data: None,
            });
        };

        let reputation_mgr = REPUTATION_MANAGER.read().await;

        match reputation_mgr.get_reputation(validator_id) {
            Some(reputation) => {
                // Convert to JSON with star display
                let stars = "⭐".repeat(reputation.score.round() as usize);
                let tier = ReputationManager::get_reputation_tier(reputation.score);

                Ok(json!({
                    "validator_id": reputation.validator_id,
                    "score": format!("{:.2}", reputation.score),
                    "score_numeric": reputation.score,
                    "stars": stars,
                    "tier": tier,
                    "metrics": {
                        "uptime": format!("{:.1}%", reputation.metrics.uptime_score * 100.0),
                        "slashing": format!("{:.1}%", reputation.metrics.slashing_score * 100.0),
                        "performance": format!("{:.1}%", reputation.metrics.performance_score * 100.0),
                        "attestation": format!("{:.1}%", reputation.metrics.attestation_score * 100.0),
                        "participation": format!("{:.1}%", reputation.metrics.participation_score * 100.0),
                        "longevity": format!("{:.1}%", reputation.metrics.longevity_score * 100.0)
                    },
                    "history": {
                        "total_epochs": reputation.history.total_epochs,
                        "blocks_produced": reputation.history.total_blocks_produced,
                        "blocks_missed": reputation.history.total_blocks_missed,
                        "slashing_events": reputation.history.total_slashing_events,
                        "downtime_incidents": reputation.history.total_downtime_incidents,
                        "registration_time": reputation.history.registration_time,
                        "total_online_time": reputation.history.total_online_time,
                        "total_expected_time": reputation.history.total_expected_time,
                        "uptime_percentage": if reputation.history.total_expected_time > 0 {
                            format!("{:.2}%", (reputation.history.total_online_time as f64 / reputation.history.total_expected_time as f64) * 100.0)
                        } else {
                            "N/A".to_string()
                        }
                    },
                    "last_updated": reputation.last_updated
                }))
            }
            None => Err(RpcError {
                code: -32000,
                message: format!("Validator {} not found in reputation system", validator_id),
                data: None,
            }),
        }
    }

    /// Get top validators by reputation score
    /// 
    /// Params: [limit] (optional, default: 10)
    /// Returns: Array of ValidatorReputation objects sorted by score
    #[allow(non_snake_case)]
    pub async fn avo_getTopValidators(&self, params: Option<Value>) -> Result<Value, RpcError> {
        let limit = params
            .and_then(|p| p.as_array().cloned())
            .and_then(|arr| arr.get(0).and_then(|v| v.as_u64()))
            .unwrap_or(10) as usize;

        let reputation_mgr = REPUTATION_MANAGER.read().await;
        let top_validators = reputation_mgr.get_top_validators(limit);

        let validators_json: Vec<Value> = top_validators
            .iter()
            .enumerate()
            .map(|(rank, rep)| {
                let stars = "⭐".repeat(rep.score.round() as usize);
                let tier = ReputationManager::get_reputation_tier(rep.score);

                json!({
                    "rank": rank + 1,
                    "validator_id": rep.validator_id,
                    "score": format!("{:.2}", rep.score),
                    "score_numeric": rep.score,
                    "stars": stars,
                    "tier": tier,
                    "uptime_percentage": if rep.history.total_expected_time > 0 {
                        format!("{:.2}%", (rep.history.total_online_time as f64 / rep.history.total_expected_time as f64) * 100.0)
                    } else {
                        "N/A".to_string()
                    },
                    "blocks_produced": rep.history.total_blocks_produced,
                    "slashing_events": rep.history.total_slashing_events
                })
            })
            .collect();

        Ok(json!({
            "top_validators": validators_json,
            "total_count": reputation_mgr.get_total_validators()
        }))
    }

    /// Get reputation statistics for all validators
    /// 
    /// Returns: Overall reputation statistics
    #[allow(non_snake_case)]
    pub async fn avo_getReputationStats(&self, _params: Option<Value>) -> Result<Value, RpcError> {
        let reputation_mgr = REPUTATION_MANAGER.read().await;

        let all_scores: Vec<f64> = reputation_mgr
            .get_all_reputations()
            .iter()
            .map(|r| r.score)
            .collect();

        if all_scores.is_empty() {
            return Ok(json!({
                "total_validators": 0,
                "average_score": "N/A",
                "highest_score": "N/A",
                "lowest_score": "N/A",
                "tier_distribution": {
                    "legendary": 0,
                    "excellent": 0,
                    "good": 0,
                    "fair": 0,
                    "poor": 0
                }
            }));
        }

        let average_score = all_scores.iter().sum::<f64>() / all_scores.len() as f64;
        let highest_score = all_scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let lowest_score = all_scores.iter().cloned().fold(f64::INFINITY, f64::min);

        // Count validators in each tier
        let mut tier_counts = (0u32, 0u32, 0u32, 0u32, 0u32); // (legendary, excellent, good, fair, poor)
        for score in &all_scores {
            match *score {
                s if s >= 4.8 => tier_counts.0 += 1,
                s if s >= 4.0 => tier_counts.1 += 1,
                s if s >= 3.0 => tier_counts.2 += 1,
                s if s >= 2.0 => tier_counts.3 += 1,
                _ => tier_counts.4 += 1,
            }
        }

        Ok(json!({
            "total_validators": all_scores.len(),
            "average_score": format!("{:.2}", average_score),
            "average_score_numeric": average_score,
            "highest_score": format!("{:.2}", highest_score),
            "lowest_score": format!("{:.2}", lowest_score),
            "tier_distribution": {
                "legendary": tier_counts.0,
                "excellent": tier_counts.1,
                "good": tier_counts.2,
                "fair": tier_counts.3,
                "poor": tier_counts.4
            }
        }))
    }
}

/// Initialize reputation for a new validator (public function)
pub async fn initialize_validator_reputation(validator_id: u64) {
    let mut reputation_mgr = REPUTATION_MANAGER.write().await;
    reputation_mgr.initialize_validator(validator_id);
}

/// Update reputation after epoch (public function)
pub async fn update_validator_reputation(
    validator_id: u64,
    blocks_produced: u64,
    blocks_missed: u64,
    online_time: u64,
    expected_time: u64,
) {
    let mut reputation_mgr = REPUTATION_MANAGER.write().await;
    reputation_mgr.update_reputation(
        validator_id,
        blocks_produced,
        blocks_missed,
        online_time,
        expected_time,
    );
}

/// Record slashing event (public function)
pub async fn record_validator_slashing(
    validator_id: u64,
    severity: SlashingSeverity,
) {
    let mut reputation_mgr = REPUTATION_MANAGER.write().await;
    reputation_mgr.record_slashing(validator_id, severity);
}

impl RpcMethods {
    /// Initialize reputation for a validator (RPC method)
    /// 
    /// Params: [validator_address]
    /// Returns: success message
    #[allow(non_snake_case)]
    pub async fn avo_initializeValidatorReputation(&self, params: Option<Value>) -> Result<Value, RpcError> {
        let params_array = params
            .and_then(|p| p.as_array().cloned())
            .ok_or_else(|| RpcError {
                code: -32602,
                message: "Invalid params: expected [validator_address]".to_string(),
                data: None,
            })?;

        if params_array.is_empty() {
            return Err(RpcError {
                code: -32602,
                message: "Missing validator_address parameter".to_string(),
                data: None,
            });
        }

        let address = params_array[0]
            .as_str()
            .ok_or_else(|| RpcError {
                code: -32602,
                message: "validator_address must be a string".to_string(),
                data: None,
            })?;

        // Hash the address to get a consistent validator_id
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        address.hash(&mut hasher);
        let validator_id = hasher.finish();

        let mut reputation_mgr = REPUTATION_MANAGER.write().await;
        reputation_mgr.initialize_validator(validator_id);

        Ok(json!({
            "success": true,
            "validator_id": validator_id,
            "address": address,
            "message": format!("Reputation initialized for validator {}", address)
        }))
    }
}

