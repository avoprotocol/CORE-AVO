//! # MEV Distribution Module
//!
//! Real MEV (Maximal Extractable Value) capture and fair distribution.
//! Tracks transaction ordering value and distributes to validators, delegators, and treasury.

use crate::economics::EconomicParams;
use crate::error::AvoError;
use crate::types::{TokenAmount, TransactionId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MEV capture event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevCaptureEvent {
    pub transaction_id: TransactionId,
    pub block_height: u64,
    pub mev_amount: TokenAmount,
    pub capture_type: MevType,
    pub timestamp: u64,
}

/// Types of MEV
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MevType {
    /// Front-running detected
    Frontrun { victim_tx: TransactionId },
    /// Back-running detected
    Backrun { target_tx: TransactionId },
    /// Sandwich attack detected
    Sandwich {
        victim_tx: TransactionId,
        front_tx: TransactionId,
        back_tx: TransactionId,
    },
    /// Arbitrage opportunity
    Arbitrage { dex_path: Vec<String> },
    /// Liquidation
    Liquidation { protocol: String, position_id: u64 },
    /// Priority ordering value
    PriorityOrdering {
        position: usize,
        premium_paid: TokenAmount,
    },
}

/// MEV distribution breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevDistribution {
    pub total_mev: TokenAmount,
    pub validator_share: TokenAmount,
    pub treasury_share: TokenAmount,
    pub burn_share: TokenAmount,
    pub validator_id: u64,
    pub block_height: u64,
    pub timestamp: u64,
}

/// MEV capture detector
#[derive(Debug)]
pub struct MevCapture {
    /// Pending transactions awaiting ordering
    pending_txs: Vec<PendingTransaction>,
    /// Historical MEV events
    captured_events: Vec<MevCaptureEvent>,
    /// Total MEV captured
    total_captured: TokenAmount,
}

#[derive(Debug, Clone)]
struct PendingTransaction {
    id: TransactionId,
    priority_fee: u128,
    max_fee: u128,
    gas_limit: u64,
    from: [u8; 20],
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
    timestamp: u64,
}

impl MevCapture {
    pub fn new() -> Self {
        Self {
            pending_txs: Vec::new(),
            captured_events: Vec::new(),
            total_captured: 0,
        }
    }

    /// Detect MEV in transaction ordering
    pub fn detect_mev_in_bundle(
        &mut self,
        ordered_txs: Vec<TransactionId>,
        tx_details: &HashMap<TransactionId, (u128, Vec<u8>)>, // (priority_fee, data)
    ) -> Vec<MevCaptureEvent> {
        let mut events = Vec::new();

        // Detect front-running patterns
        for i in 0..ordered_txs.len().saturating_sub(1) {
            let current_tx = ordered_txs[i];
            let next_tx = ordered_txs[i + 1];

            if let (Some((current_fee, current_data)), Some((next_fee, next_data))) =
                (tx_details.get(&current_tx), tx_details.get(&next_tx))
            {
                // Check for suspicious pattern: high fee tx followed by similar tx
                if *current_fee > *next_fee * 2 && data_similarity(current_data, next_data) > 0.7 {
                    let mev_amount = current_fee - next_fee;
                    let event = MevCaptureEvent {
                        transaction_id: current_tx,
                        block_height: 0,
                        mev_amount,
                        capture_type: MevType::Frontrun { victim_tx: next_tx },
                        timestamp: current_timestamp(),
                    };
                    self.total_captured += mev_amount;
                    events.push(event);
                }
            }
        }

        // Detect sandwich attacks (front-run, victim, back-run)
        for i in 0..ordered_txs.len().saturating_sub(2) {
            let front_tx = ordered_txs[i];
            let victim_tx = ordered_txs[i + 1];
            let back_tx = ordered_txs[i + 2];

            if let (
                Some((front_fee, front_data)),
                Some((_victim_fee, victim_data)),
                Some((back_fee, back_data)),
            ) = (
                tx_details.get(&front_tx),
                tx_details.get(&victim_tx),
                tx_details.get(&back_tx),
            ) {
                // Check if front and back txs are related and sandwich victim
                if data_similarity(front_data, back_data) > 0.5
                    && *front_fee > 1_000_000_000
                    && *back_fee > 1_000_000_000
                {
                    // Check if they interact with same contract as victim
                    if extracts_same_contract(front_data, victim_data)
                        && extracts_same_contract(back_data, victim_data)
                    {
                        let mev_amount = front_fee + back_fee;
                        let event = MevCaptureEvent {
                            transaction_id: front_tx,
                            block_height: 0,
                            mev_amount,
                            capture_type: MevType::Sandwich {
                                victim_tx,
                                front_tx,
                                back_tx,
                            },
                            timestamp: current_timestamp(),
                        };
                        self.total_captured += mev_amount;
                        events.push(event);
                    }
                }
            }
        }

        self.captured_events.extend(events.clone());
        events
    }

    /// Calculate MEV from priority ordering
    pub fn calculate_ordering_mev(&self, ordered_txs: &[TransactionId]) -> TokenAmount {
        // MEV from priority fees above base
        let mut total_ordering_mev = 0u128;

        for (position, _tx_id) in ordered_txs.iter().enumerate() {
            // Premium paid for priority position
            let position_premium = if position < 10 {
                // Top 10 positions pay significant premium
                (10 - position) as u128 * 100_000_000_000_000 // 0.0001 tokens per position
            } else {
                0
            };
            total_ordering_mev += position_premium;
        }

        total_ordering_mev
    }

    /// Get total captured MEV
    pub fn total_captured(&self) -> TokenAmount {
        self.total_captured
    }

    /// Get recent MEV events
    pub fn recent_events(&self, count: usize) -> &[MevCaptureEvent] {
        let start = self.captured_events.len().saturating_sub(count);
        &self.captured_events[start..]
    }
}

/// MEV distributor
#[derive(Debug, Clone)]
pub struct MevDistributor {
    params: EconomicParams,
}

impl MevDistributor {
    pub fn new(params: EconomicParams) -> Self {
        Self { params }
    }

    /// Distribute captured MEV
    pub fn distribute_mev(
        &self,
        mev_amount: TokenAmount,
        validator_id: u64,
    ) -> Result<MevDistribution, AvoError> {
        // Treasury share
        let treasury_share = ((mev_amount as f64) * self.params.treasury_mev_share) as TokenAmount;

        // Burn share (optional, can be 0)
        let burn_percentage = 0.1; // 10% burn
        let burn_share = ((mev_amount as f64) * burn_percentage) as TokenAmount;

        // Validator gets the rest
        let validator_share = mev_amount - treasury_share - burn_share;

        Ok(MevDistribution {
            total_mev: mev_amount,
            validator_share,
            treasury_share,
            burn_share,
            validator_id,
            block_height: 0,
            timestamp: current_timestamp(),
        })
    }

    /// Calculate validator MEV earnings for epoch
    pub fn calculate_epoch_mev_earnings(
        &self,
        validator_mev_events: &[MevCaptureEvent],
    ) -> TokenAmount {
        validator_mev_events
            .iter()
            .map(|event| event.mev_amount)
            .sum()
    }

    /// Get MEV distribution statistics
    pub fn calculate_mev_stats(&self, events: &[MevCaptureEvent]) -> MevStatistics {
        if events.is_empty() {
            return MevStatistics::default();
        }

        let total_mev: TokenAmount = events.iter().map(|e| e.mev_amount).sum();
        let avg_mev = total_mev / events.len() as u128;

        let mut type_counts = HashMap::new();
        for event in events {
            let key = mev_type_key(&event.capture_type);
            *type_counts.entry(key).or_insert(0) += 1;
        }

        MevStatistics {
            total_events: events.len(),
            total_mev_captured: total_mev,
            average_mev_per_event: avg_mev,
            mev_by_type: type_counts,
        }
    }
}

/// MEV statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MevStatistics {
    pub total_events: usize,
    pub total_mev_captured: TokenAmount,
    pub average_mev_per_event: TokenAmount,
    pub mev_by_type: HashMap<String, usize>,
}

// Helper functions

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn data_similarity(data1: &[u8], data2: &[u8]) -> f64 {
    if data1.is_empty() || data2.is_empty() {
        return 0.0;
    }

    // Simple similarity: check function selector (first 4 bytes)
    if data1.len() >= 4 && data2.len() >= 4 {
        if data1[0..4] == data2[0..4] {
            return 1.0; // Same function call
        }
    }

    0.0
}

fn extracts_same_contract(data1: &[u8], data2: &[u8]) -> bool {
    // Check if both transactions call same contract
    // In real implementation, would parse calldata for contract addresses
    if data1.len() >= 36 && data2.len() >= 36 {
        // Check for contract address in typical calldata positions
        data1[4..24] == data2[4..24]
    } else {
        false
    }
}

fn mev_type_key(mev_type: &MevType) -> String {
    match mev_type {
        MevType::Frontrun { .. } => "frontrun".to_string(),
        MevType::Backrun { .. } => "backrun".to_string(),
        MevType::Sandwich { .. } => "sandwich".to_string(),
        MevType::Arbitrage { .. } => "arbitrage".to_string(),
        MevType::Liquidation { .. } => "liquidation".to_string(),
        MevType::PriorityOrdering { .. } => "priority_ordering".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_params() -> EconomicParams {
        EconomicParams::default()
    }

    #[test]
    fn test_mev_distribution() {
        let params = default_params();
        let distributor = MevDistributor::new(params.clone());

        let mev_amount = 1_000_000_000_000_000_000u128; // 1 token
        let validator_id = 1;

        let distribution = distributor
            .distribute_mev(mev_amount, validator_id)
            .unwrap();

        assert_eq!(distribution.total_mev, mev_amount);
        assert!(distribution.treasury_share > 0);
        assert!(distribution.validator_share > 0);
        assert_eq!(
            distribution.treasury_share + distribution.validator_share + distribution.burn_share,
            mev_amount
        );
    }

    #[test]
    fn test_mev_capture_initialization() {
        let capture = MevCapture::new();
        assert_eq!(capture.total_captured(), 0);
        assert_eq!(capture.recent_events(10).len(), 0);
    }

    #[test]
    fn test_ordering_mev_calculation() {
        let capture = MevCapture::new();
        let tx_ids: Vec<TransactionId> = (1u64..=5)
            .map(|i| TransactionId::new(&i.to_le_bytes()))
            .collect();
        let mev = capture.calculate_ordering_mev(&tx_ids);

        // Top positions should generate MEV
        assert!(mev > 0);
    }

    #[test]
    fn test_frontrun_detection() {
        let mut capture = MevCapture::new();
        let tx1 = TransactionId::new(&1u64.to_le_bytes());
        let tx2 = TransactionId::new(&2u64.to_le_bytes());

        let mut tx_details = HashMap::new();
        // tx1 pays 10x more but has similar data to tx2
        tx_details.insert(
            tx1,
            (10_000_000_000u128, vec![0xa9, 0x05, 0x9c, 0xbb, 1, 2, 3]),
        );
        tx_details.insert(
            tx2,
            (1_000_000_000u128, vec![0xa9, 0x05, 0x9c, 0xbb, 1, 2, 4]),
        );

        let events = capture.detect_mev_in_bundle(vec![tx1, tx2], &tx_details);

        assert!(!events.is_empty());
        assert!(matches!(events[0].capture_type, MevType::Frontrun { .. }));
    }

    #[test]
    fn test_mev_statistics() {
        let params = default_params();
        let distributor = MevDistributor::new(params);

        let events = vec![
            MevCaptureEvent {
                transaction_id: TransactionId::new(&1u64.to_le_bytes()),
                block_height: 100,
                mev_amount: 1_000_000_000_000_000_000,
                capture_type: MevType::Frontrun {
                    victim_tx: TransactionId::new(&2u64.to_le_bytes()),
                },
                timestamp: 0,
            },
            MevCaptureEvent {
                transaction_id: TransactionId::new(&3u64.to_le_bytes()),
                block_height: 101,
                mev_amount: 2_000_000_000_000_000_000,
                capture_type: MevType::Arbitrage {
                    dex_path: vec!["uniswap".to_string(), "sushiswap".to_string()],
                },
                timestamp: 0,
            },
        ];

        let stats = distributor.calculate_mev_stats(&events);

        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.total_mev_captured, 3_000_000_000_000_000_000);
        assert_eq!(stats.mev_by_type.len(), 2);
    }

    #[test]
    fn test_data_similarity() {
        // Same function selector
        let data1 = vec![0xa9, 0x05, 0x9c, 0xbb, 1, 2, 3];
        let data2 = vec![0xa9, 0x05, 0x9c, 0xbb, 4, 5, 6];
        assert_eq!(data_similarity(&data1, &data2), 1.0);

        // Different function selector
        let data3 = vec![0xaa, 0xbb, 0xcc, 0xdd, 1, 2, 3];
        assert_eq!(data_similarity(&data1, &data3), 0.0);

        // Empty data
        let data4 = vec![];
        assert_eq!(data_similarity(&data1, &data4), 0.0);
    }

    #[test]
    fn test_treasury_share_percentage() {
        let params = default_params();
        let distributor = MevDistributor::new(params.clone());

        let mev_amount = 10_000_000_000_000_000_000u128; // 10 tokens
        let distribution = distributor.distribute_mev(mev_amount, 1).unwrap();

        let expected_treasury = ((mev_amount as f64) * params.treasury_mev_share) as TokenAmount;
        assert_eq!(distribution.treasury_share, expected_treasury);
    }
}
