use crate::crypto::{
    constraint_batching::{get_optimization_metrics, ConstraintOptimizationMetrics},
    hardware_acceleration::{get_acceleration_metrics, HardwareAccelerationMetrics},
    plonk_implementation::{get_plonk_metrics, PlonkImplementationMetrics},
    recursive_proofs::{get_proof_aggregation_metrics, RecursiveProofMetrics},
    zk_vm::{get_vm_performance_metrics, ZkVmMetrics},
};
use crate::types::Block;
use std::fmt;

/// ANSI color codes for terminal output
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";

    // Text colors
    pub const BLACK: &str = "\x1b[30m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";

    // Bright colors
    pub const BRIGHT_RED: &str = "\x1b[91m";
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_BLUE: &str = "\x1b[94m";
    pub const BRIGHT_MAGENTA: &str = "\x1b[95m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const BRIGHT_WHITE: &str = "\x1b[97m";

    // Background colors
    pub const BG_BLACK: &str = "\x1b[40m";
    pub const BG_RED: &str = "\x1b[41m";
    pub const BG_GREEN: &str = "\x1b[42m";
    pub const BG_YELLOW: &str = "\x1b[43m";
    pub const BG_BLUE: &str = "\x1b[44m";
    pub const BG_MAGENTA: &str = "\x1b[45m";
    pub const BG_CYAN: &str = "\x1b[46m";
    pub const BG_WHITE: &str = "\x1b[47m";
}

/// Box drawing characters for UI frames
pub mod box_chars {
    pub const DOUBLE_TOP_LEFT: &str = "╔";
    pub const DOUBLE_TOP_RIGHT: &str = "╗";
    pub const DOUBLE_BOTTOM_LEFT: &str = "╚";
    pub const DOUBLE_BOTTOM_RIGHT: &str = "╝";
    pub const DOUBLE_HORIZONTAL: &str = "═";
    pub const DOUBLE_VERTICAL: &str = "║";
    pub const DOUBLE_CROSS: &str = "╬";
    pub const DOUBLE_TEE_DOWN: &str = "╦";
    pub const DOUBLE_TEE_UP: &str = "╩";
    pub const DOUBLE_TEE_RIGHT: &str = "╠";
    pub const DOUBLE_TEE_LEFT: &str = "╣";
}

/// Epoch display information
#[derive(Debug, Clone)]
pub struct EpochDisplay {
    pub epoch: u64,
    pub consensus_type: String,
    pub active_shards: u32,
    pub block_hash: String,
    pub avg_time_ms: f64,
    pub finality_time_ms: f64,
}

/// Extended status information for periodic display
#[derive(Debug, Clone)]
pub struct ProtocolStatus {
    pub epoch: u64,
    pub consensus_efficiency: f64,
    pub active_shards: u32,
    pub active_validators: u32,
    pub last_block_hash: String,
    pub last_block_size_kb: u64,
    pub finality_time_ms: f64,
    pub zk_constraint_reduction: f64,
    pub zk_compression_ratio: f64,
    pub zk_proof_generation_ms: f64,
    pub validator_count: u32,
    pub bootstrap_count: u32,
    pub delegated_avo: f64,
    pub network_stake_percentage: f64,
}

/// Combined ZK metrics from all optimization modules
#[derive(Debug, Clone)]
pub struct CombinedZkMetrics {
    pub constraint_reduction_percentage: f64,
    pub compression_ratio: f64,
    pub proof_generation_ms: u64,
    pub verification_ms: u64,
    pub speedup_factor: f64,
}

impl EpochDisplay {
    /// Create a compact single-line display for each epoch
    pub fn format_compact(&self) -> String {
        let epoch_section = format!(
            "{}{}EPOCH {}{}",
            colors::BOLD,
            colors::BRIGHT_CYAN,
            self.epoch,
            colors::RESET
        );

        let consensus_section = format!(
            "{}{}FlowConsensus{}",
            colors::BOLD,
            colors::BRIGHT_GREEN,
            colors::RESET
        );

        let shards_section = format!(
            "{}{} Shards{}",
            colors::BRIGHT_YELLOW,
            self.active_shards,
            colors::RESET
        );

        let block_section = format!(
            "{}Block: {}{}",
            colors::BRIGHT_BLUE,
            &self.block_hash[..12],
            colors::RESET
        );

        let time_section = format!(
            "{}{}ms avg{}",
            colors::BRIGHT_MAGENTA,
            self.avg_time_ms,
            colors::RESET
        );

        let content = format!(
            "{} | {} | {} | {} | {}",
            epoch_section, consensus_section, shards_section, block_section, time_section
        );

        format!(
            "{}{}{}\n{} {} {}\n{}{}{}",
            box_chars::DOUBLE_TOP_LEFT,
            box_chars::DOUBLE_HORIZONTAL.repeat(79),
            box_chars::DOUBLE_TOP_RIGHT,
            box_chars::DOUBLE_VERTICAL,
            content,
            box_chars::DOUBLE_VERTICAL,
            box_chars::DOUBLE_BOTTOM_LEFT,
            box_chars::DOUBLE_HORIZONTAL.repeat(79),
            box_chars::DOUBLE_BOTTOM_RIGHT
        )
    }
}

impl ProtocolStatus {
    /// Create an extended multi-line display for periodic status updates
    pub fn format_extended(&self) -> String {
        // Simple box with all information
        format!(
            "{}{}{}
{} AVO PROTOCOL STATUS - EPOCH {} {}
{}{}{}
{} CONSENSUS: FlowConsensus | {} Shards | {} Validators | {}% Efficiency {}
{} BLOCKS: Last {} | Finalized | {}s Finality | {}KB Size {}
{} ZK OPTIM: {}% Constraint Reduction | {}x Compression | {}ms Generation {}
{} STAKING: {} Validators | {} Bootstrap | {} AVO | {}% Network {}
{}{}{}",
            box_chars::DOUBLE_TOP_LEFT,
            box_chars::DOUBLE_HORIZONTAL.repeat(82),
            box_chars::DOUBLE_TOP_RIGHT,
            box_chars::DOUBLE_VERTICAL,
            self.epoch,
            box_chars::DOUBLE_VERTICAL,
            box_chars::DOUBLE_TEE_RIGHT,
            box_chars::DOUBLE_HORIZONTAL.repeat(82),
            box_chars::DOUBLE_TEE_LEFT,
            box_chars::DOUBLE_VERTICAL,
            self.active_shards,
            self.active_validators,
            self.consensus_efficiency,
            box_chars::DOUBLE_VERTICAL,
            box_chars::DOUBLE_VERTICAL,
            &self.last_block_hash[..16],
            self.finality_time_ms / 1000.0,
            self.last_block_size_kb,
            box_chars::DOUBLE_VERTICAL,
            box_chars::DOUBLE_VERTICAL,
            self.zk_constraint_reduction,
            self.zk_compression_ratio,
            self.zk_proof_generation_ms,
            box_chars::DOUBLE_VERTICAL,
            box_chars::DOUBLE_VERTICAL,
            self.validator_count,
            self.bootstrap_count,
            self.delegated_avo,
            self.network_stake_percentage,
            box_chars::DOUBLE_VERTICAL,
            box_chars::DOUBLE_BOTTOM_LEFT,
            box_chars::DOUBLE_HORIZONTAL.repeat(82),
            box_chars::DOUBLE_BOTTOM_RIGHT
        )
    }
}

/// Console display manager for AVO Protocol
pub struct ConsoleDisplay;

impl ConsoleDisplay {
    /// Display epoch information in compact format
    pub fn show_epoch_compact(epoch_info: &EpochDisplay) {
        println!("{}", epoch_info.format_compact());
    }

    /// Display extended protocol status
    pub fn show_protocol_status(status: &ProtocolStatus) {
        println!("{}", status.format_extended());
    }

    /// Create epoch display from basic parameters
    pub fn create_epoch_display(
        epoch: u64,
        active_shards: u32,
        block_hash: &str,
        avg_time_ms: f64,
        finality_time_ms: f64,
    ) -> EpochDisplay {
        EpochDisplay {
            epoch,
            consensus_type: "FlowConsensus".to_string(),
            active_shards,
            block_hash: block_hash.to_string(),
            avg_time_ms,
            finality_time_ms,
        }
    }

    /// Get real ZK metrics from all optimization modules
    pub fn get_real_zk_metrics() -> CombinedZkMetrics {
        let constraint_metrics = get_optimization_metrics();
        let recursive_metrics = get_proof_aggregation_metrics();
        let hardware_metrics = get_acceleration_metrics();
        let vm_metrics = get_vm_performance_metrics();
        let plonk_metrics = get_plonk_metrics();

        CombinedZkMetrics {
            constraint_reduction_percentage: constraint_metrics.reduction_percentage,
            compression_ratio: recursive_metrics.compression_ratio,
            proof_generation_ms: plonk_metrics.proof_gen_time_ms,
            verification_ms: plonk_metrics.verification_time_ms,
            speedup_factor: hardware_metrics.speedup_factor,
        }
    }

    /// Create protocol status from consensus state and metrics
    pub async fn create_protocol_status(
        epoch: u64,
        active_shards: u32,
        active_validators: u32,
        last_block: &Block,
        finality_time_ms: f64,
        consensus_efficiency: f64,
    ) -> ProtocolStatus {
        // Get real ZK metrics
        let zk_metrics = Self::get_real_zk_metrics();

        // Calculate block size from transactions
        let block_size_bytes = bincode::serialize(last_block).unwrap_or_default().len();

        ProtocolStatus {
            epoch,
            consensus_efficiency,
            active_shards,
            active_validators,
            last_block_hash: hex::encode(&last_block.id.0[..]),
            last_block_size_kb: (block_size_bytes as u64) / 1024,
            finality_time_ms,
            zk_constraint_reduction: zk_metrics.constraint_reduction_percentage,
            zk_compression_ratio: zk_metrics.compression_ratio,
            zk_proof_generation_ms: zk_metrics.proof_generation_ms as f64,
            validator_count: active_validators,
            bootstrap_count: 12,   // Placeholder - should come from network state
            delegated_avo: 5200.0, // Placeholder - should come from staking
            network_stake_percentage: 5.65, // Placeholder - should come from governance
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_display_formatting() {
        let epoch_display = EpochDisplay {
            epoch: 98,
            consensus_type: "FlowConsensus".to_string(),
            active_shards: 4,
            block_hash: "15a51baa83faf77c3e92a8f654b7e9c42d1f8e3a".to_string(),
            avg_time_ms: 2.1,
            finality_time_ms: 1200.0,
        };

        let output = epoch_display.format_compact();
        assert!(output.contains("EPOCH 98"));
        assert!(output.contains("FlowConsensus"));
        assert!(output.contains("4 Shards"));
    }

    #[test]
    fn test_protocol_status_formatting() {
        let status = ProtocolStatus {
            epoch: 100,
            consensus_efficiency: 98.7,
            active_shards: 4,
            active_validators: 32,
            last_block_hash: "3c9e59447da8be45".to_string(),
            last_block_size_kb: 156,
            finality_time_ms: 1200.0,
            zk_constraint_reduction: 87.2,
            zk_compression_ratio: 23.7,
            zk_proof_generation_ms: 178.0,
            validator_count: 32,
            bootstrap_count: 12,
            delegated_avo: 5200.0,
            network_stake_percentage: 5.65,
        };

        let output = status.format_extended();
        assert!(output.contains("EPOCH 100"));
        assert!(output.contains("CONSENSUS"));
        assert!(output.contains("ZK OPTIM"));
        assert!(output.contains("STAKING"));
    }
}
