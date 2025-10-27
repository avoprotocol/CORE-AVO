//! Validator and Operator Reputation System
//! 
//! Implements a comprehensive scoring system (1-5 stars) based on:
//! - Uptime (online time percentage)
//! - Slashing history (malicious acts, downtime penalties)
//! - Block production performance
//! - Attestation accuracy
//! - Network participation
//! - Age/longevity of the validator

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use super::reputation_db::ReputationDB;
use tracing::{info, error};

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

/// Reputation score from 1.0 to 5.0 (displayed as 1-5 stars)
pub type ReputationScore = f64;

/// Validator reputation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReputation {
    /// Validator ID
    pub validator_id: u64,
    /// Overall reputation score (1.0 - 5.0)
    pub score: ReputationScore,
    /// Individual metric scores
    pub metrics: ReputationMetrics,
    /// Historical data
    pub history: ReputationHistory,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Individual reputation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationMetrics {
    /// Uptime score (0.0 - 1.0) - percentage of expected online time
    pub uptime_score: f64,
    /// Slashing score (0.0 - 1.0) - 1.0 = no slashing, decreases with incidents
    pub slashing_score: f64,
    /// Performance score (0.0 - 1.0) - block production efficiency
    pub performance_score: f64,
    /// Attestation score (0.0 - 1.0) - accuracy of attestations
    pub attestation_score: f64,
    /// Participation score (0.0 - 1.0) - network participation rate
    pub participation_score: f64,
    /// Longevity score (0.0 - 1.0) - time active as validator
    pub longevity_score: f64,
}

impl Default for ReputationMetrics {
    fn default() -> Self {
        Self {
            uptime_score: 1.0,
            slashing_score: 1.0,
            performance_score: 1.0,
            attestation_score: 1.0,
            participation_score: 1.0,
            longevity_score: 0.5, // New validators start at 50%
        }
    }
}

/// Historical reputation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationHistory {
    /// Total epochs as validator
    pub total_epochs: u64,
    /// Total blocks produced
    pub total_blocks_produced: u64,
    /// Total blocks missed
    pub total_blocks_missed: u64,
    /// Total slashing events
    pub total_slashing_events: u64,
    /// Total downtime incidents
    pub total_downtime_incidents: u64,
    /// Validator registration timestamp
    pub registration_time: u64,
    /// Total time online (in seconds)
    pub total_online_time: u64,
    /// Total time expected to be online (in seconds)
    pub total_expected_time: u64,
}

impl Default for ReputationHistory {
    fn default() -> Self {
        Self {
            total_epochs: 0,
            total_blocks_produced: 0,
            total_blocks_missed: 0,
            total_slashing_events: 0,
            total_downtime_incidents: 0,
            registration_time: current_timestamp(),
            total_online_time: 0,
            total_expected_time: 0,
        }
    }
}

/// Slashing event severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingSeverity {
    /// Minor infractions (1-5% slash)
    Minor,
    /// Moderate infractions (5-15% slash)
    Moderate,
    /// Severe infractions (15-30% slash)
    Severe,
    /// Critical infractions (30%+ slash, possible jail)
    Critical,
}

/// Reputation calculator with configurable weights
pub struct ReputationCalculator {
    /// Weight for uptime (default: 0.25)
    pub uptime_weight: f64,
    /// Weight for slashing history (default: 0.30)
    pub slashing_weight: f64,
    /// Weight for performance (default: 0.20)
    pub performance_weight: f64,
    /// Weight for attestation (default: 0.10)
    pub attestation_weight: f64,
    /// Weight for participation (default: 0.10)
    pub participation_weight: f64,
    /// Weight for longevity (default: 0.05)
    pub longevity_weight: f64,
}

impl Default for ReputationCalculator {
    fn default() -> Self {
        Self {
            uptime_weight: 0.25,
            slashing_weight: 0.30,
            performance_weight: 0.20,
            attestation_weight: 0.10,
            participation_weight: 0.10,
            longevity_weight: 0.05,
        }
    }
}

impl ReputationCalculator {
    /// Calculate overall reputation score (1.0 - 5.0)
    pub fn calculate_score(&self, metrics: &ReputationMetrics) -> ReputationScore {
        let weighted_sum = metrics.uptime_score * self.uptime_weight
            + metrics.slashing_score * self.slashing_weight
            + metrics.performance_score * self.performance_weight
            + metrics.attestation_score * self.attestation_weight
            + metrics.participation_score * self.participation_weight
            + metrics.longevity_score * self.longevity_weight;

        // Convert 0.0-1.0 range to 1.0-5.0 range
        // 0.0 → 1.0 star (worst)
        // 1.0 → 5.0 stars (perfect)
        1.0 + (weighted_sum * 4.0)
    }

    /// Calculate uptime score based on online percentage
    pub fn calculate_uptime_score(
        &self,
        total_online_time: u64,
        total_expected_time: u64,
    ) -> f64 {
        if total_expected_time == 0 {
            return 1.0; // New validator
        }

        let uptime_percentage = total_online_time as f64 / total_expected_time as f64;

        // Exponential curve: uptime must be very high for good score
        match uptime_percentage {
            p if p >= 0.99 => 1.0,   // 99%+ uptime = perfect
            p if p >= 0.95 => 0.95,  // 95-99% = excellent
            p if p >= 0.90 => 0.85,  // 90-95% = good
            p if p >= 0.80 => 0.70,  // 80-90% = acceptable
            p if p >= 0.70 => 0.50,  // 70-80% = poor
            _ => uptime_percentage.max(0.0), // <70% = very poor
        }
    }

    /// Calculate slashing score (decreases with slashing events)
    pub fn calculate_slashing_score(
        &self,
        total_slashing_events: u64,
        slashing_severities: &[SlashingSeverity],
    ) -> f64 {
        if total_slashing_events == 0 {
            return 1.0; // Perfect - no slashing
        }

        let mut penalty = 0.0;

        for severity in slashing_severities {
            penalty += match severity {
                SlashingSeverity::Minor => 0.05,     // -5% per minor slash
                SlashingSeverity::Moderate => 0.15,  // -15% per moderate slash
                SlashingSeverity::Severe => 0.30,    // -30% per severe slash
                SlashingSeverity::Critical => 0.50,  // -50% per critical slash
            };
        }

        // Score can't go below 0.0
        (1.0_f64 - penalty).max(0.0_f64)
    }

    /// Calculate performance score based on block production
    pub fn calculate_performance_score(
        &self,
        blocks_produced: u64,
        blocks_missed: u64,
    ) -> f64 {
        let total_assignments = blocks_produced + blocks_missed;
        if total_assignments == 0 {
            return 1.0; // New validator
        }

        let success_rate = blocks_produced as f64 / total_assignments as f64;

        // Exponential curve for performance
        match success_rate {
            p if p >= 0.99 => 1.0,
            p if p >= 0.95 => 0.95,
            p if p >= 0.90 => 0.85,
            p if p >= 0.85 => 0.75,
            p if p >= 0.80 => 0.60,
            _ => success_rate.max(0.0),
        }
    }

    /// Calculate longevity score (increases with time)
    pub fn calculate_longevity_score(
        &self,
        registration_time: u64,
        current_time: u64,
    ) -> f64 {
        let age_seconds = current_time.saturating_sub(registration_time);
        let age_days = age_seconds as f64 / 86400.0;

        // Logarithmic growth: newer validators have lower score
        match age_days {
            d if d >= 365.0 => 1.0,   // 1+ years = perfect
            d if d >= 180.0 => 0.95,  // 6+ months = excellent
            d if d >= 90.0 => 0.85,   // 3+ months = good
            d if d >= 30.0 => 0.70,   // 1+ month = acceptable
            d if d >= 7.0 => 0.50,    // 1+ week = new
            _ => 0.30,                // <1 week = very new
        }
    }
}

/// Reputation manager for tracking all validators
pub struct ReputationManager {
    /// Calculator with weights
    calculator: ReputationCalculator,
    /// Reputation data for each validator (in-memory cache)
    reputations: HashMap<u64, ValidatorReputation>,
    /// RocksDB persistence layer
    db: Option<ReputationDB>,
}

impl ReputationManager {
    pub fn new() -> Self {
        Self {
            calculator: ReputationCalculator::default(),
            reputations: HashMap::new(),
            db: None,
        }
    }

    /// Create a new ReputationManager with RocksDB persistence
    pub fn with_db(db_path: &str) -> Self {
        let mut manager = Self::new();
        
        // Open database
        match ReputationDB::open(db_path) {
            Ok(db) => {
                // Load all existing reputations from DB
                match db.load_all_reputations() {
                    Ok(loaded_reps) => {
                        for (validator_id, reputation) in loaded_reps {
                            manager.reputations.insert(validator_id, reputation);
                        }
                        info!("✅ Loaded {} reputations from database", manager.reputations.len());
                    }
                    Err(e) => {
                        error!("❌ Failed to load reputations from DB: {}", e);
                    }
                }
                manager.db = Some(db);
            }
            Err(e) => {
                error!("❌ Failed to open reputation database: {}", e);
            }
        }
        
        manager
    }

    /// Initialize reputation for a new validator
    pub fn initialize_validator(&mut self, validator_id: u64) {
        let reputation = ValidatorReputation {
            validator_id,
            score: 3.5, // New validators start at 3.5 stars (70%)
            metrics: ReputationMetrics::default(),
            history: ReputationHistory::default(),
            last_updated: current_timestamp(),
        };

        // Save to memory cache
        self.reputations.insert(validator_id, reputation.clone());
        
        // Persist to database
        if let Some(db) = &self.db {
            if let Err(e) = db.save_reputation(validator_id, &reputation) {
                error!("❌ Failed to persist reputation to DB: {}", e);
            }
        }
    }

    /// Update reputation after each epoch
    pub fn update_reputation(
        &mut self,
        validator_id: u64,
        blocks_produced: u64,
        blocks_missed: u64,
        online_time: u64,
        expected_time: u64,
    ) {
        let reputation = self
            .reputations
            .entry(validator_id)
            .or_insert_with(|| ValidatorReputation {
                validator_id,
                score: 3.5,
                metrics: ReputationMetrics::default(),
                history: ReputationHistory::default(),
                last_updated: current_timestamp(),
            });

        // Update history
        reputation.history.total_blocks_produced += blocks_produced;
        reputation.history.total_blocks_missed += blocks_missed;
        reputation.history.total_online_time += online_time;
        reputation.history.total_expected_time += expected_time;
        reputation.history.total_epochs += 1;

        // Recalculate metrics
        reputation.metrics.uptime_score = self.calculator.calculate_uptime_score(
            reputation.history.total_online_time,
            reputation.history.total_expected_time,
        );

        reputation.metrics.performance_score = self.calculator.calculate_performance_score(
            reputation.history.total_blocks_produced,
            reputation.history.total_blocks_missed,
        );

        reputation.metrics.longevity_score = self.calculator.calculate_longevity_score(
            reputation.history.registration_time,
            current_timestamp(),
        );

        // Recalculate overall score
        reputation.score = self.calculator.calculate_score(&reputation.metrics);
        reputation.last_updated = current_timestamp();
        
        // Persist to database
        if let Some(db) = &self.db {
            if let Err(e) = db.save_reputation(validator_id, reputation) {
                error!("❌ Failed to persist reputation update to DB: {}", e);
            }
        }
    }

    /// Record a slashing event
    pub fn record_slashing(
        &mut self,
        validator_id: u64,
        severity: SlashingSeverity,
    ) {
        if let Some(reputation) = self.reputations.get_mut(&validator_id) {
            reputation.history.total_slashing_events += 1;

            // Recalculate slashing score
            let severities = vec![severity]; // In production, track all severities
            reputation.metrics.slashing_score =
                self.calculator.calculate_slashing_score(1, &severities);

            // Recalculate overall score
            reputation.score = self.calculator.calculate_score(&reputation.metrics);
            reputation.last_updated = current_timestamp();
            
            // Persist to database
            if let Some(db) = &self.db {
                if let Err(e) = db.save_reputation(validator_id, reputation) {
                    error!("❌ Failed to persist slashing event to DB: {}", e);
                }
            }
        }
    }

    /// Get reputation for a validator
    pub fn get_reputation(&self, validator_id: u64) -> Option<&ValidatorReputation> {
        self.reputations.get(&validator_id)
    }

    /// Get total validator count
    pub fn get_total_validators(&self) -> usize {
        self.reputations.len()
    }

    /// Get all reputations
    pub fn get_all_reputations(&self) -> Vec<&ValidatorReputation> {
        self.reputations.values().collect()
    }

    /// Get all reputations sorted by score (descending)
    pub fn get_top_validators(&self, limit: usize) -> Vec<&ValidatorReputation> {
        let mut validators: Vec<_> = self.reputations.values().collect();
        validators.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        validators.into_iter().take(limit).collect()
    }

    /// Get reputation tier (Legendary, Excellent, Good, Fair, Poor)
    pub fn get_reputation_tier(score: ReputationScore) -> &'static str {
        match score {
            s if s >= 4.8 => "🏆 Legendary",    // 4.8-5.0 stars
            s if s >= 4.0 => "⭐ Excellent",    // 4.0-4.8 stars
            s if s >= 3.0 => "✅ Good",         // 3.0-4.0 stars
            s if s >= 2.0 => "⚠️ Fair",        // 2.0-3.0 stars
            _ => "❌ Poor",                     // 1.0-2.0 stars
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perfect_validator() {
        let calculator = ReputationCalculator::default();
        let metrics = ReputationMetrics {
            uptime_score: 1.0,
            slashing_score: 1.0,
            performance_score: 1.0,
            attestation_score: 1.0,
            participation_score: 1.0,
            longevity_score: 1.0,
        };

        let score = calculator.calculate_score(&metrics);
        assert_eq!(score, 5.0); // Perfect score
    }

    #[test]
    fn test_new_validator() {
        let calculator = ReputationCalculator::default();
        let metrics = ReputationMetrics::default();

        let score = calculator.calculate_score(&metrics);
        assert!(score >= 3.0 && score <= 4.0); // New validators ~3.5 stars
    }

    #[test]
    fn test_uptime_calculation() {
        let calculator = ReputationCalculator::default();

        // 99% uptime
        let score_99 = calculator.calculate_uptime_score(99, 100);
        assert_eq!(score_99, 1.0);

        // 90% uptime
        let score_90 = calculator.calculate_uptime_score(90, 100);
        assert_eq!(score_90, 0.85);

        // 50% uptime
        let score_50 = calculator.calculate_uptime_score(50, 100);
        assert!(score_50 < 0.60);
    }

    #[test]
    fn test_slashing_penalty() {
        let calculator = ReputationCalculator::default();

        // No slashing
        let score_none = calculator.calculate_slashing_score(0, &[]);
        assert_eq!(score_none, 1.0);

        // One critical slash
        let score_critical = calculator.calculate_slashing_score(1, &[SlashingSeverity::Critical]);
        assert_eq!(score_critical, 0.5);

        // Multiple minor slashes
        let score_minor = calculator.calculate_slashing_score(
            3,
            &[
                SlashingSeverity::Minor,
                SlashingSeverity::Minor,
                SlashingSeverity::Minor,
            ],
        );
        assert_eq!(score_minor, 0.85);
    }
}
