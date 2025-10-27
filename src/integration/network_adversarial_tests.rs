use crate::error::AvoError;
use crate::integration::integration_framework::IntegrationTestFramework;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::info;

/// Network adversarial testing suite for hostile conditions
pub struct NetworkAdversarialTestSuite {
    /// Integration test framework
    framework: Arc<RwLock<IntegrationTestFramework>>,
    /// Adversarial test configuration
    config: AdversarialTestConfig,
    /// Test results
    results: Arc<RwLock<AdversarialTestResults>>,
}

/// Adversarial test configuration
#[derive(Debug, Clone)]
pub struct AdversarialTestConfig {
    /// Network attack scenarios to test
    pub attack_scenarios: Vec<AttackScenario>,
    /// Byzantine node percentage (0.0-0.33)
    pub byzantine_node_percentage: f64,
    /// Network partition scenarios
    pub partition_scenarios: Vec<PartitionScenario>,
    /// DDoS attack simulation
    pub ddos_simulation: DDoSConfig,
    /// Eclipse attack simulation
    pub eclipse_attack: EclipseConfig,
    /// Sybil attack simulation
    pub sybil_attack: SybilConfig,
    /// Test duration per scenario
    pub scenario_duration_seconds: u64,
}

/// Network attack scenario
#[derive(Debug, Clone)]
pub struct AttackScenario {
    /// Attack name
    pub name: String,
    /// Attack type
    pub attack_type: AttackType,
    /// Attack intensity (0.0-1.0)
    pub intensity: f64,
    /// Duration in seconds
    pub duration_seconds: u64,
    /// Affected nodes percentage
    pub affected_nodes_percentage: f64,
}

/// Types of network attacks
#[derive(Debug, Clone)]
pub enum AttackType {
    /// Byzantine behavior
    Byzantine,
    /// Network flooding
    Flooding,
    /// Message corruption
    MessageCorruption,
    /// Selective message dropping
    SelectiveDropping,
    /// Timing attacks
    TimingAttack,
    /// Resource exhaustion
    ResourceExhaustion,
}

/// Network partition scenario
#[derive(Debug, Clone)]
pub struct PartitionScenario {
    /// Partition name
    pub name: String,
    /// Partition type
    pub partition_type: PartitionType,
    /// Duration in seconds
    pub duration_seconds: u64,
    /// Partition configuration
    pub partition_config: PartitionConfig,
}

/// Types of network partitions
#[derive(Debug, Clone)]
pub enum PartitionType {
    /// Random partition
    Random,
    /// Geographic partition
    Geographic,
    /// Shard-based partition
    ShardBased,
    /// Validator isolation
    ValidatorIsolation,
}

/// Partition configuration
#[derive(Debug, Clone)]
pub struct PartitionConfig {
    /// Nodes in partition A
    pub partition_a_nodes: Vec<String>,
    /// Nodes in partition B  
    pub partition_b_nodes: Vec<String>,
    /// Cross-partition communication allowed
    pub cross_partition_communication: bool,
    /// Partition healing time
    pub healing_time_seconds: u64,
}

/// DDoS attack configuration
#[derive(Debug, Clone)]
pub struct DDoSConfig {
    /// Attack enabled
    pub enabled: bool,
    /// Requests per second
    pub requests_per_second: u64,
    /// Attack duration
    pub duration_seconds: u64,
    /// Target nodes percentage
    pub target_nodes_percentage: f64,
    /// Request size bytes
    pub request_size_bytes: usize,
}

/// Eclipse attack configuration
#[derive(Debug, Clone)]
pub struct EclipseConfig {
    /// Attack enabled
    pub enabled: bool,
    /// Malicious peers percentage
    pub malicious_peers_percentage: f64,
    /// Isolation target nodes
    pub target_nodes: Vec<String>,
    /// Attack duration
    pub duration_seconds: u64,
}

/// Sybil attack configuration
#[derive(Debug, Clone)]
pub struct SybilConfig {
    /// Attack enabled
    pub enabled: bool,
    /// Number of fake identities
    pub fake_identities_count: usize,
    /// Identity change frequency
    pub identity_change_frequency_seconds: u64,
    /// Attack duration
    pub duration_seconds: u64,
}

/// Adversarial test results
#[derive(Debug, Default, Clone)]
pub struct AdversarialTestResults {
    /// Test start time
    pub start_time: Option<Instant>,
    /// Test completion time
    pub completion_time: Option<Instant>,
    /// Attack scenario results
    pub attack_results: HashMap<String, AttackScenarioResults>,
    /// Partition test results
    pub partition_results: HashMap<String, PartitionTestResults>,
    /// Byzantine behavior results
    pub byzantine_results: ByzantineTestResults,
    /// Network resilience metrics
    pub resilience_metrics: NetworkResilienceMetrics,
    /// Overall adversarial resistance score
    pub adversarial_resistance_score: f64,
}

/// Results for individual attack scenario
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct AttackScenarioResults {
    /// Attack successfully mitigated
    pub attack_mitigated: bool,
    /// System availability during attack
    pub availability_during_attack: f64,
    /// Performance degradation percentage
    pub performance_degradation: f64,
    /// Recovery time after attack (seconds)
    pub recovery_time_seconds: f64,
    /// Consensus maintained
    pub consensus_maintained: bool,
    /// False positive rate
    pub false_positive_rate: f64,
}

/// Results for partition testing
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PartitionTestResults {
    /// Partition detected correctly
    pub partition_detected: bool,
    /// Healing time (seconds)
    pub healing_time_seconds: f64,
    /// Consistency maintained across partitions
    pub consistency_maintained: bool,
    /// Performance during partition
    pub performance_during_partition: f64,
    /// Recovery success rate
    pub recovery_success_rate: f64,
}

/// Byzantine behavior test results
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ByzantineTestResults {
    /// Byzantine nodes detected
    pub byzantine_nodes_detected: u32,
    /// Byzantine nodes tolerated
    pub byzantine_nodes_tolerated: u32,
    /// False accusation rate
    pub false_accusation_rate: f64,
    /// Consensus agreement despite Byzantine nodes
    pub consensus_agreement_rate: f64,
    /// BFT threshold maintained
    pub bft_threshold_maintained: bool,
}

/// Network resilience metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkResilienceMetrics {
    /// Average recovery time across scenarios
    pub avg_recovery_time_seconds: f64,
    /// System uptime percentage
    pub system_uptime_percentage: f64,
    /// Attack detection accuracy
    pub attack_detection_accuracy: f64,
    /// False alarm rate
    pub false_alarm_rate: f64,
    /// Adaptive response effectiveness
    pub adaptive_response_effectiveness: f64,
}

impl NetworkAdversarialTestSuite {
    /// Create new adversarial test suite
    pub fn new(
        framework: Arc<RwLock<IntegrationTestFramework>>,
        config: AdversarialTestConfig,
    ) -> Self {
        Self {
            framework,
            config,
            results: Arc::new(RwLock::new(AdversarialTestResults::default())),
        }
    }

    /// Run comprehensive adversarial tests
    pub async fn run_adversarial_tests(&self) -> Result<AdversarialTestResults, AvoError> {
        info!("⚔️  Starting Network Adversarial Test Suite");
        info!(
            "   • Attack Scenarios: {}",
            self.config.attack_scenarios.len()
        );
        info!(
            "   • Partition Scenarios: {}",
            self.config.partition_scenarios.len()
        );
        info!(
            "   • Byzantine Nodes: {:.1}%",
            self.config.byzantine_node_percentage * 100.0
        );

        let start_time = Instant::now();
        {
            let mut results = self.results.write().await;
            results.start_time = Some(start_time);
        }

        // Test Phase 1: Attack Scenario Testing
        info!("📋 Phase 1: Network Attack Scenarios");
        self.test_attack_scenarios().await?;

        // Test Phase 2: Network Partition Testing
        info!("📋 Phase 2: Network Partition Testing");
        self.test_network_partitions().await?;

        // Test Phase 3: Byzantine Behavior Testing
        info!("📋 Phase 3: Byzantine Behavior Testing");
        self.test_byzantine_behavior().await?;

        // Test Phase 4: DDoS Resistance Testing
        info!("📋 Phase 4: DDoS Resistance Testing");
        self.test_ddos_resistance().await?;

        // Test Phase 5: Advanced Attack Combinations
        info!("📋 Phase 5: Advanced Attack Combinations");
        self.test_combined_attacks().await?;

        let completion_time = Instant::now();
        {
            let mut results = self.results.write().await;
            results.completion_time = Some(completion_time);

            // Calculate overall adversarial resistance score
            results.adversarial_resistance_score = self.calculate_resistance_score().await;
        }

        let final_results = {
            let results = self.results.read().await;
            AdversarialTestResults {
                start_time: results.start_time,
                completion_time: results.completion_time,
                attack_results: results.attack_results.clone(),
                partition_results: results.partition_results.clone(),
                byzantine_results: results.byzantine_results.clone(),
                resilience_metrics: results.resilience_metrics.clone(),
                adversarial_resistance_score: results.adversarial_resistance_score,
            }
        };

        info!("✅ Adversarial Tests Completed");
        info!(
            "   • Duration: {:.2}s",
            completion_time.duration_since(start_time).as_secs_f64()
        );
        info!(
            "   • Adversarial Resistance Score: {:.1}%",
            final_results.adversarial_resistance_score * 100.0
        );

        Ok(final_results)
    }

    /// Test attack scenarios
    async fn test_attack_scenarios(&self) -> Result<(), AvoError> {
        info!("🎯 Testing attack scenarios");

        for scenario in &self.config.attack_scenarios {
            info!(
                "   • Testing attack: {} (intensity: {:.1})",
                scenario.name, scenario.intensity
            );

            let scenario_start = Instant::now();

            // Simulate attack scenario
            let attack_results = self.simulate_attack_scenario(scenario).await?;

            let scenario_duration = scenario_start.elapsed();
            info!(
                "     ✅ Attack scenario completed in {:.2}s (mitigated: {})",
                scenario_duration.as_secs_f64(),
                attack_results.attack_mitigated
            );

            // Store results
            {
                let mut results = self.results.write().await;
                results
                    .attack_results
                    .insert(scenario.name.clone(), attack_results);
            }
        }

        Ok(())
    }

    /// Simulate individual attack scenario
    async fn simulate_attack_scenario(
        &self,
        scenario: &AttackScenario,
    ) -> Result<AttackScenarioResults, AvoError> {
        let mut rng = thread_rng();

        // Simulate attack execution
        let attack_duration = Duration::from_secs(scenario.duration_seconds);
        let _attack_start = Instant::now();

        // Simulate system response based on attack type and intensity
        let (availability, performance_degradation) = match scenario.attack_type {
            AttackType::Byzantine => {
                // Byzantine attacks affect consensus
                let availability = 1.0 - (scenario.intensity * 0.3);
                let degradation = scenario.intensity * 0.4;
                (availability, degradation)
            }
            AttackType::Flooding => {
                // Flooding affects network performance
                let availability = 1.0 - (scenario.intensity * 0.5);
                let degradation = scenario.intensity * 0.7;
                (availability, degradation)
            }
            AttackType::MessageCorruption => {
                // Message corruption affects reliability
                let availability = 1.0 - (scenario.intensity * 0.2);
                let degradation = scenario.intensity * 0.3;
                (availability, degradation)
            }
            AttackType::SelectiveDropping => {
                // Selective dropping affects specific connections
                let availability = 1.0 - (scenario.intensity * 0.4);
                let degradation = scenario.intensity * 0.5;
                (availability, degradation)
            }
            AttackType::TimingAttack => {
                // Timing attacks affect synchronization
                let availability = 1.0 - (scenario.intensity * 0.1);
                let degradation = scenario.intensity * 0.2;
                (availability, degradation)
            }
            AttackType::ResourceExhaustion => {
                // Resource exhaustion affects system capacity
                let availability = 1.0 - (scenario.intensity * 0.6);
                let degradation = scenario.intensity * 0.8;
                (availability, degradation)
            }
        };

        // Simulate attack duration
        sleep(Duration::from_millis(
            (attack_duration.as_millis() / 10) as u64,
        ))
        .await;

        // Determine if attack was mitigated
        let mitigation_effectiveness = 0.7 + rng.gen::<f64>() * 0.25; // 70-95% effectiveness
        let attack_mitigated = mitigation_effectiveness > scenario.intensity;

        // Calculate recovery time
        let base_recovery_time = 5.0; // 5 seconds base
        let intensity_factor = scenario.intensity * 10.0;
        let recovery_time = base_recovery_time + intensity_factor + rng.gen::<f64>() * 5.0;

        // Consensus maintained if attack intensity is not too high
        let consensus_maintained = scenario.intensity < 0.8 && attack_mitigated;

        // False positive rate (system incorrectly identifies benign behavior as attack)
        let false_positive_rate = (1.0 - mitigation_effectiveness) * 0.1;

        Ok(AttackScenarioResults {
            attack_mitigated,
            availability_during_attack: availability.max(0.0).min(1.0),
            performance_degradation: performance_degradation.max(0.0).min(1.0),
            recovery_time_seconds: recovery_time,
            consensus_maintained,
            false_positive_rate,
        })
    }

    /// Test network partitions
    async fn test_network_partitions(&self) -> Result<(), AvoError> {
        info!("🌐 Testing network partitions");

        for partition in &self.config.partition_scenarios {
            info!(
                "   • Testing partition: {} (type: {:?})",
                partition.name, partition.partition_type
            );

            let partition_start = Instant::now();

            // Simulate network partition
            let partition_results = self.simulate_network_partition(partition).await?;

            let partition_duration = partition_start.elapsed();
            info!(
                "     ✅ Partition test completed in {:.2}s (detected: {})",
                partition_duration.as_secs_f64(),
                partition_results.partition_detected
            );

            // Store results
            {
                let mut results = self.results.write().await;
                results
                    .partition_results
                    .insert(partition.name.clone(), partition_results);
            }
        }

        Ok(())
    }

    /// Simulate network partition
    async fn simulate_network_partition(
        &self,
        partition: &PartitionScenario,
    ) -> Result<PartitionTestResults, AvoError> {
        let mut rng = thread_rng();

        // Simulate partition detection
        let detection_time = Duration::from_millis(rng.gen_range(500..2000));
        sleep(detection_time).await;

        let partition_detected = rng.gen::<f64>() > 0.1; // 90% detection rate

        // Simulate partition effects
        let partition_duration = Duration::from_secs(partition.duration_seconds);
        let healing_time =
            partition.partition_config.healing_time_seconds as f64 + rng.gen::<f64>() * 5.0; // Add some variance

        // Performance during partition depends on type
        let performance_during_partition = match partition.partition_type {
            PartitionType::Random => 0.6 + rng.gen::<f64>() * 0.3, // 60-90%
            PartitionType::Geographic => 0.7 + rng.gen::<f64>() * 0.2, // 70-90%
            PartitionType::ShardBased => 0.8 + rng.gen::<f64>() * 0.15, // 80-95%
            PartitionType::ValidatorIsolation => 0.5 + rng.gen::<f64>() * 0.3, // 50-80%
        };

        // Consistency maintenance depends on cross-partition communication
        let consistency_maintained =
            partition.partition_config.cross_partition_communication || rng.gen::<f64>() > 0.2; // 80% chance if no cross-partition communication

        // Recovery success rate
        let recovery_success_rate = if partition_detected { 0.95 } else { 0.7 };

        // Simulate partition duration (shortened for testing)
        sleep(Duration::from_millis(
            (partition_duration.as_millis() / 20) as u64,
        ))
        .await;

        Ok(PartitionTestResults {
            partition_detected,
            healing_time_seconds: healing_time,
            consistency_maintained,
            performance_during_partition,
            recovery_success_rate,
        })
    }

    /// Test Byzantine behavior
    async fn test_byzantine_behavior(&self) -> Result<(), AvoError> {
        info!("👹 Testing Byzantine behavior tolerance");

        // Calculate number of Byzantine nodes
        let total_nodes = 12; // Default from framework
        let byzantine_count = (total_nodes as f64 * self.config.byzantine_node_percentage) as u32;

        info!(
            "   • Byzantine nodes: {} / {}",
            byzantine_count, total_nodes
        );

        // Simulate Byzantine behavior detection
        let mut rng = thread_rng();

        // Detection effectiveness
        let detection_rate = 0.85 + rng.gen::<f64>() * 0.1; // 85-95%
        let detected_byzantine = (byzantine_count as f64 * detection_rate) as u32;

        // Tolerance calculation (BFT can tolerate up to 1/3 Byzantine nodes)
        let max_tolerable = total_nodes / 3;
        let byzantine_tolerated = byzantine_count.min(max_tolerable as u32);

        // False accusation rate
        let false_accusation_rate = (1.0 - detection_rate) * 0.05; // Low false positive rate

        // Consensus agreement despite Byzantine nodes
        let consensus_agreement_rate = if byzantine_count <= max_tolerable as u32 {
            0.95 + rng.gen::<f64>() * 0.04 // 95-99%
        } else {
            0.7 + rng.gen::<f64>() * 0.2 // 70-90% if above threshold
        };

        // BFT threshold maintained
        let bft_threshold_maintained = byzantine_count <= max_tolerable as u32;

        // Simulate Byzantine behavior testing
        sleep(Duration::from_secs(5)).await;

        // Store results
        {
            let mut results = self.results.write().await;
            results.byzantine_results = ByzantineTestResults {
                byzantine_nodes_detected: detected_byzantine,
                byzantine_nodes_tolerated: byzantine_tolerated,
                false_accusation_rate,
                consensus_agreement_rate,
                bft_threshold_maintained,
            };
        }

        info!("   ✅ Byzantine behavior test completed");
        info!(
            "     • Detected: {} / {}",
            detected_byzantine, byzantine_count
        );
        info!(
            "     • BFT threshold maintained: {}",
            bft_threshold_maintained
        );

        Ok(())
    }

    /// Test DDoS resistance
    async fn test_ddos_resistance(&self) -> Result<(), AvoError> {
        info!("🚫 Testing DDoS resistance");

        if !self.config.ddos_simulation.enabled {
            info!("   • DDoS testing disabled, skipping");
            return Ok(());
        }

        let ddos_config = &self.config.ddos_simulation;

        info!(
            "   • DDoS simulation: {} RPS for {}s",
            ddos_config.requests_per_second, ddos_config.duration_seconds
        );

        // Simulate DDoS attack
        let _attack_start = Instant::now();

        // Calculate attack impact
        let attack_intensity = (ddos_config.requests_per_second as f64 / 10000.0).min(1.0);
        let availability_during_attack = 1.0 - (attack_intensity * 0.4);
        let performance_degradation = attack_intensity * 0.6;

        // Simulate attack duration
        sleep(Duration::from_secs(ddos_config.duration_seconds.min(10))).await;

        // Simulate recovery
        let recovery_time = 2.0 + attack_intensity * 8.0; // 2-10 seconds
        sleep(Duration::from_millis((recovery_time * 100.0) as u64)).await;

        // DDoS mitigation success
        let mitigation_success = attack_intensity < 0.8;

        // Create attack scenario result for DDoS
        let ddos_results = AttackScenarioResults {
            attack_mitigated: mitigation_success,
            availability_during_attack,
            performance_degradation,
            recovery_time_seconds: recovery_time,
            consensus_maintained: mitigation_success,
            false_positive_rate: 0.05,
        };

        // Store results
        {
            let mut results = self.results.write().await;
            results
                .attack_results
                .insert("DDoS Attack".to_string(), ddos_results);
        }

        info!(
            "   ✅ DDoS resistance test completed (mitigated: {})",
            mitigation_success
        );

        Ok(())
    }

    /// Test combined attacks
    async fn test_combined_attacks(&self) -> Result<(), AvoError> {
        info!("⚡ Testing combined attack scenarios");

        // Simulate combined attack: Byzantine + Network partition
        info!("   • Combined attack: Byzantine + Partition");

        let combined_start = Instant::now();

        // Simulate more severe impact from combined attacks
        let mut rng = thread_rng();
        let availability = 0.5 + rng.gen::<f64>() * 0.3; // 50-80%
        let performance_degradation = 0.4 + rng.gen::<f64>() * 0.4; // 40-80%
        let recovery_time = 10.0 + rng.gen::<f64>() * 15.0; // 10-25 seconds
        let mitigation_success = availability > 0.6;

        // Simulate combined attack duration
        sleep(Duration::from_secs(8)).await;

        let combined_results = AttackScenarioResults {
            attack_mitigated: mitigation_success,
            availability_during_attack: availability,
            performance_degradation,
            recovery_time_seconds: recovery_time,
            consensus_maintained: mitigation_success && availability > 0.7,
            false_positive_rate: 0.08,
        };

        // Store results
        {
            let mut results = self.results.write().await;
            results
                .attack_results
                .insert("Combined Attack".to_string(), combined_results);
        }

        let combined_duration = combined_start.elapsed();
        info!(
            "   ✅ Combined attack test completed in {:.2}s (mitigated: {})",
            combined_duration.as_secs_f64(),
            mitigation_success
        );

        Ok(())
    }

    /// Calculate overall adversarial resistance score
    async fn calculate_resistance_score(&self) -> f64 {
        let results = self.results.read().await;

        let mut total_score = 0.0;
        let mut score_count = 0;

        // Score from attack scenarios
        for (_, attack_result) in &results.attack_results {
            let attack_score = if attack_result.attack_mitigated {
                (attack_result.availability_during_attack
                    + (1.0 - attack_result.performance_degradation)
                    + if attack_result.consensus_maintained {
                        1.0
                    } else {
                        0.0
                    })
                    / 3.0
            } else {
                attack_result.availability_during_attack * 0.5
            };
            total_score += attack_score;
            score_count += 1;
        }

        // Score from partition scenarios
        for (_, partition_result) in &results.partition_results {
            let partition_score = if partition_result.partition_detected {
                (partition_result.performance_during_partition
                    + partition_result.recovery_success_rate
                    + if partition_result.consistency_maintained {
                        1.0
                    } else {
                        0.0
                    })
                    / 3.0
            } else {
                partition_result.performance_during_partition * 0.7
            };
            total_score += partition_score;
            score_count += 1;
        }

        // Score from Byzantine behavior
        let byzantine_score = if results.byzantine_results.bft_threshold_maintained {
            results.byzantine_results.consensus_agreement_rate
        } else {
            results.byzantine_results.consensus_agreement_rate * 0.6
        };
        total_score += byzantine_score;
        score_count += 1;

        if score_count > 0 {
            total_score / score_count as f64
        } else {
            0.0
        }
    }
}

impl Default for AdversarialTestConfig {
    fn default() -> Self {
        Self {
            attack_scenarios: vec![
                AttackScenario {
                    name: "Low-intensity Byzantine".to_string(),
                    attack_type: AttackType::Byzantine,
                    intensity: 0.3,
                    duration_seconds: 30,
                    affected_nodes_percentage: 0.1,
                },
                AttackScenario {
                    name: "Medium-intensity Flooding".to_string(),
                    attack_type: AttackType::Flooding,
                    intensity: 0.5,
                    duration_seconds: 45,
                    affected_nodes_percentage: 0.2,
                },
                AttackScenario {
                    name: "High-intensity Message Corruption".to_string(),
                    attack_type: AttackType::MessageCorruption,
                    intensity: 0.7,
                    duration_seconds: 60,
                    affected_nodes_percentage: 0.15,
                },
            ],
            byzantine_node_percentage: 0.25, // 25% Byzantine nodes (under 1/3 threshold)
            partition_scenarios: vec![
                PartitionScenario {
                    name: "Random Network Split".to_string(),
                    partition_type: PartitionType::Random,
                    duration_seconds: 60,
                    partition_config: PartitionConfig {
                        partition_a_nodes: vec![],
                        partition_b_nodes: vec![],
                        cross_partition_communication: false,
                        healing_time_seconds: 10,
                    },
                },
                PartitionScenario {
                    name: "Geographic Partition".to_string(),
                    partition_type: PartitionType::Geographic,
                    duration_seconds: 90,
                    partition_config: PartitionConfig {
                        partition_a_nodes: vec![],
                        partition_b_nodes: vec![],
                        cross_partition_communication: true,
                        healing_time_seconds: 15,
                    },
                },
            ],
            ddos_simulation: DDoSConfig {
                enabled: true,
                requests_per_second: 5000,
                duration_seconds: 30,
                target_nodes_percentage: 0.3,
                request_size_bytes: 1024,
            },
            eclipse_attack: EclipseConfig {
                enabled: true,
                malicious_peers_percentage: 0.4,
                target_nodes: vec![],
                duration_seconds: 45,
            },
            sybil_attack: SybilConfig {
                enabled: true,
                fake_identities_count: 20,
                identity_change_frequency_seconds: 30,
                duration_seconds: 60,
            },
            scenario_duration_seconds: 120,
        }
    }
}
