//! Integration testing framework for AVO Protocol
//!
//! This module provides comprehensive integration testing capabilities including:
//! - End-to-end system validation
//! - Network adversarial testing
//! - Fault tolerance validation
//! - Performance optimization under load
//! - P2P + Data Availability integration

/// Integration testing framework module
pub mod integration_framework;
/// P2P + Data Availability integration
pub mod p2p_da_integration;

pub use p2p_da_integration::{
    ChunkMessage, ChunkMessageType, ChunkPropagationStrategy, DAEventType, DataAvailabilityEvent,
    IntegratedNetworkConfig, IntegratedNetworkSystem, SystemMetrics,
};

/// End-to-end testing capabilities
pub mod end_to_end_tests;

/// Network adversarial testing
pub mod network_adversarial_tests;

/// Fault tolerance testing
pub mod fault_tolerance_tests;

/// Performance optimization testing
pub mod performance_optimization_tests;

// Re-export main types for convenience
pub use integration_framework::{
    IntegrationTestConfig, IntegrationTestFramework, IntegrationTestResults, NetworkConfig,
    TestEvent, TestNode,
};

pub use end_to_end_tests::{EndToEndTestConfig, EndToEndTestResults, EndToEndTestSuite};

pub use network_adversarial_tests::{AdversarialTestConfig, NetworkAdversarialTestSuite};

pub use fault_tolerance_tests::{FaultToleranceTestConfig, FaultToleranceTestSuite};

pub use performance_optimization_tests::PerformanceOptimizationTestSuite;
