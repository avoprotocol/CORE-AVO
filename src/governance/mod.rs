pub mod delegation;
pub mod governance_admin;
pub mod governance_state;
pub mod proposals;
pub mod treasury;
pub mod voting;

// Re-export main structures
pub use crate::types::TokenAmount;

// Admin governance exports
pub use governance_admin::{
    AdminGovernanceConfig, AdminGovernanceManager, GovernancePhase, GovernanceStats,
    GOVERNANCE_ADMIN, VOTE_FEE,
};
pub use proposals::{
    EconomicImpact, GovernanceConfig, ImpactAssessment, Proposal, ProposalId, ProposalManager,
    ProposalMetadata, ProposalStatus, ProposalType, SecurityRisk, TechnicalComplexity, VoteChoice,
    VoteRecord, VotingPower,
};

pub use voting::{
    DelegationRecord, DelegationType, QuorumConfig, VoterProfile, VotingConfig, VotingHistory,
    VotingStatistics, VotingSystem,
};

pub use treasury::{
    AccountState, ExpenditureCategory, FeeDistribution, IncomeSource, SpendingLimits,
    TransactionId, TransactionMetadata, TransactionType, Treasury, TreasuryAccount, TreasuryConfig,
    TreasuryReport, TreasuryTransaction,
};

pub use delegation::{
    DelegateProfile, DelegationConfig, DelegationId, DelegationManager,
    DelegationRecord as DelRecord, DelegationStatistics, DelegationType as DelType,
    ProposalCategory, TrustLevel, VerificationStatus,
};

pub use governance_state::{
    ActivityType, EpochState, GovernanceActivity, GovernanceGlobalConfig, GovernanceHealthReport,
    GovernanceMetrics, GovernanceState,
};
