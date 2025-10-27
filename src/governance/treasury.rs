use crate::error::AvoError;
use crate::governance::proposals::ProposalId;
use crate::state::storage::AvocadoStorage;
use crate::types::{Hash, NodeId, TokenAmount};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Unique identifier for treasury transactions
pub type TransactionId = u64;

/// Treasury account categories with their designated addresses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub enum TreasuryAccount {
    /// Main operational treasury
    Main,
    /// Development funding
    Development,
    /// Marketing and partnerships
    Marketing,
    /// Security audits and bug bounties
    Security,
    /// Community incentives
    Community,
    /// Validator rewards
    ValidatorRewards,
    /// Emergency fund
    Emergency,
    /// Custom account with specific purpose
    Custom(String),
}

impl TreasuryAccount {
    /// Get the designated address for each treasury account
    pub fn get_address(&self) -> &'static str {
        match self {
            TreasuryAccount::Main => "0x1000000000000000000000000000000000000001", // Governance multisig
            TreasuryAccount::Development => "0x2000000000000000000000000000000000000001", // Dev team multisig
            TreasuryAccount::Marketing => "0x3000000000000000000000000000000000000001", // Marketing multisig
            TreasuryAccount::Security => "0x4000000000000000000000000000000000000001", // Security team multisig
            TreasuryAccount::Community => "0x5000000000000000000000000000000000000001", // Community multisig
            TreasuryAccount::ValidatorRewards => "0x6000000000000000000000000000000000000001", // Auto-distribution contract
            TreasuryAccount::Emergency => "0x7000000000000000000000000000000000000001", // Emergency multisig
            TreasuryAccount::Custom(name) => {
                // For custom accounts, generate deterministic address based on name
                "0x8000000000000000000000000000000000000001" // Default custom address
            }
        }
    }

    /// Get account description
    pub fn get_description(&self) -> &'static str {
        match self {
            TreasuryAccount::Main => "Main operational treasury - Governance controlled",
            TreasuryAccount::Development => "Development funding - Core team multisig",
            TreasuryAccount::Marketing => "Marketing and partnerships - Marketing team multisig",
            TreasuryAccount::Security => {
                "Security audits and bug bounties - Security team multisig"
            }
            TreasuryAccount::Community => "Community incentives and grants - Community multisig",
            TreasuryAccount::ValidatorRewards => "Validator rewards pool - Automated distribution",
            TreasuryAccount::Emergency => "Emergency fund - High-security multisig",
            TreasuryAccount::Custom(_) => "Custom purpose account",
        }
    }

    /// Get required multisig threshold for this account
    pub fn get_multisig_threshold(&self) -> u8 {
        match self {
            TreasuryAccount::Main => 5,        // Requires 5/7 governance signatures
            TreasuryAccount::Development => 3, // Requires 3/5 dev team signatures
            TreasuryAccount::Marketing => 2,   // Requires 2/3 marketing team signatures
            TreasuryAccount::Security => 3,    // Requires 3/5 security team signatures
            TreasuryAccount::Community => 3,   // Requires 3/5 community leaders signatures
            TreasuryAccount::ValidatorRewards => 1, // Automated, no manual approval needed
            TreasuryAccount::Emergency => 6,   // Requires 6/9 emergency committee signatures
            TreasuryAccount::Custom(_) => 2,   // Default 2/3 for custom accounts
        }
    }
}

/// Types of treasury transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    /// Funds received (protocol fees, donations, etc.)
    Income {
        source: IncomeSource,
        description: String,
    },
    /// Funds spent through governance
    Expenditure {
        proposal_id: ProposalId,
        recipient: NodeId,
        purpose: String,
        category: ExpenditureCategory,
    },
    /// Transfer between treasury accounts
    Transfer {
        from_account: TreasuryAccount,
        to_account: TreasuryAccount,
        reason: String,
    },
    /// Staking rewards distribution
    StakingReward {
        recipient: NodeId,
        epoch: u64,
        performance_factor: f64,
    },
    /// Penalties and slashing
    Penalty {
        target: NodeId,
        violation_type: String,
        evidence_hash: Hash,
    },
    /// Fee collection from transactions
    FeeCollection {
        block_height: u64,
        total_fees: TokenAmount,
        fee_breakdown: HashMap<String, TokenAmount>,
    },
}

/// Sources of treasury income
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IncomeSource {
    TransactionFees,
    ProtocolFees,
    Donations,
    Partnerships,
    Grants,
    Penalties,
    Investment,
    Other(String),
}

/// Categories of expenditures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ExpenditureCategory {
    Development,
    Security,
    Marketing,
    Operations,
    Rewards,
    Grants,
    Emergency,
    Other(String),
}

/// Status of treasury transactions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionStatus {
    Pending,
    Approved,
    Executed,
    Failed { reason: String },
    Cancelled,
}

/// Treasury transaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryTransaction {
    pub id: TransactionId,
    pub transaction_type: TransactionType,
    pub account: TreasuryAccount,
    pub amount: TokenAmount,
    pub status: TransactionStatus,
    pub created_at: u64,
    pub executed_at: Option<u64>,
    pub created_by: NodeId,
    pub approved_by: Option<NodeId>,
    pub metadata: TransactionMetadata,
    pub signatures: Vec<TransactionSignature>,
}

/// Additional transaction metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMetadata {
    pub description: String,
    pub tags: Vec<String>,
    pub external_reference: Option<String>,
    pub requires_approval: bool,
    pub approval_threshold: Option<u8>,
    pub expiry: Option<u64>,
    pub priority: TransactionPriority,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionPriority {
    Low,
    Normal,
    High,
    Emergency,
}

/// Transaction signature for multi-sig approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSignature {
    pub signer: NodeId,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub approval: bool,
}

/// Treasury account state with real blockchain addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountState {
    pub account: TreasuryAccount,
    pub address: String, // Real blockchain address
    pub balance: TokenAmount,
    pub reserved: TokenAmount, // Funds allocated but not yet spent
    pub last_updated: u64,
    pub transaction_count: u64,
    pub spending_limits: SpendingLimits,
    pub authorized_signers: Vec<NodeId>, // Multisig signers for this account
    pub multisig_threshold: u8,          // Required signatures
}

/// Spending limits and controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingLimits {
    pub daily_limit: Option<TokenAmount>,
    pub monthly_limit: Option<TokenAmount>,
    pub single_transaction_limit: Option<TokenAmount>,
    pub requires_governance: TokenAmount, // Amounts above this require governance vote
    pub emergency_limit: TokenAmount,
}

impl Default for SpendingLimits {
    fn default() -> Self {
        Self {
            daily_limit: Some(1_000_000_000_000_000_000_000), // 1K tokens
            monthly_limit: Some(30_000_000_000_000_000_000_000), // 30K tokens
            single_transaction_limit: Some(10_000_000_000_000_000_000_000), // 10K tokens
            requires_governance: 100_000_000_000_000_000_000_000, // 100K tokens
            emergency_limit: 1_000_000_000_000_000_000_000_000, // 1M tokens
        }
    }
}

/// Treasury reporting period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryReport {
    pub period_start: u64,
    pub period_end: u64,
    pub account_balances: HashMap<TreasuryAccount, TokenAmount>,
    pub total_income: TokenAmount,
    pub total_expenditure: TokenAmount,
    pub net_change: i128, // Can be negative
    pub income_by_source: HashMap<IncomeSource, TokenAmount>,
    pub expenditure_by_category: HashMap<ExpenditureCategory, TokenAmount>,
    pub transaction_count: u64,
    pub largest_transactions: Vec<TransactionId>,
    pub analysis: TreasuryAnalysis,
}

/// Treasury analysis and insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryAnalysis {
    pub burn_rate: f64,             // Monthly spending rate
    pub runway_months: Option<f64>, // How long funds will last at current rate
    pub spending_trend: SpendingTrend,
    pub income_stability: f64,      // 0-1 score
    pub diversification_score: f64, // 0-1 score
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpendingTrend {
    Increasing,
    Stable,
    Decreasing,
}

/// Treasury configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryConfig {
    pub multi_sig_threshold: u8, // Number of signatures required
    pub authorized_signers: Vec<NodeId>,
    pub automatic_transfers: HashMap<TreasuryAccount, AutoTransferRule>,
    pub fee_distribution: FeeDistribution,
    pub reporting_frequency: u64, // seconds
    pub audit_frequency: u64,     // seconds
}

/// Rules for automatic transfers between accounts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTransferRule {
    pub from_account: TreasuryAccount,
    pub to_account: TreasuryAccount,
    pub trigger: TransferTrigger,
    pub amount_rule: AmountRule,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransferTrigger {
    BalanceThreshold { threshold: TokenAmount },
    PercentageThreshold { percentage: u8 },
    TimeInterval { interval: u64 },
    ExternalTrigger,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AmountRule {
    FixedAmount { amount: TokenAmount },
    Percentage { percentage: u8 },
    Excess { keep_minimum: TokenAmount },
    Formula { formula: String },
}

/// Fee distribution rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    pub validator_rewards: u8, // percentage
    pub development: u8,
    pub marketing: u8,
    pub security: u8,
    pub community: u8,
    pub treasury_main: u8,
    pub burn: u8, // percentage to burn (deflationary)
}

impl Default for FeeDistribution {
    fn default() -> Self {
        Self {
            validator_rewards: 0,
            development: 0,
            marketing: 0,
            security: 0,
            community: 0,
            treasury_main: 0,
            burn: 100, // 100% burn - completely deflationary
        }
    }
}

impl Default for TreasuryConfig {
    fn default() -> Self {
        Self {
            multi_sig_threshold: 3,
            authorized_signers: vec![],
            automatic_transfers: HashMap::new(),
            fee_distribution: FeeDistribution::default(),
            reporting_frequency: 24 * 60 * 60, // Daily reports
            audit_frequency: 7 * 24 * 60 * 60, // Weekly audits
        }
    }
}

/// Main treasury management system
#[derive(Debug)]
pub struct Treasury {
    config: TreasuryConfig,
    /// Storage backend
    storage: Arc<AvocadoStorage>,
    /// Account states and balances
    accounts: Arc<RwLock<HashMap<TreasuryAccount, AccountState>>>,
    /// All treasury transactions
    transactions: Arc<RwLock<HashMap<TransactionId, TreasuryTransaction>>>,
    /// Transaction counter for unique IDs
    transaction_counter: Arc<RwLock<TransactionId>>,
    /// Pending transactions awaiting approval
    pending_transactions: Arc<RwLock<Vec<TransactionId>>>,
    /// Historical reports
    reports: Arc<RwLock<Vec<TreasuryReport>>>,
    /// Spending tracking for limits
    spending_tracker: Arc<RwLock<HashMap<TreasuryAccount, SpendingTracker>>>,
}

/// Track spending against limits
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpendingTracker {
    daily_spent: TokenAmount,
    monthly_spent: TokenAmount,
    last_reset_day: u64,
    last_reset_month: u64,
}

impl Treasury {
    /// Create a new treasury system
    pub fn new(config: TreasuryConfig, storage: Arc<AvocadoStorage>) -> Self {
        let treasury = Self {
            config,
            storage,
            accounts: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            transaction_counter: Arc::new(RwLock::new(0)),
            pending_transactions: Arc::new(RwLock::new(Vec::new())),
            reports: Arc::new(RwLock::new(Vec::new())),
            spending_tracker: Arc::new(RwLock::new(HashMap::new())),
        };

        // Initialize default accounts
        treasury
    }

    /// Store treasury account in RocksDB
    async fn store_account(
        &self,
        account: &TreasuryAccount,
        state: &AccountState,
    ) -> Result<(), AvoError> {
        let key = format!(
            "treasury_account_{}",
            serde_json::to_string(account).map_err(|e| AvoError::StateError {
                reason: format!("Failed to serialize account key: {}", e)
            })?
        );
        let value = serde_json::to_string(state).map_err(|e| AvoError::StateError {
            reason: format!("Failed to serialize account state: {}", e),
        })?;

        self.storage.put_cf("treasury", &key, &value).await
    }

    /// Load treasury account from RocksDB
    async fn load_account(
        &self,
        account: &TreasuryAccount,
    ) -> Result<Option<AccountState>, AvoError> {
        let key = format!(
            "treasury_account_{}",
            serde_json::to_string(account).map_err(|e| AvoError::StateError {
                reason: format!("Failed to serialize account key: {}", e)
            })?
        );

        match self.storage.get_cf("treasury", &key).await? {
            Some(value) => {
                let state: AccountState =
                    serde_json::from_str(&value).map_err(|e| AvoError::StateError {
                        reason: format!("Failed to deserialize account state: {}", e),
                    })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Store treasury transaction in RocksDB
    async fn store_transaction(&self, transaction: &TreasuryTransaction) -> Result<(), AvoError> {
        let key = format!("treasury_tx_{}", transaction.id);
        let value = serde_json::to_string(transaction).map_err(|e| AvoError::StateError {
            reason: format!("Failed to serialize transaction: {}", e),
        })?;

        self.storage.put_cf("treasury", &key, &value).await
    }

    /// Load treasury transaction from RocksDB
    async fn load_transaction(
        &self,
        tx_id: &TransactionId,
    ) -> Result<Option<TreasuryTransaction>, AvoError> {
        let key = format!("treasury_tx_{}", tx_id);

        match self.storage.get_cf("treasury", &key).await? {
            Some(value) => {
                let transaction: TreasuryTransaction =
                    serde_json::from_str(&value).map_err(|e| AvoError::StateError {
                        reason: format!("Failed to deserialize transaction: {}", e),
                    })?;
                Ok(Some(transaction))
            }
            None => Ok(None),
        }
    }

    /// Store spending tracker in RocksDB
    async fn store_spending_tracker(
        &self,
        account: &TreasuryAccount,
        tracker: &SpendingTracker,
    ) -> Result<(), AvoError> {
        let key = format!(
            "treasury_spending_{}",
            serde_json::to_string(account).map_err(|e| AvoError::StateError {
                reason: format!("Failed to serialize account key: {}", e)
            })?
        );
        let value = serde_json::to_string(tracker).map_err(|e| AvoError::StateError {
            reason: format!("Failed to serialize spending tracker: {}", e),
        })?;

        self.storage.put_cf("treasury", &key, &value).await
    }

    /// Load spending tracker from RocksDB
    async fn load_spending_tracker(
        &self,
        account: &TreasuryAccount,
    ) -> Result<Option<SpendingTracker>, AvoError> {
        let key = format!(
            "treasury_spending_{}",
            serde_json::to_string(account).map_err(|e| AvoError::StateError {
                reason: format!("Failed to serialize account key: {}", e)
            })?
        );

        match self.storage.get_cf("treasury", &key).await? {
            Some(value) => {
                let tracker: SpendingTracker =
                    serde_json::from_str(&value).map_err(|e| AvoError::StateError {
                        reason: format!("Failed to deserialize spending tracker: {}", e),
                    })?;
                Ok(Some(tracker))
            }
            None => Ok(None),
        }
    }

    /// Get treasury account information including address
    pub async fn get_account_info(
        &self,
        account: &TreasuryAccount,
    ) -> Result<AccountState, AvoError> {
        // Check cache first
        {
            let accounts = self.accounts.read().await;
            if let Some(state) = accounts.get(account) {
                return Ok(state.clone());
            }
        }

        // Load from RocksDB
        if let Some(state) = self.load_account(account).await? {
            // Update cache
            {
                let mut accounts = self.accounts.write().await;
                accounts.insert(account.clone(), state.clone());
            }
            Ok(state)
        } else {
            Err(AvoError::GovernanceError("Account not found".to_string()))
        }
    }

    /// Get all treasury accounts with their addresses and balances
    pub async fn get_all_accounts(
        &self,
    ) -> Result<HashMap<TreasuryAccount, AccountState>, AvoError> {
        let accounts = self.accounts.read().await;
        Ok(accounts.clone())
    }

    /// Initialize treasury with default accounts and their designated addresses
    pub async fn initialize_default_accounts(&self) -> Result<(), AvoError> {
        let default_accounts = vec![
            TreasuryAccount::Main,
            TreasuryAccount::Development,
            TreasuryAccount::Marketing,
            TreasuryAccount::Security,
            TreasuryAccount::Community,
            TreasuryAccount::ValidatorRewards,
            TreasuryAccount::Emergency,
        ];

        for account in default_accounts {
            // Check if account already exists in RocksDB
            if self.load_account(&account).await?.is_none() {
                // Get default authorized signers for each account
                let authorized_signers = self.get_default_signers(&account);

                let account_state = AccountState {
                    address: account.get_address().to_string(),
                    account: account.clone(),
                    balance: 0,
                    reserved: 0,
                    last_updated: current_timestamp(),
                    transaction_count: 0,
                    spending_limits: SpendingLimits::default(),
                    authorized_signers,
                    multisig_threshold: account.get_multisig_threshold(),
                };

                // Store in RocksDB
                self.store_account(&account, &account_state).await?;

                // Update cache
                {
                    let mut accounts = self.accounts.write().await;
                    accounts.insert(account.clone(), account_state);
                }
            }
        }

        Ok(())
    }

    /// Get default signers for each treasury account
    fn get_default_signers(&self, account: &TreasuryAccount) -> Vec<NodeId> {
        match account {
            TreasuryAccount::Main => vec![
                "governance_council_1".to_string(),
                "governance_council_2".to_string(),
                "governance_council_3".to_string(),
                "governance_council_4".to_string(),
                "governance_council_5".to_string(),
                "governance_council_6".to_string(),
                "governance_council_7".to_string(),
            ],
            TreasuryAccount::Development => vec![
                "lead_developer_1".to_string(),
                "lead_developer_2".to_string(),
                "dev_team_lead".to_string(),
                "protocol_architect".to_string(),
                "tech_advisor".to_string(),
            ],
            TreasuryAccount::Marketing => vec![
                "marketing_director".to_string(),
                "community_manager".to_string(),
                "partnership_lead".to_string(),
            ],
            TreasuryAccount::Security => vec![
                "security_lead_1".to_string(),
                "security_lead_2".to_string(),
                "audit_coordinator".to_string(),
                "bug_bounty_manager".to_string(),
                "security_advisor".to_string(),
            ],
            TreasuryAccount::Community => vec![
                "community_lead_1".to_string(),
                "community_lead_2".to_string(),
                "ecosystem_manager".to_string(),
                "grants_committee_1".to_string(),
                "grants_committee_2".to_string(),
            ],
            TreasuryAccount::ValidatorRewards => vec!["automated_rewards_contract".to_string()],
            TreasuryAccount::Emergency => vec![
                "emergency_council_1".to_string(),
                "emergency_council_2".to_string(),
                "emergency_council_3".to_string(),
                "emergency_council_4".to_string(),
                "emergency_council_5".to_string(),
                "emergency_council_6".to_string(),
                "emergency_council_7".to_string(),
                "emergency_council_8".to_string(),
                "emergency_council_9".to_string(),
            ],
            TreasuryAccount::Custom(_) => vec![
                "custom_account_admin_1".to_string(),
                "custom_account_admin_2".to_string(),
                "custom_account_admin_3".to_string(),
            ],
        }
    }

    /// Get transaction status
    pub async fn get_transaction_status(
        &self,
        transaction_id: TransactionId,
    ) -> Result<TransactionStatus, AvoError> {
        // Check cache first
        {
            let transactions = self.transactions.read().await;
            if let Some(transaction) = transactions.get(&transaction_id) {
                return Ok(transaction.status.clone());
            }
        }

        // Load from RocksDB
        if let Some(transaction) = self.load_transaction(&transaction_id).await? {
            // Update cache
            {
                let mut transactions = self.transactions.write().await;
                transactions.insert(transaction_id, transaction.clone());
            }
            Ok(transaction.status)
        } else {
            Err(AvoError::GovernanceError(
                "Transaction not found".to_string(),
            ))
        }
    }

    /// Create a new treasury transaction
    pub async fn create_transaction(
        &self,
        transaction_type: TransactionType,
        account: TreasuryAccount,
        amount: TokenAmount,
        created_by: NodeId,
        metadata: TransactionMetadata,
    ) -> Result<TransactionId, AvoError> {
        // Generate transaction ID
        let transaction_id = {
            let mut counter = self.transaction_counter.write().await;
            *counter += 1;
            *counter
        };

        // Create transaction
        let transaction = TreasuryTransaction {
            id: transaction_id,
            transaction_type: transaction_type.clone(),
            account: account.clone(),
            amount,
            status: TransactionStatus::Pending,
            created_at: current_timestamp(),
            executed_at: None,
            created_by,
            approved_by: None,
            metadata,
            signatures: Vec::new(),
        };

        // Validate transaction
        self.validate_transaction(&transaction).await?;

        // Store transaction
        self.store_transaction(&transaction).await?;
        {
            let mut transactions = self.transactions.write().await;
            transactions.insert(transaction_id, transaction.clone());
        }

        // Add to pending queue if approval required
        if self.requires_approval(&transaction_type, amount).await? {
            let mut pending = self.pending_transactions.write().await;
            pending.push(transaction_id);
        } else {
            // Execute immediately if no approval required
            self.execute_transaction(transaction_id).await?;
        }

        Ok(transaction_id)
    }

    /// Sign a transaction for multi-sig approval
    pub async fn sign_transaction(
        &self,
        transaction_id: TransactionId,
        signer: NodeId,
        signature: Vec<u8>,
        approval: bool,
    ) -> Result<(), AvoError> {
        // Verify signer is authorized
        if !self.config.authorized_signers.contains(&signer) {
            return Err(AvoError::GovernanceError("Unauthorized signer".to_string()));
        }

        let mut transaction = {
            // Load from cache or RocksDB
            let mut transactions = self.transactions.write().await;
            if let Some(tx) = transactions.get(&transaction_id) {
                tx.clone()
            } else if let Some(tx) = self.load_transaction(&transaction_id).await? {
                transactions.insert(transaction_id, tx.clone());
                tx
            } else {
                return Err(AvoError::GovernanceError(
                    "Transaction not found".to_string(),
                ));
            }
        };

        // Check if already signed by this signer
        if transaction.signatures.iter().any(|s| s.signer == signer) {
            return Err(AvoError::GovernanceError(
                "Already signed by this signer".to_string(),
            ));
        }

        // Add signature
        let signature_record = TransactionSignature {
            signer,
            signature,
            timestamp: current_timestamp(),
            approval,
        };

        transaction.signatures.push(signature_record);

        // Check if enough signatures for approval
        let approval_count = transaction.signatures.iter().filter(|s| s.approval).count() as u8;

        if approval_count >= self.config.multi_sig_threshold {
            transaction.status = TransactionStatus::Approved;
        } else if transaction.signatures.iter().any(|s| !s.approval) {
            // If any signature is a rejection, check if it exceeds rejection threshold
            let rejection_count = transaction
                .signatures
                .iter()
                .filter(|s| !s.approval)
                .count() as u8;

            // If more than half reject, cancel transaction
            if rejection_count > self.config.authorized_signers.len() as u8 / 2 {
                transaction.status = TransactionStatus::Cancelled;
            }
        }

        // Store updated transaction in RocksDB
        self.store_transaction(&transaction).await?;

        // Update cache
        {
            let mut transactions = self.transactions.write().await;
            transactions.insert(transaction_id, transaction.clone());
        }

        // Execute if approved
        if transaction.status == TransactionStatus::Approved && approval {
            self.execute_transaction(transaction_id).await?;
        }

        Ok(())
    }

    /// Execute an approved transaction
    pub async fn execute_transaction(&self, transaction_id: TransactionId) -> Result<(), AvoError> {
        let current_time = current_timestamp();

        // Get transaction details
        let (transaction_type, account, amount) = {
            let mut transactions = self.transactions.write().await;
            let transaction = transactions
                .get_mut(&transaction_id)
                .ok_or_else(|| AvoError::GovernanceError("Transaction not found".to_string()))?;

            if transaction.status != TransactionStatus::Pending
                && transaction.status != TransactionStatus::Approved
            {
                return Err(AvoError::GovernanceError(
                    "Transaction not in executable state".to_string(),
                ));
            }

            transaction.status = TransactionStatus::Executed;
            transaction.executed_at = Some(current_time);

            (
                transaction.transaction_type.clone(),
                transaction.account.clone(),
                transaction.amount,
            )
        };

        // Execute based on transaction type
        match transaction_type {
            TransactionType::Income { .. } => {
                self.add_funds(account, amount).await?;
            }
            TransactionType::Expenditure { .. } => {
                self.spend_funds(account, amount).await?;
            }
            TransactionType::Transfer {
                from_account,
                to_account,
                ..
            } => {
                self.transfer_funds(from_account, to_account, amount)
                    .await?;
            }
            TransactionType::StakingReward { .. } => {
                // Handle staking reward distribution
                self.spend_funds(account, amount).await?;
                // Additional logic for reward distribution would go here
            }
            TransactionType::Penalty { .. } => {
                self.add_funds(account, amount).await?;
            }
            TransactionType::FeeCollection { .. } => {
                self.distribute_fees(amount).await?;
            }
        }

        // Remove from pending queue
        {
            let mut pending = self.pending_transactions.write().await;
            pending.retain(|&id| id != transaction_id);
        }

        Ok(())
    }

    /// Get account balance
    pub async fn get_balance(&self, account: &TreasuryAccount) -> Result<TokenAmount, AvoError> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(account).map(|a| a.balance).unwrap_or(0))
    }

    /// Get total treasury balance across all accounts
    pub async fn get_total_balance(&self) -> Result<TokenAmount, AvoError> {
        let accounts = self.accounts.read().await;
        let total = accounts.values().map(|a| a.balance).sum();
        Ok(total)
    }

    /// Generate treasury report for a period
    pub async fn generate_report(
        &self,
        period_start: u64,
        period_end: u64,
    ) -> Result<TreasuryReport, AvoError> {
        let transactions = self.transactions.read().await;
        let accounts = self.accounts.read().await;

        // Filter transactions for the period
        let period_transactions: Vec<&TreasuryTransaction> = transactions
            .values()
            .filter(|t| t.created_at >= period_start && t.created_at <= period_end)
            .collect();

        // Calculate totals
        let mut total_income = 0;
        let mut total_expenditure = 0;
        let mut income_by_source = HashMap::new();
        let mut expenditure_by_category = HashMap::new();

        for transaction in &period_transactions {
            match &transaction.transaction_type {
                TransactionType::Income { source, .. } => {
                    total_income += transaction.amount;
                    *income_by_source.entry(source.clone()).or_insert(0) += transaction.amount;
                }
                TransactionType::Expenditure { category, .. } => {
                    total_expenditure += transaction.amount;
                    *expenditure_by_category.entry(category.clone()).or_insert(0) +=
                        transaction.amount;
                }
                _ => {}
            }
        }

        // Get current account balances
        let account_balances: HashMap<TreasuryAccount, TokenAmount> = accounts
            .iter()
            .map(|(k, v)| (k.clone(), v.balance))
            .collect();

        // Find largest transactions
        let mut transaction_amounts: Vec<(TransactionId, TokenAmount)> = period_transactions
            .iter()
            .map(|t| (t.id, t.amount))
            .collect::<Vec<_>>();
        transaction_amounts.sort_by(|a, b| b.1.cmp(&a.1));
        let largest_transactions: Vec<TransactionId> = transaction_amounts
            .into_iter()
            .take(10)
            .map(|(id, _)| id)
            .collect();

        // Calculate analysis
        let analysis = self
            .calculate_treasury_analysis(&period_transactions, total_income, total_expenditure)
            .await?;

        let report = TreasuryReport {
            period_start,
            period_end,
            account_balances,
            total_income,
            total_expenditure,
            net_change: total_income as i128 - total_expenditure as i128,
            income_by_source,
            expenditure_by_category,
            transaction_count: period_transactions.len() as u64,
            largest_transactions,
            analysis,
        };

        // Store report
        {
            let mut reports = self.reports.write().await;
            reports.push(report.clone());
        }

        Ok(report)
    }

    /// Get transaction history
    pub async fn get_transactions(
        &self,
        account_filter: Option<TreasuryAccount>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<TreasuryTransaction>, AvoError> {
        let transactions = self.transactions.read().await;

        let mut filtered_transactions: Vec<TreasuryTransaction> = transactions
            .values()
            .filter(|t| {
                if let Some(ref account) = account_filter {
                    &t.account == account
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Sort by creation time (newest first)
        filtered_transactions.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply pagination
        let start = offset.unwrap_or(0);
        let end = if let Some(limit) = limit {
            std::cmp::min(start + limit, filtered_transactions.len())
        } else {
            filtered_transactions.len()
        };

        Ok(filtered_transactions[start..end].to_vec())
    }

    // Private helper methods

    async fn validate_transaction(
        &self,
        transaction: &TreasuryTransaction,
    ) -> Result<(), AvoError> {
        // Check spending limits
        if let TransactionType::Expenditure { .. } = transaction.transaction_type {
            self.check_spending_limits(&transaction.account, transaction.amount)
                .await?;
        }

        // Check account balance for expenditures
        if matches!(
            transaction.transaction_type,
            TransactionType::Expenditure { .. } | TransactionType::Transfer { .. }
        ) {
            let balance = self.get_balance(&transaction.account).await?;
            if balance < transaction.amount {
                return Err(AvoError::GovernanceError(
                    "Insufficient account balance".to_string(),
                ));
            }
        }

        Ok(())
    }

    async fn requires_approval(
        &self,
        transaction_type: &TransactionType,
        amount: TokenAmount,
    ) -> Result<bool, AvoError> {
        match transaction_type {
            TransactionType::Expenditure { .. } | TransactionType::Transfer { .. } => {
                // Check if amount requires governance approval
                Ok(amount >= 1_000_000_000_000_000_000_000) // 1K tokens threshold
            }
            TransactionType::Penalty { .. } => Ok(true),
            _ => Ok(false),
        }
    }

    async fn check_spending_limits(
        &self,
        account: &TreasuryAccount,
        amount: TokenAmount,
    ) -> Result<(), AvoError> {
        let accounts = self.accounts.read().await;
        if let Some(account_state) = accounts.get(account) {
            let limits = &account_state.spending_limits;

            // Check single transaction limit
            if let Some(single_limit) = limits.single_transaction_limit {
                if amount > single_limit {
                    return Err(AvoError::GovernanceError(
                        "Amount exceeds single transaction limit".to_string(),
                    ));
                }
            }

            // Check daily/monthly limits would require spending tracker implementation
        }

        Ok(())
    }

    async fn add_funds(
        &self,
        account: TreasuryAccount,
        amount: TokenAmount,
    ) -> Result<(), AvoError> {
        let mut accounts = self.accounts.write().await;
        let account_state = accounts
            .entry(account.clone())
            .or_insert_with(|| AccountState {
                address: account.get_address().to_string(),
                account: account.clone(),
                balance: 0,
                reserved: 0,
                last_updated: current_timestamp(),
                transaction_count: 0,
                spending_limits: SpendingLimits::default(),
                authorized_signers: Vec::new(),
                multisig_threshold: account.get_multisig_threshold(),
            });

        account_state.balance += amount;
        account_state.transaction_count += 1;
        account_state.last_updated = current_timestamp();

        Ok(())
    }

    async fn spend_funds(
        &self,
        account: TreasuryAccount,
        amount: TokenAmount,
    ) -> Result<(), AvoError> {
        let mut accounts = self.accounts.write().await;
        let account_state = accounts
            .get_mut(&account)
            .ok_or_else(|| AvoError::GovernanceError("Account not found".to_string()))?;

        if account_state.balance < amount {
            return Err(AvoError::GovernanceError("Insufficient funds".to_string()));
        }

        account_state.balance -= amount;
        account_state.transaction_count += 1;
        account_state.last_updated = current_timestamp();

        Ok(())
    }

    async fn transfer_funds(
        &self,
        from_account: TreasuryAccount,
        to_account: TreasuryAccount,
        amount: TokenAmount,
    ) -> Result<(), AvoError> {
        self.spend_funds(from_account, amount).await?;
        self.add_funds(to_account, amount).await?;
        Ok(())
    }

    async fn distribute_fees(&self, total_fees: TokenAmount) -> Result<(), AvoError> {
        let distribution = &self.config.fee_distribution;

        // Calculate amounts for each category
        let validator_rewards = (total_fees * distribution.validator_rewards as TokenAmount) / 100;
        let development = (total_fees * distribution.development as TokenAmount) / 100;
        let marketing = (total_fees * distribution.marketing as TokenAmount) / 100;
        let security = (total_fees * distribution.security as TokenAmount) / 100;
        let community = (total_fees * distribution.community as TokenAmount) / 100;
        let treasury_main = (total_fees * distribution.treasury_main as TokenAmount) / 100;
        // Burn amount is ignored (tokens are destroyed)

        // Distribute to accounts
        self.add_funds(TreasuryAccount::ValidatorRewards, validator_rewards)
            .await?;
        self.add_funds(TreasuryAccount::Development, development)
            .await?;
        self.add_funds(TreasuryAccount::Marketing, marketing)
            .await?;
        self.add_funds(TreasuryAccount::Security, security).await?;
        self.add_funds(TreasuryAccount::Community, community)
            .await?;
        self.add_funds(TreasuryAccount::Main, treasury_main).await?;

        Ok(())
    }

    async fn calculate_treasury_analysis(
        &self,
        _transactions: &[&TreasuryTransaction],
        total_income: TokenAmount,
        total_expenditure: TokenAmount,
    ) -> Result<TreasuryAnalysis, AvoError> {
        // Calculate burn rate (monthly spending)
        let period_days = 30.0; // Assume 30-day period for simplicity
        let burn_rate = (total_expenditure as f64) / period_days * 30.0;

        // Calculate runway
        let total_balance = self.get_total_balance().await? as f64;
        let runway_months = if burn_rate > 0.0 {
            Some(total_balance / burn_rate)
        } else {
            None
        };

        // Determine spending trend (simplified)
        let spending_trend = if total_expenditure > total_income {
            SpendingTrend::Increasing
        } else if total_expenditure == total_income {
            SpendingTrend::Stable
        } else {
            SpendingTrend::Decreasing
        };

        // Generate recommendations
        let mut recommendations = Vec::new();
        if let Some(runway) = runway_months {
            if runway < 6.0 {
                recommendations.push("Warning: Treasury runway less than 6 months".to_string());
            }
        }
        if total_expenditure > total_income * 2 {
            recommendations.push("Consider reducing expenditures or increasing income".to_string());
        }

        Ok(TreasuryAnalysis {
            burn_rate,
            runway_months,
            spending_trend,
            income_stability: 0.8,      // Placeholder
            diversification_score: 0.7, // Placeholder
            recommendations,
        })
    }
}

/// Get current timestamp in seconds since Unix epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
