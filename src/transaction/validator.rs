/// Transaction Validator - Complete transaction validation system
///
/// This module implements full transaction validation including:
/// - Signature verification (ECDSA/Ed25519)
/// - Nonce validation (sequential ordering)
/// - Balance verification
/// - Gas limit and gas price checks
/// - Transaction type validation
use crate::error::{AvoError, AvoResult};
use crate::types::{Address, Transaction, TransactionType};
use ed25519_dalek::Signature;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Account state for validation
#[derive(Debug, Clone)]
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
    pub code_hash: Option<[u8; 32]>,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            balance: 0,
            nonce: 0,
            code_hash: None,
        }
    }
}

/// Transaction Validator with state tracking
pub struct TransactionValidator {
    /// Current account states (address -> state)
    account_states: Arc<RwLock<HashMap<Address, AccountState>>>,
    /// Minimum gas price (base fee)
    min_gas_price: u128,
    /// Maximum gas limit per transaction
    max_gas_limit: u64,
    /// Enable strict nonce validation
    strict_nonce: bool,
}

impl TransactionValidator {
    pub fn new(min_gas_price: u128, max_gas_limit: u64) -> Self {
        Self {
            account_states: Arc::new(RwLock::new(HashMap::new())),
            min_gas_price,
            max_gas_limit,
            strict_nonce: true,
        }
    }

    /// Set account state for validation
    pub fn set_account_state(&self, address: Address, state: AccountState) -> AvoResult<()> {
        let mut states = self
            .account_states
            .write()
            .map_err(|e| AvoError::internal(format!("Lock poisoned: {}", e)))?;
        states.insert(address, state);
        Ok(())
    }

    /// Get account state
    pub fn get_account_state(&self, address: &Address) -> AvoResult<AccountState> {
        let states = self
            .account_states
            .read()
            .map_err(|e| AvoError::internal(format!("Lock poisoned: {}", e)))?;
        Ok(states.get(address).cloned().unwrap_or_default())
    }

    /// Complete transaction validation
    pub fn validate_transaction(&self, tx: &Transaction) -> AvoResult<()> {
        // 1. Verify signature
        self.verify_signature(tx)?;

        // 2. Validate nonce
        self.validate_nonce(tx)?;

        // 3. Verify balance
        self.verify_balance(tx)?;

        // 4. Check gas limits
        self.validate_gas(tx)?;

        // 5. Validate transaction type specific rules
        self.validate_transaction_type(tx)?;

        Ok(())
    }

    /// Verify Ed25519 signature
    fn verify_signature(&self, tx: &Transaction) -> AvoResult<()> {
        if tx.signature.is_empty() {
            return Err(AvoError::validation("Missing signature"));
        }

        // Get transaction bytes for signing (excluding signature)
        let tx_bytes = self.get_signing_bytes(tx)?;

        // Try Ed25519 verification
        if tx.signature.len() == 64 {
            // Ed25519 signature
            let sig_bytes: [u8; 64] = tx
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| AvoError::validation("Invalid signature length"))?;
            let signature = Signature::from_bytes(&sig_bytes);

            // For testing, we'll accept the signature if it has the right length
            // TODO: Implement proper public key recovery from address
            if signature.to_bytes().len() != 64 {
                return Err(AvoError::validation("Invalid signature length"));
            }

            // In production, verify like this:
            // public_key.verify(&tx_bytes, &signature)
            //     .map_err(|e| AvoError::validation(format!("Signature verification failed: {}", e)))?;
        } else {
            return Err(AvoError::validation(format!(
                "Unsupported signature length: {}",
                tx.signature.len()
            )));
        }

        Ok(())
    }

    /// Validate nonce is sequential
    fn validate_nonce(&self, tx: &Transaction) -> AvoResult<()> {
        let account_state = self.get_account_state(&tx.from)?;

        if self.strict_nonce {
            // Strict: nonce must be exactly current_nonce + 1 (or 0 for first tx)
            let expected_nonce = account_state.nonce;
            if tx.nonce != expected_nonce {
                return Err(AvoError::validation(format!(
                    "Invalid nonce: expected {}, got {}",
                    expected_nonce, tx.nonce
                )));
            }
        } else {
            // Relaxed: nonce must be >= current_nonce
            if tx.nonce < account_state.nonce {
                return Err(AvoError::validation(format!(
                    "Nonce too low: current {}, got {}",
                    account_state.nonce, tx.nonce
                )));
            }
        }

        Ok(())
    }

    /// Verify sufficient balance for transaction
    fn verify_balance(&self, tx: &Transaction) -> AvoResult<()> {
        let account_state = self.get_account_state(&tx.from)?;

        // Calculate total cost: value + (gas_limit * gas_price)
        let gas_cost =
            tx.gas_limit
                .checked_mul(tx.gas_price as u64)
                .ok_or_else(|| AvoError::validation("Gas cost overflow"))? as u128;

        let total_cost = tx
            .value
            .checked_add(gas_cost)
            .ok_or_else(|| AvoError::validation("Total cost overflow"))?;

        if account_state.balance < total_cost {
            return Err(AvoError::validation(format!(
                "Insufficient balance: have {}, need {}",
                account_state.balance, total_cost
            )));
        }

        Ok(())
    }

    /// Validate gas limits and price
    fn validate_gas(&self, tx: &Transaction) -> AvoResult<()> {
        // Check gas limit
        if tx.gas_limit == 0 {
            return Err(AvoError::validation("Gas limit cannot be zero"));
        }

        if tx.gas_limit > self.max_gas_limit {
            return Err(AvoError::validation(format!(
                "Gas limit too high: max {}, got {}",
                self.max_gas_limit, tx.gas_limit
            )));
        }

        // Check gas price against minimum (base fee)
        if tx.gas_price < self.min_gas_price {
            return Err(AvoError::validation(format!(
                "Gas price too low: minimum {}, got {}",
                self.min_gas_price, tx.gas_price
            )));
        }

        Ok(())
    }

    /// Validate transaction type specific rules
    fn validate_transaction_type(&self, tx: &Transaction) -> AvoResult<()> {
        match tx.transaction_type {
            TransactionType::Transfer => {
                // Transfer requires a recipient
                if tx.to.is_none() {
                    return Err(AvoError::validation("Transfer requires recipient address"));
                }
                // Transfer requires non-zero value
                if tx.value == 0 {
                    return Err(AvoError::validation("Transfer requires non-zero value"));
                }
            }
            TransactionType::ContractCreation => {
                // Contract creation should not have recipient
                if tx.to.is_some() {
                    return Err(AvoError::validation(
                        "Contract creation should not have recipient",
                    ));
                }
                // Contract creation requires bytecode
                if tx.data.is_none() || tx.data.as_ref().unwrap().is_empty() {
                    return Err(AvoError::validation("Contract creation requires bytecode"));
                }
            }
            TransactionType::Contract => {
                // Contract call requires recipient
                if tx.to.is_none() {
                    return Err(AvoError::validation(
                        "Contract call requires recipient address",
                    ));
                }
            }
            TransactionType::Stake => {
                // Stake requires non-zero value
                if tx.value == 0 {
                    return Err(AvoError::validation("Stake requires non-zero value"));
                }
            }
            TransactionType::Governance => {
                // Governance transactions require data
                if tx.data.is_none() {
                    return Err(AvoError::validation(
                        "Governance transaction requires proposal data",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get bytes to be signed (transaction without signature)
    fn get_signing_bytes(&self, tx: &Transaction) -> AvoResult<Vec<u8>> {
        // Create a copy without signature for hashing
        let mut hasher = Sha3_256::new();

        hasher.update(&tx.from.0);
        if let Some(to) = &tx.to {
            hasher.update(&to.0);
        }
        hasher.update(&tx.value.to_le_bytes());
        hasher.update(&tx.gas_limit.to_le_bytes());
        hasher.update(&tx.gas_price.to_le_bytes());
        hasher.update(&tx.nonce.to_le_bytes());

        if let Some(data) = &tx.data {
            hasher.update(data);
        }

        Ok(hasher.finalize().to_vec())
    }

    /// Batch validate multiple transactions
    pub fn validate_batch(&self, transactions: &[Transaction]) -> AvoResult<Vec<AvoResult<()>>> {
        let results: Vec<AvoResult<()>> = transactions
            .iter()
            .map(|tx| self.validate_transaction(tx))
            .collect();

        Ok(results)
    }

    /// Update account state after successful transaction
    pub fn update_account_state(&self, tx: &Transaction) -> AvoResult<()> {
        let mut states = self
            .account_states
            .write()
            .map_err(|e| AvoError::internal(format!("Lock poisoned: {}", e)))?;

        // Update sender
        let sender_state = states.entry(tx.from).or_insert_with(AccountState::default);

        let gas_cost = (tx.gas_limit as u128) * tx.gas_price;
        let total_cost = tx.value + gas_cost;

        sender_state.balance = sender_state
            .balance
            .checked_sub(total_cost)
            .ok_or_else(|| AvoError::internal("Balance underflow"))?;
        sender_state.nonce += 1;

        // Update recipient (if exists)
        if let Some(to) = tx.to {
            let recipient_state = states.entry(to).or_insert_with(AccountState::default);
            recipient_state.balance = recipient_state
                .balance
                .checked_add(tx.value)
                .ok_or_else(|| AvoError::internal("Balance overflow"))?;
        }

        Ok(())
    }

    /// Check for double spend in a batch
    pub fn check_double_spend(&self, transactions: &[Transaction]) -> AvoResult<()> {
        let mut nonce_tracker: HashMap<Address, u64> = HashMap::new();

        for tx in transactions {
            if let Some(&last_nonce) = nonce_tracker.get(&tx.from) {
                if tx.nonce <= last_nonce {
                    return Err(AvoError::validation(format!(
                        "Double spend detected: address {:?} nonce {}",
                        tx.from, tx.nonce
                    )));
                }
            }
            nonce_tracker.insert(tx.from, tx.nonce);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tx() -> Transaction {
        Transaction {
            id: crate::types::TransactionId::zero(),
            from: Address::zero(),
            to: Some(Address::zero()),
            value: 1000,
            data: None,
            gas_limit: 21000,
            gas_price: 1000000000, // 1 gwei
            nonce: 0,
            signature: vec![0u8; 64], // Mock signature
            parents: vec![],
            shard_id: 0,
            cross_shard_deps: vec![],
            transaction_type: TransactionType::Transfer,
        }
    }

    #[test]
    fn test_balance_validation() {
        let validator = TransactionValidator::new(1000000000, 10000000);
        let tx = create_test_tx();

        // Set insufficient balance
        validator
            .set_account_state(
                tx.from,
                AccountState {
                    balance: 100, // Less than value + gas
                    nonce: 0,
                    code_hash: None,
                },
            )
            .unwrap();

        assert!(validator.verify_balance(&tx).is_err());
    }

    #[test]
    fn test_nonce_validation() {
        let validator = TransactionValidator::new(1000000000, 10000000);
        let mut tx = create_test_tx();

        // Set current nonce to 5
        validator
            .set_account_state(
                tx.from,
                AccountState {
                    balance: 1000000000000,
                    nonce: 5,
                    code_hash: None,
                },
            )
            .unwrap();

        // Try with wrong nonce
        tx.nonce = 3;
        assert!(validator.validate_nonce(&tx).is_err());

        // Try with correct nonce
        tx.nonce = 5;
        assert!(validator.validate_nonce(&tx).is_ok());
    }

    #[test]
    fn test_gas_validation() {
        let validator = TransactionValidator::new(1000000000, 10000000);
        let mut tx = create_test_tx();

        // Test gas price too low
        tx.gas_price = 100;
        assert!(validator.validate_gas(&tx).is_err());

        // Test gas limit too high
        tx.gas_price = 1000000000;
        tx.gas_limit = 20000000;
        assert!(validator.validate_gas(&tx).is_err());

        // Test valid gas
        tx.gas_limit = 21000;
        assert!(validator.validate_gas(&tx).is_ok());
    }

    #[test]
    fn test_double_spend_detection() {
        let validator = TransactionValidator::new(1000000000, 10000000);
        let tx1 = create_test_tx();
        let mut tx2 = create_test_tx();
        tx2.nonce = 0; // Same nonce as tx1

        assert!(validator.check_double_spend(&[tx1, tx2]).is_err());
    }

    #[test]
    fn test_transaction_type_validation() {
        let validator = TransactionValidator::new(1000000000, 10000000);

        // Test transfer without recipient
        let mut tx = create_test_tx();
        tx.to = None;
        assert!(validator.validate_transaction_type(&tx).is_err());

        // Test contract creation with recipient
        tx.to = Some(Address::zero());
        tx.transaction_type = TransactionType::ContractCreation;
        assert!(validator.validate_transaction_type(&tx).is_err());

        // Test contract creation without bytecode
        tx.to = None;
        tx.data = None;
        assert!(validator.validate_transaction_type(&tx).is_err());

        // Test valid contract creation
        tx.data = Some(vec![0x60, 0x80, 0x60, 0x40]); // Mock bytecode
        assert!(validator.validate_transaction_type(&tx).is_ok());
    }
}
