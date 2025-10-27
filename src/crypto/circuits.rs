/// Groth16 Circuits - Real ZK circuit implementation
///
/// This module implements real Groth16 circuits using ark-groth16 for:
/// - Balance transfer validation
/// - Cross-shard transaction verification
/// - Batch transaction aggregation
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{AvoError, AvoResult};
use crate::types::Address;

/// Circuit for balance transfer validation
#[derive(Clone)]
pub struct BalanceTransferCircuit {
    // Public inputs
    pub sender: Option<Fr>,
    pub receiver: Option<Fr>,
    pub amount: Option<Fr>,
    pub new_sender_balance: Option<Fr>,
    pub new_receiver_balance: Option<Fr>,

    // Private witness
    pub old_sender_balance: Option<Fr>,
    pub old_receiver_balance: Option<Fr>,
    pub nonce: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for BalanceTransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let sender = FpVar::new_input(cs.clone(), || {
            self.sender.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let receiver = FpVar::new_input(cs.clone(), || {
            self.receiver.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let amount = FpVar::new_input(cs.clone(), || {
            self.amount.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let new_sender_balance = FpVar::new_input(cs.clone(), || {
            self.new_sender_balance
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let new_receiver_balance = FpVar::new_input(cs.clone(), || {
            self.new_receiver_balance
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate private witness
        let old_sender_balance = FpVar::new_witness(cs.clone(), || {
            self.old_sender_balance
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let old_receiver_balance = FpVar::new_witness(cs.clone(), || {
            self.old_receiver_balance
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _nonce = FpVar::new_witness(cs.clone(), || {
            self.nonce.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: sender != receiver
        sender.is_neq(&receiver)?.enforce_equal(&Boolean::TRUE)?;

        // Constraint 2: amount > 0
        let zero = FpVar::zero();
        amount.is_neq(&zero)?.enforce_equal(&Boolean::TRUE)?;

        // Constraint 3: old_sender_balance - amount == new_sender_balance
        let computed_new_sender = &old_sender_balance - &amount;
        computed_new_sender.enforce_equal(&new_sender_balance)?;

        // Constraint 4: old_receiver_balance + amount == new_receiver_balance
        let computed_new_receiver = &old_receiver_balance + &amount;
        computed_new_receiver.enforce_equal(&new_receiver_balance)?;

        // Constraint 5: old_sender_balance >= amount (no underflow)
        old_sender_balance
            .is_cmp(&amount, std::cmp::Ordering::Greater, false)?
            .or(&old_sender_balance.is_eq(&amount)?)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

/// Circuit for cross-shard transaction
#[derive(Clone)]
pub struct CrossShardCircuit {
    // Public inputs
    pub source_shard: Option<Fr>,
    pub target_shard: Option<Fr>,
    pub sender: Option<Fr>,
    pub receiver: Option<Fr>,
    pub amount: Option<Fr>,
    pub state_root_before: Option<Fr>,
    pub state_root_after: Option<Fr>,

    // Private witness
    pub sender_balance_before: Option<Fr>,
    pub sender_balance_after: Option<Fr>,
    pub receiver_balance_before: Option<Fr>,
    pub receiver_balance_after: Option<Fr>,
    pub merkle_path: Option<Vec<Fr>>,
}

impl ConstraintSynthesizer<Fr> for CrossShardCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let source_shard = FpVar::new_input(cs.clone(), || {
            self.source_shard.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let target_shard = FpVar::new_input(cs.clone(), || {
            self.target_shard.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sender = FpVar::new_input(cs.clone(), || {
            self.sender.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let receiver = FpVar::new_input(cs.clone(), || {
            self.receiver.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let amount = FpVar::new_input(cs.clone(), || {
            self.amount.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _state_root_before = FpVar::new_input(cs.clone(), || {
            self.state_root_before
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _state_root_after = FpVar::new_input(cs.clone(), || {
            self.state_root_after
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate private witness
        let sender_balance_before = FpVar::new_witness(cs.clone(), || {
            self.sender_balance_before
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let sender_balance_after = FpVar::new_witness(cs.clone(), || {
            self.sender_balance_after
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let receiver_balance_before = FpVar::new_witness(cs.clone(), || {
            self.receiver_balance_before
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let receiver_balance_after = FpVar::new_witness(cs.clone(), || {
            self.receiver_balance_after
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint 1: source_shard != target_shard
        source_shard
            .is_neq(&target_shard)?
            .enforce_equal(&Boolean::TRUE)?;

        // Constraint 2: sender != receiver
        sender.is_neq(&receiver)?.enforce_equal(&Boolean::TRUE)?;

        // Constraint 3: amount > 0
        let zero = FpVar::zero();
        amount.is_neq(&zero)?.enforce_equal(&Boolean::TRUE)?;

        // Constraint 4: Balance updates are correct
        let computed_sender_after = &sender_balance_before - &amount;
        computed_sender_after.enforce_equal(&sender_balance_after)?;

        let computed_receiver_after = &receiver_balance_before + &amount;
        computed_receiver_after.enforce_equal(&receiver_balance_after)?;

        // Constraint 5: No underflow
        sender_balance_before
            .is_cmp(&amount, std::cmp::Ordering::Greater, false)?
            .or(&sender_balance_before.is_eq(&amount)?)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

/// Circuit for batch transaction aggregation
#[derive(Clone)]
pub struct BatchAggregationCircuit {
    // Public inputs
    pub batch_size: Option<Fr>,
    pub total_fees: Option<Fr>,
    pub state_root_before: Option<Fr>,
    pub state_root_after: Option<Fr>,

    // Private witness
    pub transaction_amounts: Option<Vec<Fr>>,
    pub transaction_fees: Option<Vec<Fr>>,
    pub sender_balances_before: Option<Vec<Fr>>,
    pub sender_balances_after: Option<Vec<Fr>>,
}

impl ConstraintSynthesizer<Fr> for BatchAggregationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate public inputs
        let batch_size = FpVar::new_input(cs.clone(), || {
            self.batch_size.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let total_fees = FpVar::new_input(cs.clone(), || {
            self.total_fees.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _state_root_before = FpVar::new_input(cs.clone(), || {
            self.state_root_before
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let _state_root_after = FpVar::new_input(cs.clone(), || {
            self.state_root_after
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate private witness
        let tx_amounts = self
            .transaction_amounts
            .ok_or(SynthesisError::AssignmentMissing)?;
        let tx_fees = self
            .transaction_fees
            .ok_or(SynthesisError::AssignmentMissing)?;
        let sender_balances_before = self
            .sender_balances_before
            .ok_or(SynthesisError::AssignmentMissing)?;
        let sender_balances_after = self
            .sender_balances_after
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Verify batch size
        let actual_size = Fr::from(tx_amounts.len() as u64);
        let batch_size_value = batch_size.value().unwrap_or(Fr::zero());
        if actual_size != batch_size_value {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Calculate total fees and verify
        let mut computed_total_fees = FpVar::zero();

        for (idx, fee_value) in tx_fees.iter().enumerate() {
            let fee = FpVar::new_witness(cs.clone(), || Ok(*fee_value))?;
            let amount = FpVar::new_witness(cs.clone(), || Ok(tx_amounts[idx]))?;
            let balance_before =
                FpVar::new_witness(cs.clone(), || Ok(sender_balances_before[idx]))?;
            let balance_after = FpVar::new_witness(cs.clone(), || Ok(sender_balances_after[idx]))?;

            // Constraint: balance_before - (amount + fee) == balance_after
            let total_deduction = &amount + &fee;
            let computed_balance_after = &balance_before - &total_deduction;
            computed_balance_after.enforce_equal(&balance_after)?;

            // Accumulate fees
            computed_total_fees = &computed_total_fees + &fee;

            // Constraint: fee > 0
            let zero = FpVar::zero();
            fee.is_neq(&zero)?.enforce_equal(&Boolean::TRUE)?;
        }

        // Verify total fees
        computed_total_fees.enforce_equal(&total_fees)?;

        Ok(())
    }
}

/// Groth16 Prover for circuits
pub struct Groth16Prover;

impl Groth16Prover {
    /// Generate proving and verification keys for balance transfer circuit
    pub fn setup_balance_transfer<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> AvoResult<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {
        let circuit = BalanceTransferCircuit {
            sender: Some(Fr::from(1u64)),
            receiver: Some(Fr::from(2u64)),
            amount: Some(Fr::from(100u64)),
            new_sender_balance: Some(Fr::from(900u64)),
            new_receiver_balance: Some(Fr::from(100u64)),
            old_sender_balance: Some(Fr::from(1000u64)),
            old_receiver_balance: Some(Fr::from(0u64)),
            nonce: Some(Fr::from(1u64)),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)
            .map_err(|e| AvoError::internal(format!("Groth16 setup failed: {}", e)))?;

        Ok((pk, vk))
    }

    /// Generate proof for balance transfer
    pub fn prove_balance_transfer<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &ProvingKey<Bls12_381>,
        circuit: BalanceTransferCircuit,
    ) -> AvoResult<Proof<Bls12_381>> {
        let proof = Groth16::<Bls12_381>::prove(pk, circuit, rng)
            .map_err(|e| AvoError::internal(format!("Proof generation failed: {}", e)))?;

        Ok(proof)
    }

    /// Verify balance transfer proof
    pub fn verify_balance_transfer(
        vk: &VerifyingKey<Bls12_381>,
        proof: &Proof<Bls12_381>,
        public_inputs: &[Fr],
    ) -> AvoResult<bool> {
        let result = Groth16::<Bls12_381>::verify(vk, public_inputs, proof)
            .map_err(|e| AvoError::internal(format!("Verification failed: {}", e)))?;

        Ok(result)
    }

    /// Setup cross-shard circuit
    pub fn setup_cross_shard<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> AvoResult<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {
        let circuit = CrossShardCircuit {
            source_shard: Some(Fr::from(0u64)),
            target_shard: Some(Fr::from(1u64)),
            sender: Some(Fr::from(100u64)),
            receiver: Some(Fr::from(200u64)),
            amount: Some(Fr::from(50u64)),
            state_root_before: Some(Fr::from(1234u64)),
            state_root_after: Some(Fr::from(5678u64)),
            sender_balance_before: Some(Fr::from(1000u64)),
            sender_balance_after: Some(Fr::from(950u64)),
            receiver_balance_before: Some(Fr::from(0u64)),
            receiver_balance_after: Some(Fr::from(50u64)),
            merkle_path: Some(vec![]),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)
            .map_err(|e| AvoError::internal(format!("Groth16 setup failed: {}", e)))?;

        Ok((pk, vk))
    }

    /// Prove cross-shard transaction
    pub fn prove_cross_shard<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &ProvingKey<Bls12_381>,
        circuit: CrossShardCircuit,
    ) -> AvoResult<Proof<Bls12_381>> {
        let proof = Groth16::<Bls12_381>::prove(pk, circuit, rng)
            .map_err(|e| AvoError::internal(format!("Proof generation failed: {}", e)))?;

        Ok(proof)
    }

    /// Verify cross-shard proof
    pub fn verify_cross_shard(
        vk: &VerifyingKey<Bls12_381>,
        proof: &Proof<Bls12_381>,
        public_inputs: &[Fr],
    ) -> AvoResult<bool> {
        let result = Groth16::<Bls12_381>::verify(vk, public_inputs, proof)
            .map_err(|e| AvoError::internal(format!("Verification failed: {}", e)))?;

        Ok(result)
    }

    /// Setup batch aggregation circuit
    pub fn setup_batch_aggregation<R: RngCore + CryptoRng>(
        rng: &mut R,
        batch_size: usize,
    ) -> AvoResult<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {
        let circuit = BatchAggregationCircuit {
            batch_size: Some(Fr::from(batch_size as u64)),
            total_fees: Some(Fr::from(10u64)),
            state_root_before: Some(Fr::from(1000u64)),
            state_root_after: Some(Fr::from(2000u64)),
            transaction_amounts: Some(vec![Fr::from(100u64); batch_size]),
            transaction_fees: Some(vec![Fr::from(10u64 / batch_size as u64); batch_size]),
            sender_balances_before: Some(vec![Fr::from(1000u64); batch_size]),
            sender_balances_after: Some(vec![Fr::from(890u64); batch_size]),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, rng)
            .map_err(|e| AvoError::internal(format!("Groth16 setup failed: {}", e)))?;

        Ok((pk, vk))
    }

    /// Prove batch aggregation
    pub fn prove_batch_aggregation<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &ProvingKey<Bls12_381>,
        circuit: BatchAggregationCircuit,
    ) -> AvoResult<Proof<Bls12_381>> {
        let proof = Groth16::<Bls12_381>::prove(pk, circuit, rng)
            .map_err(|e| AvoError::internal(format!("Proof generation failed: {}", e)))?;

        Ok(proof)
    }

    /// Verify batch aggregation proof
    pub fn verify_batch_aggregation(
        vk: &VerifyingKey<Bls12_381>,
        proof: &Proof<Bls12_381>,
        public_inputs: &[Fr],
    ) -> AvoResult<bool> {
        let result = Groth16::<Bls12_381>::verify(vk, public_inputs, proof)
            .map_err(|e| AvoError::internal(format!("Verification failed: {}", e)))?;

        Ok(result)
    }
}

/// Helper to convert address to field element
pub fn address_to_fr(address: &Address) -> Fr {
    let mut bytes = [0u8; 32];
    bytes[..20].copy_from_slice(&address.0);
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Helper to convert u64 to field element
pub fn u64_to_fr(value: u64) -> Fr {
    Fr::from(value)
}

#[cfg(all(test, feature = "run-tests"))]
mod tests {
use super::*;
use rand::{rngs::StdRng, SeedableRng};

#[test]
fn test_balance_transfer_circuit() {
let rng = &mut StdRng::seed_from_u64(0);

        // Setup
        let (pk, vk) = Groth16Prover::setup_balance_transfer(rng).unwrap();

        // Create circuit with valid transfer
        let circuit = BalanceTransferCircuit {
            sender: Some(Fr::from(1u64)),
            receiver: Some(Fr::from(2u64)),
            amount: Some(Fr::from(100u64)),
            new_sender_balance: Some(Fr::from(900u64)),
            new_receiver_balance: Some(Fr::from(100u64)),
            old_sender_balance: Some(Fr::from(1000u64)),
            old_receiver_balance: Some(Fr::from(0u64)),
            nonce: Some(Fr::from(1u64)),
        };

        // Generate proof
        let proof = Groth16Prover::prove_balance_transfer(rng, &pk, circuit.clone()).unwrap();

        // Prepare public inputs
        let public_inputs = vec![
            Fr::from(1u64),   // sender
            Fr::from(2u64),   // receiver
            Fr::from(100u64), // amount
            Fr::from(900u64), // new_sender_balance
            Fr::from(100u64), // new_receiver_balance
        ];

        // Verify
        let result = Groth16Prover::verify_balance_transfer(&vk, &proof, &public_inputs).unwrap();
        assert!(result);
    }

    #[test]
    fn test_cross_shard_circuit() {
        let rng = &mut StdRng::seed_from_u64(1);

        // Setup
        let (pk, vk) = Groth16Prover::setup_cross_shard(rng).unwrap();

        // Create circuit
        let circuit = CrossShardCircuit {
            source_shard: Some(Fr::from(0u64)),
            target_shard: Some(Fr::from(1u64)),
            sender: Some(Fr::from(100u64)),
            receiver: Some(Fr::from(200u64)),
            amount: Some(Fr::from(50u64)),
            state_root_before: Some(Fr::from(1234u64)),
            state_root_after: Some(Fr::from(5678u64)),
            sender_balance_before: Some(Fr::from(1000u64)),
            sender_balance_after: Some(Fr::from(950u64)),
            receiver_balance_before: Some(Fr::from(0u64)),
            receiver_balance_after: Some(Fr::from(50u64)),
            merkle_path: Some(vec![]),
        };

        // Generate proof
        let proof = Groth16Prover::prove_cross_shard(rng, &pk, circuit.clone()).unwrap();

        // Public inputs
        let public_inputs = vec![
            Fr::from(0u64),    // source_shard
            Fr::from(1u64),    // target_shard
            Fr::from(100u64),  // sender
            Fr::from(200u64),  // receiver
            Fr::from(50u64),   // amount
            Fr::from(1234u64), // state_root_before
            Fr::from(5678u64), // state_root_after
        ];

        // Verify
        let result = Groth16Prover::verify_cross_shard(&vk, &proof, &public_inputs).unwrap();
        assert!(result);
    }

    #[test]
    fn test_batch_aggregation_circuit() {
        let rng = &mut StdRng::seed_from_u64(2);
        let batch_size = 3;

        // Setup
        let (pk, vk) = Groth16Prover::setup_batch_aggregation(rng, batch_size).unwrap();

        // Create circuit
        let circuit = BatchAggregationCircuit {
            batch_size: Some(Fr::from(batch_size as u64)),
            total_fees: Some(Fr::from(30u64)),
            state_root_before: Some(Fr::from(1000u64)),
            state_root_after: Some(Fr::from(2000u64)),
            transaction_amounts: Some(vec![Fr::from(100u64); batch_size]),
            transaction_fees: Some(vec![Fr::from(10u64); batch_size]),
            sender_balances_before: Some(vec![Fr::from(1000u64); batch_size]),
            sender_balances_after: Some(vec![Fr::from(890u64); batch_size]),
        };

        // Generate proof
        let proof = Groth16Prover::prove_batch_aggregation(rng, &pk, circuit.clone()).unwrap();

        // Public inputs
        let public_inputs = vec![
            Fr::from(batch_size as u64), // batch_size
            Fr::from(30u64),             // total_fees
            Fr::from(1000u64),           // state_root_before
            Fr::from(2000u64),           // state_root_after
        ];

        // Verify
        let result = Groth16Prover::verify_batch_aggregation(&vk, &proof, &public_inputs).unwrap();
        assert!(result);
    }
}
