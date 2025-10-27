// Transaction module - Complete transaction validation and processing
//
// This module provides complete transaction validation including:
// - Signature verification (ECDSA/Ed25519)
// - Nonce validation
// - Balance verification
// - Gas limit checks

pub mod validator;

pub use validator::TransactionValidator;
