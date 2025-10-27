use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Benchmark-specific Hash type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BenchmarkHash([u8; 32]);

impl BenchmarkHash {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        Self(hasher.finalize().into())
    }

    pub fn zero() -> Self {
        Self([0; 32])
    }
}

impl Default for BenchmarkHash {
    fn default() -> Self {
        Self::zero()
    }
}

/// Benchmark-specific Address type  
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BenchmarkAddress([u8; 20]);

impl BenchmarkAddress {
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[..20]);
        Self(addr)
    }

    pub fn zero() -> Self {
        Self([0; 20])
    }
}

impl Default for BenchmarkAddress {
    fn default() -> Self {
        Self::zero()
    }
}

/// Benchmark-specific Signature type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSignature(pub Vec<u8>);

impl BenchmarkSignature {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn empty() -> Self {
        Self(Vec::new())
    }
}

impl Default for BenchmarkSignature {
    fn default() -> Self {
        Self::empty()
    }
}

/// Benchmark-specific Transaction type for batch processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkTransaction {
    pub hash: BenchmarkHash,
    pub from: BenchmarkAddress,
    pub to: BenchmarkAddress,
    pub amount: u64,
    pub nonce: u64,
    pub signature: BenchmarkSignature,
    pub timestamp: u64,
}

impl BenchmarkTransaction {
    pub fn new(
        from: BenchmarkAddress,
        to: BenchmarkAddress,
        amount: u64,
        nonce: u64,
        signature: BenchmarkSignature,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hash_data = format!("{:?}{:?}{}{}{}", from, to, amount, nonce, timestamp);
        let hash = BenchmarkHash::from_bytes(hash_data.as_bytes());

        Self {
            hash,
            from,
            to,
            amount,
            nonce,
            signature,
            timestamp,
        }
    }
}
