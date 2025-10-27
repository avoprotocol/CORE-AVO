//! Distributed chunk registry for Data Availability Sampling.
//!
//! This module provides an in-memory network abstraction that keeps track of
//! which peers host which encoded data chunks. While simplistic, it allows the
//! data-availability pipeline to exercise publishing, replication and sampling
//! across multiple peers without relying on the full P2P stack.

use crate::data_availability::{DataBlobId, DataChunk};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Identifier for a peer participating in data availability sharing.
pub type PeerId = String;

/// Shared, asynchronous registry that records which peers store which chunks.
#[derive(Clone, Debug)]
pub struct DistributedChunkStore {
    inner: Arc<RwLock<HashMap<PeerId, HashMap<(DataBlobId, usize), Vec<u8>>>>>,
}

impl DistributedChunkStore {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a peer in the registry. Idempotent.
    pub async fn register_peer(&self, peer_id: PeerId) {
        let mut guard = self.inner.write().await;
        guard.entry(peer_id).or_insert_with(HashMap::new);
    }

    /// Publish a single chunk for a peer.
    pub async fn publish_chunk(&self, peer_id: &PeerId, blob_id: &DataBlobId, chunk: &DataChunk) {
        let mut guard = self.inner.write().await;
        let peer_entry = guard.entry(peer_id.clone()).or_insert_with(HashMap::new);
        peer_entry.insert((blob_id.clone(), chunk.index), chunk.data.clone());
    }

    /// Publish a list of chunks for a peer in one go.
    pub async fn publish_chunks(
        &self,
        peer_id: &PeerId,
        blob_id: &DataBlobId,
        chunks: &[DataChunk],
    ) {
        let mut guard = self.inner.write().await;
        let peer_entry = guard.entry(peer_id.clone()).or_insert_with(HashMap::new);
        for chunk in chunks {
            peer_entry.insert((blob_id.clone(), chunk.index), chunk.data.clone());
        }
    }

    /// Fetch a chunk stored by a peer, if present.
    pub async fn fetch_chunk(
        &self,
        peer_id: &PeerId,
        blob_id: &DataBlobId,
        chunk_index: usize,
    ) -> Option<DataChunk> {
        let guard = self.inner.read().await;
        guard
            .get(peer_id)
            .and_then(|chunks| chunks.get(&(blob_id.clone(), chunk_index)))
            .map(|data| DataChunk::new(chunk_index, data.clone()))
    }

    /// Return the list of peers that currently advertise the requested chunk.
    pub async fn peers_with_chunk(&self, blob_id: &DataBlobId, chunk_index: usize) -> Vec<PeerId> {
        let guard = self.inner.read().await;
        guard
            .iter()
            .filter_map(|(peer_id, chunks)| {
                if chunks.contains_key(&(blob_id.clone(), chunk_index)) {
                    Some(peer_id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Enumerate registered peers.
    pub async fn peers(&self) -> Vec<PeerId> {
        let guard = self.inner.read().await;
        guard.keys().cloned().collect()
    }

    /// Remove all chunks for a given blob from a peer (useful for tests).
    pub async fn drop_blob_from_peer(&self, peer_id: &PeerId, blob_id: &DataBlobId) {
        let mut guard = self.inner.write().await;
        if let Some(chunks) = guard.get_mut(peer_id) {
            chunks.retain(|(stored_blob, _), _| stored_blob != blob_id);
        }
    }
}
