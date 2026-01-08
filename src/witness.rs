//! Witness generation for stateless verification.
//!
//! This module provides types and utilities for tracking all trie nodes accessed
//! during state operations. The resulting witness can be used by stateless clients
//! to verify state transitions without having the full trie.

use alloy_primitives::B256;
use alloy_trie::Nibbles;
use std::collections::HashMap;

/// Tracks all nodes accessed during trie operations.
///
/// This is used during `compute_root_with_overlay` to record every node that is
/// read from the database, enabling witness generation for stateless verification.
#[derive(Debug, Default, Clone)]
pub struct AccessTracker {
    /// Map of node hash -> (path, node RLP data)
    /// Using hash as key for deduplication
    accessed_nodes: HashMap<B256, AccessedNode>,
}

/// Represents a single accessed node with its metadata.
#[derive(Debug, Clone)]
pub struct AccessedNode {
    /// The path in the trie where this node was accessed
    pub path: Nibbles,
    /// The RLP-encoded node data
    pub data: Vec<u8>,
}

impl AccessTracker {
    /// Creates a new empty access tracker.
    pub fn new() -> Self {
        Self { accessed_nodes: HashMap::new() }
    }

    /// Creates a new access tracker with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self { accessed_nodes: HashMap::with_capacity(capacity) }
    }

    /// Records a node access.
    ///
    /// If the node has already been recorded (by hash), this is a no-op.
    /// This ensures each unique node is only stored once in the witness.
    ///
    /// # Arguments
    /// * `node_hash` - The keccak256 hash of the node's RLP encoding
    /// * `path` - The nibble path where this node was accessed
    /// * `node_data` - The RLP-encoded node data
    pub fn record(&mut self, node_hash: B256, path: Nibbles, node_data: Vec<u8>) {
        self.accessed_nodes.entry(node_hash).or_insert(AccessedNode { path, data: node_data });
    }

    /// Records a node access using raw bytes for the path.
    pub fn record_with_path_slice(&mut self, node_hash: B256, path: &[u8], node_data: Vec<u8>) {
        self.record(node_hash, Nibbles::from_nibbles_unchecked(path), node_data);
    }

    /// Returns the number of unique nodes that have been accessed.
    pub fn len(&self) -> usize {
        self.accessed_nodes.len()
    }

    /// Returns true if no nodes have been accessed.
    pub fn is_empty(&self) -> bool {
        self.accessed_nodes.is_empty()
    }

    /// Consumes the tracker and returns a [`Witness`].
    pub fn into_witness(self) -> Witness {
        Witness { nodes: self.accessed_nodes }
    }

    /// Returns an immutable reference to the accessed nodes.
    pub fn nodes(&self) -> &HashMap<B256, AccessedNode> {
        &self.accessed_nodes
    }
}

/// A witness containing all trie nodes accessed during a state operation.
///
/// The witness can be serialized and transmitted to stateless clients for
/// verification. It contains all the data needed to reconstruct the relevant
/// portions of the trie.
#[derive(Debug, Clone, Default)]
pub struct Witness {
    /// Map of node hash -> accessed node data
    pub nodes: HashMap<B256, AccessedNode>,
}

impl Witness {
    /// Creates an empty witness.
    pub fn empty() -> Self {
        Self { nodes: HashMap::new() }
    }

    /// Returns the number of nodes in the witness.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if the witness contains no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the total size of all node data in bytes.
    pub fn size_bytes(&self) -> usize {
        self.nodes.values().map(|n| n.data.len()).sum::<usize>() + self.nodes.len() * 32 // hash sizes
    }

    /// Checks if a node with the given hash exists in the witness.
    pub fn contains(&self, hash: &B256) -> bool {
        self.nodes.contains_key(hash)
    }

    /// Gets a node by its hash.
    pub fn get(&self, hash: &B256) -> Option<&AccessedNode> {
        self.nodes.get(hash)
    }

    /// Returns an iterator over all nodes in the witness.
    pub fn iter(&self) -> impl Iterator<Item = (&B256, &AccessedNode)> {
        self.nodes.iter()
    }

    /// Returns an iterator over just the node data (for compatibility with Go's Witness format).
    pub fn node_blobs(&self) -> impl Iterator<Item = &[u8]> {
        self.nodes.values().map(|n| n.data.as_slice())
    }

    /// Merges another witness into this one.
    pub fn merge(&mut self, other: Witness) {
        for (hash, node) in other.nodes {
            self.nodes.entry(hash).or_insert(node);
        }
    }

    /// Serializes the witness to bytes.
    ///
    /// Format: [count:u32][hash:32][path_len:u16][path:...][data_len:u32][data:...]...
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        // Write count
        let count = self.nodes.len() as u32;
        buffer.extend_from_slice(&count.to_le_bytes());

        // Write each node
        for (hash, node) in &self.nodes {
            // Hash (32 bytes)
            buffer.extend_from_slice(hash.as_slice());

            // Path length and path
            let path_bytes = node.path.to_vec();
            let path_len = path_bytes.len() as u16;
            buffer.extend_from_slice(&path_len.to_le_bytes());
            buffer.extend_from_slice(&path_bytes);

            // Data length and data
            let data_len = node.data.len() as u32;
            buffer.extend_from_slice(&data_len.to_le_bytes());
            buffer.extend_from_slice(&node.data);
        }

        buffer
    }

    /// Deserializes a witness from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, WitnessError> {
        if data.len() < 4 {
            return Err(WitnessError::InvalidFormat("too short for count"));
        }

        let mut offset = 0;

        // Read count
        let count = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let mut nodes = HashMap::with_capacity(count);

        for _ in 0..count {
            // Read hash
            if offset + 32 > data.len() {
                return Err(WitnessError::InvalidFormat("truncated hash"));
            }
            let hash = B256::from_slice(&data[offset..offset + 32]);
            offset += 32;

            // Read path length and path
            if offset + 2 > data.len() {
                return Err(WitnessError::InvalidFormat("truncated path length"));
            }
            let path_len =
                u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            if offset + path_len > data.len() {
                return Err(WitnessError::InvalidFormat("truncated path"));
            }
            let path = Nibbles::from_nibbles_unchecked(&data[offset..offset + path_len]);
            offset += path_len;

            // Read data length and data
            if offset + 4 > data.len() {
                return Err(WitnessError::InvalidFormat("truncated data length"));
            }
            let data_len =
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + data_len > data.len() {
                return Err(WitnessError::InvalidFormat("truncated data"));
            }
            let node_data = data[offset..offset + data_len].to_vec();
            offset += data_len;

            nodes.insert(hash, AccessedNode { path, data: node_data });
        }

        Ok(Self { nodes })
    }
}

/// Errors that can occur during witness operations.
#[derive(Debug, Clone)]
pub enum WitnessError {
    /// The witness data format is invalid.
    InvalidFormat(&'static str),
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::InvalidFormat(msg) => write!(f, "invalid witness format: {}", msg),
        }
    }
}

impl std::error::Error for WitnessError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_tracker_basic() {
        let mut tracker = AccessTracker::new();
        assert!(tracker.is_empty());

        let hash = B256::repeat_byte(0x42);
        let path = Nibbles::from_nibbles([0x1, 0x2, 0x3]);
        let data = vec![0xde, 0xad, 0xbe, 0xef];

        tracker.record(hash, path, data.clone());
        assert_eq!(tracker.len(), 1);

        // Recording same hash again should be a no-op
        tracker.record(hash, path, vec![0x00]);
        assert_eq!(tracker.len(), 1);

        // Different hash should be added
        let hash2 = B256::repeat_byte(0x43);
        tracker.record(hash2, path, vec![0x01, 0x02]);
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn test_witness_serialization() {
        let mut tracker = AccessTracker::new();

        tracker.record(
            B256::repeat_byte(0x01),
            Nibbles::from_nibbles([0x1, 0x2]),
            vec![0xaa, 0xbb],
        );
        tracker.record(
            B256::repeat_byte(0x02),
            Nibbles::from_nibbles([0x3, 0x4, 0x5]),
            vec![0xcc, 0xdd, 0xee],
        );

        let witness = tracker.into_witness();
        let serialized = witness.serialize();
        let deserialized = Witness::deserialize(&serialized).unwrap();

        assert_eq!(witness.len(), deserialized.len());
        for (hash, node) in witness.iter() {
            let other = deserialized.get(hash).unwrap();
            assert_eq!(node.path, other.path);
            assert_eq!(node.data, other.data);
        }
    }

    #[test]
    fn test_witness_merge() {
        let mut tracker1 = AccessTracker::new();
        tracker1.record(B256::repeat_byte(0x01), Nibbles::default(), vec![0x01]);

        let mut tracker2 = AccessTracker::new();
        tracker2.record(B256::repeat_byte(0x02), Nibbles::default(), vec![0x02]);

        let mut witness1 = tracker1.into_witness();
        let witness2 = tracker2.into_witness();

        witness1.merge(witness2);
        assert_eq!(witness1.len(), 2);
    }
}
