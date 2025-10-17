//! Compression utilities for tunnel data using Snappy algorithm.
//!
//! This module provides compression and decompression functions for tunnel data
//! to reduce bandwidth usage and improve performance over limited connections.

use anyhow::{Context, Result};
use log::debug;

/// Compress data using Snappy algorithm
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = snap::raw::Encoder::new();
    let compressed = encoder
        .compress_vec(data)
        .context("failed to compress data with snappy")?;
    
    debug!(
        "compressed {} bytes to {} bytes (ratio: {:.2}%)",
        data.len(),
        compressed.len(),
        (compressed.len() as f64 / data.len() as f64) * 100.0
    );
    
    Ok(compressed)
}

/// Decompress data using Snappy algorithm
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = snap::raw::Decoder::new();
    let decompressed = decoder
        .decompress_vec(data)
        .context("failed to decompress data with snappy")?;
    
    debug!(
        "decompressed {} bytes to {} bytes",
        data.len(),
        decompressed.len()
    );
    
    Ok(decompressed)
}

/// Compress data if it's worth compressing (size threshold)
/// Returns (compressed_data, was_compressed)
pub fn compress_if_worthwhile(data: &[u8], min_size: usize) -> Result<(Vec<u8>, bool)> {
    // Don't compress small packets as overhead isn't worth it
    if data.len() < min_size {
        return Ok((data.to_vec(), false));
    }
    
    let compressed = compress(data)?;
    
    // Only use compression if it actually reduces size
    if compressed.len() < data.len() {
        Ok((compressed, true))
    } else {
        Ok((data.to_vec(), false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress() {
        let original = b"Hello, World! This is a test message that should compress well because it has repetition. repetition. repetition.";
        
        let compressed = compress(original).unwrap();
        assert!(compressed.len() < original.len());
        
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(original.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_compress_if_worthwhile_small() {
        let small_data = b"Hi";
        let (result, was_compressed) = compress_if_worthwhile(small_data, 64).unwrap();
        assert!(!was_compressed);
        assert_eq!(result, small_data);
    }

    #[test]
    fn test_compress_if_worthwhile_large() {
        let large_data = vec![b'A'; 1000];
        let (result, was_compressed) = compress_if_worthwhile(&large_data, 64).unwrap();
        assert!(was_compressed);
        assert!(result.len() < large_data.len());
    }
}
