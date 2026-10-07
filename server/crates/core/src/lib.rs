//! p2pnas performance core: chunking, gated compression, AES-256-GCM (aws-lc-rs),
//! SIMD Reed-Solomon, and a data-parallel upload pipeline.
//!
//! This crate is the successor to ptopnas-core, reworked for throughput
//! (see `pipeline`) without weakening the security model (see `crypto`).

pub mod chunker;
pub mod crypto;
pub mod erasure;
pub mod error;
pub mod pipeline;

pub use error::CoreError;
