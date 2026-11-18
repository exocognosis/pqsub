//! Library half of the `pqsub` CLI: multi-agent simulation, transcript
//! rendering, test-vector generation and micro-benchmarks.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod bench;
pub mod render;
pub mod sim;
pub mod vectors;
