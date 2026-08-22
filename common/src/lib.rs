//! common/src/lib.rs
#![cfg_attr(not(feature = "user"), no_std)]

pub mod rules;
pub mod telemetry;

pub use rules::*;
pub use telemetry::*;