//! ai-ida-common/src/lib.rs
//! قرارداد مشترک حافظه میان کرنل و یوزراسپیس.

#![cfg_attr(not(feature = "user"), no_std)]

pub mod rules;
pub mod telemetry;

pub use rules::*;
pub use telemetry::*;