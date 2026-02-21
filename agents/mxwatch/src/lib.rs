//! MxWatch library crate.
//!
//! Exposes all internal modules so that benchmark harnesses and integration
//! tests can access parsers, detectors, configuration types, and event
//! serialization without pulling in the binary entry-point.

pub mod capture;
pub mod config;
pub mod detectors;
pub mod events;
pub mod health;
pub mod parsers;
pub mod resource;
pub mod transport;
