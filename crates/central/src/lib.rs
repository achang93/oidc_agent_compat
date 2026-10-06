//! Library crate for the central proxy, exposing modules for integration tests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod admin;
pub mod audit;
pub mod crypto;
pub mod db;
pub mod device_store;
pub mod entity;
pub mod mcp;
pub mod migration;
pub mod oidc_bootstrap;
pub mod optimizer;
pub mod policy;
pub mod pricing;
pub mod provider;
pub mod proxy;
pub mod token_store;
pub mod usage;
