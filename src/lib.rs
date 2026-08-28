//! Server-side DBSC (Device Bound Session Credentials) implementation.
//!
//! A framework-agnostic, memory-safe Rust port of the C library opendbsc.
//! It implements the core protocol pieces of the W3C DBSC draft:
//! structured-field headers, session instructions, proof-JWT verification
//! (ES256 / RS256 / none), session storage, and a high-level [`Manager`]
//! orchestrating the registration, refresh, and close flows.
//!
//! Web-framework integration (mapping [`ManagerResponse`] onto HTTP
//! responses) is intentionally left to the caller.

#![forbid(unsafe_code)]

pub mod error;
pub mod header;
pub mod instruction;
pub mod jwt;
pub mod manager;
pub mod session;
pub mod store;

pub use error::{Error, Result};
pub use instruction::{ScopeRule, SessionCredential, SessionInstruction, SessionScope};
pub use jwt::ProofJwt;
pub use manager::{generate_challenge, Manager, ManagerConfig, ManagerResponse};
pub use session::{Session, SessionState};
pub use store::{MemoryStore, SessionStore};
