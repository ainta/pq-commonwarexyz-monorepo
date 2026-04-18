//! MAYO implementation of the [crate::Verifier] and [crate::Signer] traits.
//!
//! MAYO is a post-quantum multivariate signature scheme in the NIST additional
//! signatures process. This module wraps the `pq-mayo` implementation behind
//! Commonware's signing and certificate traits.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{mayo, PrivateKey, PublicKey, Verifier as _, Signer as _};
//! use commonware_math::algebra::Random;
//! use rand::rngs::OsRng;
//!
//! let signer = mayo::PrivateKey::<mayo::Mayo1>::random(&mut OsRng);
//! let namespace = b"demo";
//! let msg = b"hello, world!";
//! let signature = signer.sign(namespace, msg);
//!
//! assert!(signer.public_key().verify(namespace, msg, &signature));
//! ```

pub mod certificate;
mod scheme;

pub use pq_mayo::{Mayo1, Mayo2, Mayo3, Mayo5, MayoParameter};
pub use scheme::{PrivateKey, PublicKey, Signature};
