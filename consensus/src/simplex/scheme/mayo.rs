//! MAYO implementation of the [`Scheme`] trait for `simplex`.
//!
//! [`Scheme`] is attributable: individual signatures can be presented as
//! evidence of validator activity or faults. Certificates contain signer
//! indices alongside individual MAYO signatures.

use crate::simplex::{scheme::Namespace, types::Subject};
use commonware_cryptography::impl_certificate_mayo;

impl_certificate_mayo!(Subject<'a, D>, Namespace);
