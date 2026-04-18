//! MAYO signing scheme implementation.

use super::{Mayo1, MayoParameter, PrivateKey, PublicKey, Signature as MayoSignature};
use crate::{
    certificate::{Attestation, Namespace, Scheme, Signers, Subject},
    Digest, Signer as _, Verifier as _,
};
use bytes::{Buf, BufMut};
use commonware_codec::{types::lazy::Lazy, EncodeSize, Error, Read, ReadRangeExt, Write};
use commonware_utils::{
    ordered::{Quorum, Set},
    Faults, Participant,
};

/// Generic MAYO signing scheme implementation.
#[derive(Clone, Debug)]
pub struct Generic<P: MayoParameter, N: Namespace> {
    /// Participants in the committee.
    pub participants: Set<PublicKey<P>>,
    /// Key used for generating signatures.
    pub signer: Option<(Participant, PrivateKey<P>)>,
    /// Pre-computed namespace(s) for this subject type.
    pub namespace: N,
}

impl<P: MayoParameter, N: Namespace> Generic<P, N> {
    /// Creates a new generic MAYO scheme instance.
    pub fn signer(
        namespace: &[u8],
        participants: Set<PublicKey<P>>,
        private_key: PrivateKey<P>,
    ) -> Option<Self> {
        let signer = participants
            .index(&private_key.public_key())
            .map(|index| (index, private_key))?;

        Some(Self {
            participants,
            signer: Some(signer),
            namespace: N::derive(namespace),
        })
    }

    /// Builds a verifier that can authenticate signatures without generating them.
    pub fn verifier(namespace: &[u8], participants: Set<PublicKey<P>>) -> Self {
        Self {
            participants,
            signer: None,
            namespace: N::derive(namespace),
        }
    }

    /// Returns the index of "self" in the participant set, if available.
    pub fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|(index, _)| *index)
    }

    /// Signs a subject and returns the signer index and signature.
    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = MayoSignature<P>>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;
        let signature = private_key.sign(subject.namespace(&self.namespace), &subject.message());

        Some(Attestation {
            signer: *index,
            signature: signature.into(),
        })
    }

    /// Verifies a single attestation from a signer.
    pub fn verify_attestation<'a, S, D>(
        &self,
        subject: S::Subject<'a, D>,
        attestation: &Attestation<S>,
    ) -> bool
    where
        S: Scheme<Signature = MayoSignature<P>>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let Some(public_key) = self.participants.key(attestation.signer) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        public_key.verify(
            subject.namespace(&self.namespace),
            &subject.message(),
            signature,
        )
    }

    /// Assembles a certificate from a collection of attestations.
    pub fn assemble<S, I, M>(&self, attestations: I) -> Option<Certificate<P>>
    where
        S: Scheme<Signature = MayoSignature<P>>,
        I: IntoIterator<Item = Attestation<S>>,
        M: Faults,
    {
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            if usize::from(signer) >= self.participants.len() {
                return None;
            }
            let signature = signature.get().cloned()?;
            entries.push((signer, signature));
        }
        if entries.len() < self.participants.quorum::<M>() as usize {
            return None;
        }

        entries.sort_by_key(|(signer, _)| *signer);
        let (signer, signatures): (Vec<Participant>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signer);
        let signatures = signatures.into_iter().map(Lazy::from).collect();

        Some(Certificate {
            signers,
            signatures,
        })
    }

    /// Verifies a certificate by checking each signature individually.
    pub fn verify_certificate<'a, S, D, M>(
        &self,
        subject: S::Subject<'a, D>,
        certificate: &Certificate<P>,
    ) -> bool
    where
        S: Scheme<Signature = MayoSignature<P>>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
        M: Faults,
    {
        if certificate.signers.len() != self.participants.len() {
            return false;
        }
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return false;
        }

        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };
            let Some(signature) = signature.get() else {
                return false;
            };
            if !public_key.verify(namespace, &message, signature) {
                return false;
            }
        }

        true
    }

    pub const fn is_attributable() -> bool {
        true
    }

    pub const fn is_batchable() -> bool {
        false
    }

    pub const fn certificate_codec_config(&self) -> <Certificate<P> as Read>::Cfg {
        self.participants.len()
    }

    pub const fn certificate_codec_config_unbounded() -> <Certificate<P> as Read>::Cfg {
        u32::MAX as usize
    }
}

pub struct Certificate<P: MayoParameter = Mayo1> {
    /// Bitmap of participant indices that contributed signatures.
    pub signers: Signers,
    /// MAYO signatures emitted by the respective participants ordered by signer index.
    pub signatures: Vec<Lazy<MayoSignature<P>>>,
}

impl<P: MayoParameter> Clone for Certificate<P> {
    fn clone(&self) -> Self {
        Self {
            signers: self.signers.clone(),
            signatures: self.signatures.clone(),
        }
    }
}

impl<P: MayoParameter> core::fmt::Debug for Certificate<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Certificate")
            .field("signers", &self.signers)
            .field("signatures", &self.signatures)
            .finish()
    }
}

impl<P: MayoParameter> PartialEq for Certificate<P> {
    fn eq(&self, other: &Self) -> bool {
        self.signers == other.signers && self.signatures == other.signatures
    }
}

impl<P: MayoParameter> Eq for Certificate<P> {}

impl<P: MayoParameter> core::hash::Hash for Certificate<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.signers.hash(state);
        self.signatures.hash(state);
    }
}

#[cfg(feature = "arbitrary")]
impl<P: MayoParameter> arbitrary::Arbitrary<'_> for Certificate<P> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let signers = Signers::arbitrary(u)?;
        let signatures = (0..signers.count())
            .map(|_| u.arbitrary::<MayoSignature<P>>().map(Lazy::from))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            signers,
            signatures,
        })
    }
}

impl<P: MayoParameter> Write for Certificate<P> {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signatures.write(writer);
    }
}

impl<P: MayoParameter> EncodeSize for Certificate<P> {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signatures.encode_size()
    }
}

impl<P: MayoParameter> Read for Certificate<P> {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, Error> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(Error::Invalid(
                "cryptography::mayo::certificate::Certificate",
                "Certificate contains no signers",
            ));
        }

        let signatures = Vec::<Lazy<MayoSignature<P>>>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(Error::Invalid(
                "cryptography::mayo::certificate::Certificate",
                "Signers and signatures counts differ",
            ));
        }

        Ok(Self {
            signers,
            signatures,
        })
    }
}

/// Generates a MAYO signing scheme wrapper for a specific protocol.
#[macro_export]
macro_rules! impl_certificate_mayo {
    ($subject:ty, $namespace:ty) => {
        /// MAYO signing scheme wrapper.
        pub struct Scheme<P: $crate::mayo::MayoParameter = $crate::mayo::Mayo1> {
            generic: $crate::mayo::certificate::Generic<P, $namespace>,
        }

        impl<P: $crate::mayo::MayoParameter> Clone for Scheme<P> {
            fn clone(&self) -> Self {
                Self {
                    generic: self.generic.clone(),
                }
            }
        }

        impl<P: $crate::mayo::MayoParameter> core::fmt::Debug for Scheme<P> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("Scheme").finish_non_exhaustive()
            }
        }

        impl<P: $crate::mayo::MayoParameter> Scheme<P> {
            /// Creates a new scheme instance with the provided key material.
            pub fn signer(
                namespace: &[u8],
                participants: commonware_utils::ordered::Set<$crate::mayo::PublicKey<P>>,
                private_key: $crate::mayo::PrivateKey<P>,
            ) -> Option<Self> {
                Some(Self {
                    generic: $crate::mayo::certificate::Generic::signer(
                        namespace,
                        participants,
                        private_key,
                    )?,
                })
            }

            /// Builds a verifier that can authenticate signatures without generating them.
            pub fn verifier(
                namespace: &[u8],
                participants: commonware_utils::ordered::Set<$crate::mayo::PublicKey<P>>,
            ) -> Self {
                Self {
                    generic: $crate::mayo::certificate::Generic::verifier(
                        namespace,
                        participants,
                    ),
                }
            }
        }

        impl<P: $crate::mayo::MayoParameter> $crate::certificate::Scheme for Scheme<P> {
            type Subject<'a, D: $crate::Digest> = $subject;
            type PublicKey = $crate::mayo::PublicKey<P>;
            type Signature = $crate::mayo::Signature<P>;
            type Certificate = $crate::mayo::certificate::Certificate<P>;

            fn me(&self) -> Option<commonware_utils::Participant> {
                self.generic.me()
            }

            fn participants(&self) -> &commonware_utils::ordered::Set<Self::PublicKey> {
                &self.generic.participants
            }

            fn sign<D: $crate::Digest>(
                &self,
                subject: Self::Subject<'_, D>,
            ) -> Option<$crate::certificate::Attestation<Self>> {
                self.generic.sign::<Self, D>(subject)
            }

            fn verify_attestation<R, D>(
                &self,
                _rng: &mut R,
                subject: Self::Subject<'_, D>,
                attestation: &$crate::certificate::Attestation<Self>,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRngCore,
                D: $crate::Digest,
            {
                self.generic
                    .verify_attestation::<Self, D>(subject, attestation)
            }

            fn assemble<I, M>(
                &self,
                attestations: I,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> Option<Self::Certificate>
            where
                I: IntoIterator<Item = $crate::certificate::Attestation<Self>>,
                M: commonware_utils::Faults,
            {
                self.generic.assemble::<Self, _, M>(attestations)
            }

            fn verify_certificate<R, D, M>(
                &self,
                _rng: &mut R,
                subject: Self::Subject<'_, D>,
                certificate: &Self::Certificate,
                _strategy: &impl commonware_parallel::Strategy,
            ) -> bool
            where
                R: rand_core::CryptoRngCore,
                D: $crate::Digest,
                M: commonware_utils::Faults,
            {
                self.generic
                    .verify_certificate::<Self, D, M>(subject, certificate)
            }

            fn is_attributable() -> bool {
                $crate::mayo::certificate::Generic::<P, $namespace>::is_attributable()
            }

            fn is_batchable() -> bool {
                $crate::mayo::certificate::Generic::<P, $namespace>::is_batchable()
            }

            fn certificate_codec_config(
                &self,
            ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                self.generic.certificate_codec_config()
            }

            fn certificate_codec_config_unbounded(
            ) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                $crate::mayo::certificate::Generic::<P, $namespace>::certificate_codec_config_unbounded()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{certificate::Scheme as _, sha256::Digest as Sha256Digest};
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Set, test_rng, Faults, N3f1, TryCollect};
    use rand_core::CryptoRngCore;

    const NAMESPACE: &[u8] = b"test-mayo";
    const MESSAGE: &[u8] = b"test message";

    #[derive(Clone, Debug)]
    pub struct TestSubject {
        pub message: Bytes,
    }

    impl Subject for TestSubject {
        type Namespace = Vec<u8>;

        fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
            derived.as_ref()
        }

        fn message(&self) -> Bytes {
            self.message.clone()
        }
    }

    impl_certificate_mayo!(TestSubject, Vec<u8>);

    fn setup_signers<P: MayoParameter>(
        rng: &mut impl CryptoRngCore,
        n: u32,
    ) -> (Vec<Scheme<P>>, Scheme<P>) {
        let private_keys: Vec<_> = (0..n)
            .map(|_| PrivateKey::<P>::random(&mut *rng))
            .collect();
        let participants: Set<PublicKey<P>> = private_keys
            .iter()
            .map(|sk| sk.public_key())
            .try_collect()
            .unwrap();

        let signers = private_keys
            .into_iter()
            .map(|sk| Scheme::signer(NAMESPACE, participants.clone(), sk).unwrap())
            .collect();

        let verifier = Scheme::verifier(NAMESPACE, participants);

        (signers, verifier)
    }

    #[test]
    fn test_is_attributable() {
        assert!(Generic::<Mayo1, Vec<u8>>::is_attributable());
        assert!(Scheme::<Mayo1>::is_attributable());
    }

    #[test]
    fn test_is_not_batchable() {
        assert!(!Generic::<Mayo1, Vec<u8>>::is_batchable());
        assert!(!Scheme::<Mayo1>::is_batchable());
    }

    #[test]
    fn test_sign_vote_roundtrip() {
        let mut rng = test_rng();
        let (schemes, _) = setup_signers::<Mayo1>(&mut rng, 4);
        let scheme = &schemes[0];

        let attestation = scheme
            .sign::<Sha256Digest>(TestSubject {
                message: Bytes::from_static(MESSAGE),
            })
            .unwrap();
        assert!(scheme.verify_attestation::<_, Sha256Digest>(
            &mut rng,
            TestSubject {
                message: Bytes::from_static(MESSAGE),
            },
            &attestation,
            &Sequential,
        ));
    }

    #[test]
    fn test_certificate_roundtrip() {
        let mut rng = test_rng();
        let (schemes, verifier) = setup_signers::<Mayo1>(&mut rng, 4);
        let quorum = N3f1::quorum(schemes.len()) as usize;

        let subject = TestSubject {
            message: Bytes::from_static(MESSAGE),
        };
        let attestations: Vec<_> = schemes
            .iter()
            .take(quorum)
            .map(|s| s.sign::<Sha256Digest>(subject.clone()).unwrap())
            .collect();

        let certificate = verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            subject.clone(),
            &certificate,
            &Sequential,
        ));

        let encoded = certificate.encode();
        let decoded = Certificate::<Mayo1>::decode_cfg(
            encoded,
            &verifier.certificate_codec_config(),
        )
        .unwrap();
        assert_eq!(certificate, decoded);
    }
}
