use bytes::{Buf, BufMut};
use commonware_codec::{util::at_least, Error as CodecError, FixedSize, Read, Write};
use commonware_math::algebra::Random;
use commonware_utils::{hex, union_unique, Array, Span};
use core::{
    cmp::Ordering,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
};
use pq_mayo::{Mayo1, MayoParameter};
use rand_core::CryptoRngCore;

const SCHEME_NAME: &str = "mayo";

/// MAYO private key.
///
/// The `pq-mayo` crate stores compact signing keys as seeds and zeroizes them on drop.
pub struct PrivateKey<P: MayoParameter = Mayo1> {
    key: pq_mayo::SigningKey<P>,
}

impl<P: MayoParameter> Clone for PrivateKey<P> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
        }
    }
}

impl<P: MayoParameter> Debug for PrivateKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("variant", &P::NAME)
            .field("bytes", &"**FILTERED**")
            .finish_non_exhaustive()
    }
}

impl<P: MayoParameter> Display for PrivateKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<P: MayoParameter> PartialEq for PrivateKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.key.as_ref() == other.key.as_ref()
    }
}

impl<P: MayoParameter> Eq for PrivateKey<P> {}

impl<P: MayoParameter> crate::PrivateKey for PrivateKey<P> {}

impl<P: MayoParameter> crate::Signer for PrivateKey<P> {
    type Signature = Signature<P>;
    type PublicKey = PublicKey<P>;

    fn public_key(&self) -> Self::PublicKey {
        PublicKey::from(pq_mayo::VerifyingKey::from(&self.key))
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        let payload = union_unique(namespace, msg);
        let signature =
            signature::Signer::<pq_mayo::Signature<P>>::try_sign(&self.key, &payload)
                .expect("MAYO signing failed");
        Signature::from(signature)
    }
}

impl<P: MayoParameter> Random for PrivateKey<P> {
    fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut seed = vec![0u8; P::SK_SEED_BYTES];
        rng.fill_bytes(&mut seed);
        let keypair =
            pq_mayo::KeyPair::<P>::from_seed(&seed).expect("seed length matches parameter set");
        Self {
            key: keypair.signing_key().clone(),
        }
    }
}

impl<P: MayoParameter> Write for PrivateKey<P> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.key.as_ref());
    }
}

impl<P: MayoParameter> Read for PrivateKey<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, P::CSK_BYTES)?;
        let raw = buf.copy_to_bytes(P::CSK_BYTES);
        let key = pq_mayo::SigningKey::<P>::try_from(raw.as_ref())
            .map_err(|e| CodecError::Wrapped(SCHEME_NAME, e.into()))?;
        Ok(Self { key })
    }
}

impl<P: MayoParameter> FixedSize for PrivateKey<P> {
    const SIZE: usize = P::CSK_BYTES;
}

#[cfg(feature = "arbitrary")]
impl<P: MayoParameter> arbitrary::Arbitrary<'_> for PrivateKey<P> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use rand::{rngs::StdRng, SeedableRng};

        let mut rand = StdRng::from_seed(u.arbitrary::<[u8; 32]>()?);
        Ok(Self::random(&mut rand))
    }
}

/// MAYO public key.
pub struct PublicKey<P: MayoParameter = Mayo1> {
    raw: Vec<u8>,
    key: pq_mayo::VerifyingKey<P>,
}

impl<P: MayoParameter> Clone for PublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            key: self.key.clone(),
        }
    }
}

impl<P: MayoParameter> PartialEq for PublicKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<P: MayoParameter> Eq for PublicKey<P> {}

impl<P: MayoParameter> Hash for PublicKey<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl<P: MayoParameter> Ord for PublicKey<P> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl<P: MayoParameter> PartialOrd for PublicKey<P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: MayoParameter> crate::PublicKey for PublicKey<P> {}

impl<P: MayoParameter> crate::Verifier for PublicKey<P> {
    type Signature = Signature<P>;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        let payload = union_unique(namespace, msg);
        signature::Verifier::<pq_mayo::Signature<P>>::verify(&self.key, &payload, &sig.signature)
            .is_ok()
    }
}

impl<P: MayoParameter> Write for PublicKey<P> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.raw);
    }
}

impl<P: MayoParameter> Read for PublicKey<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, P::CPK_BYTES)?;
        let raw = buf.copy_to_bytes(P::CPK_BYTES);
        pq_mayo::VerifyingKey::<P>::try_from(raw.as_ref())
            .map(Self::from)
            .map_err(|e| CodecError::Wrapped(SCHEME_NAME, e.into()))
    }
}

impl<P: MayoParameter> FixedSize for PublicKey<P> {
    const SIZE: usize = P::CPK_BYTES;
}

impl<P: MayoParameter> Span for PublicKey<P> {}

impl<P: MayoParameter> Array for PublicKey<P> {}

impl<P: MayoParameter> AsRef<[u8]> for PublicKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl<P: MayoParameter> Deref for PublicKey<P> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl<P: MayoParameter> From<PrivateKey<P>> for PublicKey<P> {
    fn from(value: PrivateKey<P>) -> Self {
        <PrivateKey<P> as crate::Signer>::public_key(&value)
    }
}

impl<P: MayoParameter> From<pq_mayo::VerifyingKey<P>> for PublicKey<P> {
    fn from(key: pq_mayo::VerifyingKey<P>) -> Self {
        Self {
            raw: key.as_ref().to_vec(),
            key,
        }
    }
}

impl<P: MayoParameter> Debug for PublicKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl<P: MayoParameter> Display for PublicKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl<P: MayoParameter> arbitrary::Arbitrary<'_> for PublicKey<P> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer as _;
        let private_key = u.arbitrary::<PrivateKey<P>>()?;
        Ok(private_key.public_key())
    }
}

/// MAYO signature.
pub struct Signature<P: MayoParameter = Mayo1> {
    raw: Vec<u8>,
    signature: pq_mayo::Signature<P>,
    _marker: PhantomData<P>,
}

impl<P: MayoParameter> Clone for Signature<P> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            signature: self.signature.clone(),
            _marker: PhantomData,
        }
    }
}

impl<P: MayoParameter> PartialEq for Signature<P> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<P: MayoParameter> Eq for Signature<P> {}

impl<P: MayoParameter> Hash for Signature<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl<P: MayoParameter> Ord for Signature<P> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl<P: MayoParameter> PartialOrd for Signature<P> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P: MayoParameter> crate::Signature for Signature<P> {}

impl<P: MayoParameter> Write for Signature<P> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.raw);
    }
}

impl<P: MayoParameter> Read for Signature<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        at_least(buf, P::SIG_BYTES)?;
        let raw = buf.copy_to_bytes(P::SIG_BYTES);
        pq_mayo::Signature::<P>::try_from(raw.as_ref())
            .map(Self::from)
            .map_err(|e| CodecError::Wrapped(SCHEME_NAME, e.into()))
    }
}

impl<P: MayoParameter> FixedSize for Signature<P> {
    const SIZE: usize = P::SIG_BYTES;
}

impl<P: MayoParameter> Span for Signature<P> {}

impl<P: MayoParameter> Array for Signature<P> {}

impl<P: MayoParameter> AsRef<[u8]> for Signature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

impl<P: MayoParameter> Deref for Signature<P> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.raw
    }
}

impl<P: MayoParameter> From<pq_mayo::Signature<P>> for Signature<P> {
    fn from(signature: pq_mayo::Signature<P>) -> Self {
        Self {
            raw: signature.as_ref().to_vec(),
            signature,
            _marker: PhantomData,
        }
    }
}

impl<P: MayoParameter> Debug for Signature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

impl<P: MayoParameter> Display for Signature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.raw))
    }
}

#[cfg(feature = "arbitrary")]
impl<P: MayoParameter> arbitrary::Arbitrary<'_> for Signature<P> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        use crate::Signer as _;
        let private_key = u.arbitrary::<PrivateKey<P>>()?;
        let len = u.arbitrary::<usize>()? % 256;
        let message = u
            .arbitrary_iter()?
            .take(len)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(private_key.sign(&[], &message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Signer as _, Verifier as _};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::test_rng;

    fn sign_and_verify<P: MayoParameter>() {
        let signer = PrivateKey::<P>::random(&mut test_rng());
        let public_key = signer.public_key();
        let signature = signer.sign(b"test-mayo", b"hello mayo");

        assert!(public_key.verify(b"test-mayo", b"hello mayo", &signature));
        assert!(!public_key.verify(b"test-mayo", b"wrong message", &signature));
        assert!(!public_key.verify(b"wrong namespace", b"hello mayo", &signature));
    }

    fn codec_roundtrip<P: MayoParameter>() {
        let signer = PrivateKey::<P>::random(&mut test_rng());
        let public_key = signer.public_key();
        let signature = signer.sign(b"test-mayo", b"hello mayo");

        let signer_decoded = PrivateKey::<P>::decode(signer.encode()).unwrap();
        let public_key_decoded = PublicKey::<P>::decode(public_key.encode()).unwrap();
        let signature_decoded = Signature::<P>::decode(signature.encode()).unwrap();

        assert_eq!(signer, signer_decoded);
        assert_eq!(public_key, public_key_decoded);
        assert_eq!(signature, signature_decoded);
        assert!(public_key_decoded.verify(b"test-mayo", b"hello mayo", &signature_decoded));
    }

    #[test]
    fn mayo1_sign_and_verify() {
        sign_and_verify::<pq_mayo::Mayo1>();
    }

    #[test]
    fn mayo2_sign_and_verify() {
        sign_and_verify::<pq_mayo::Mayo2>();
    }

    #[test]
    fn mayo3_sign_and_verify() {
        sign_and_verify::<pq_mayo::Mayo3>();
    }

    #[test]
    fn mayo5_sign_and_verify() {
        sign_and_verify::<pq_mayo::Mayo5>();
    }

    #[test]
    fn mayo1_codec_roundtrip() {
        codec_roundtrip::<pq_mayo::Mayo1>();
    }
}
