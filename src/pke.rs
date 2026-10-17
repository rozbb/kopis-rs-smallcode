//! This file implements the IND-CPA-secure Kopis PKE scheme

use crate::{
    arithmetic::{Matrix, RingElem},
    consts::{DOMSEP_KGEXPAND, DOMSEP_PKHASH, MAX_L, MAX_T},
    gen::{gen_matrix_from_seed, gen_secret_from_seed},
    ser::deserialize,
    turboshake256_hash,
};

use turboshake::digest::{ExtendableOutput, Update, XofReader};
use turboshake::CTurboShake256;

/// A secret key for the IND-CPA-secure Kopis PKE scheme (expanded form)
pub(crate) struct PkeSecretKey<const L: usize>(Matrix<L, 1>);

/// A public key for the IND-CPA-secure Kopis PKE scheme
#[derive(Clone)]
pub struct PkePublicKey<const L: usize> {
    matrix_seed: [u8; 32],
    vec: Matrix<L, 1>,
}

impl<const L: usize> PkePublicKey<L> {
    pub const SERIALIZED_LEN: usize = 256 * L * 10 / 8 + 32;

    /// Serializes this public key to a byte string. `out_buf` MUST have length SERIALIZED_LEN
    pub(crate) fn serialize(&self, out_buf: &mut [u8]) {
        let out_size = Self::SERIALIZED_LEN;
        assert_eq!(out_buf.len(), out_size);

        // Write out the LWR sample, then the seed
        self.vec.serialize(&mut out_buf[..out_size - 32], 10);
        // Write out the pubkey seed
        out_buf[out_size - 32..].copy_from_slice(&self.matrix_seed);
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SERIALIZED_LEN);

        let (vec_bytes, seed) = bytes.split_at(Self::SERIALIZED_LEN - 32);
        let vec = Matrix::from_bytes(vec_bytes, 10);
        Self {
            matrix_seed: seed.try_into().expect("split_at(N-32).1 has len 32"),
            vec,
        }
    }

    /// Returns the public key hash
    // From the spec:
    // let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)
    pub(crate) fn hash(&self) -> [u8; 32] {
        let mut buf = [0u8; max_pke_pubkey_serialized_len()];
        let pk_slice = &mut buf[..PkePublicKey::<L>::SERIALIZED_LEN];
        self.serialize(pk_slice);
        turboshake256_hash::<DOMSEP_PKHASH>(&[pk_slice])
    }
}

/// The maximum length of a serialized public key, for all parameter choices
pub(crate) const fn max_pke_pubkey_serialized_len() -> usize {
    256 * MAX_L * 10 / 8 + 32
}

/// The length of a ciphertext (PKE or KEM, since they're the same) for a given parameter choice,
/// for a message that is 32-bytes.
pub const fn ciphertext_len<const L: usize, const T: usize>() -> usize {
    256 * T / 8 + 256 * L * 10 / 8
}

/// The maximum length of a ciphertext (PKE or KEM, since they're the same), for all parameter
/// choices, for a message that is 32-bytes.
pub const fn max_ciphertext_len() -> usize {
    ciphertext_len::<MAX_L, MAX_T>()
}

/// Expands a 32-byte secret key into the full decapsulation key components.
///
/// Returns (vec_s, z, pk, pkh) where:
/// - vec_s is the secret vector (as PkeSecretKey)
/// - z is 32 bytes used for rejection in decapsulation
/// - pk is the public key
/// - pkh is the hash of the public key
// From the spec:
// fn ExpandSecretKey(
//   sk: [u8; 32]
// ) -> (VecR13, [u8; 32], [u8; PK_SIZE], [u8; 32]):
//   let randomness = TurboSHAKE256(sk || (ℓ as u8), 96, DOMSEP_KGEXPAND)
//   let mat_seed = randomness[..32]
//   let secret_seed = randomness[32..64]
//   let z = randomness[64..]
//
//   let mat_A = GenMat(mat_seed)
//   let vec_s = GenSecret(secret_seed)
//   let vec_b = CompressToR10(transpose(mat_A) * vec_s)
//   let pk = serialize_vec(10, vec_b) || mat_seed
//   let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)
//
//   return (vec_s, z, pk, pkh)
pub(crate) fn expand_secret_key<const L: usize, const MU: usize>(
    sk: &[u8; 32],
) -> (PkeSecretKey<L>, [u8; 32], PkePublicKey<L>, [u8; 32]) {
    // mat_seed || secret_seed || r = TurboSHAKE256(sk || L, 96, DOMSEP_KGEXPAND)
    let mut mat_seed = [0u8; 32];
    let mut secret_seed = [0u8; 32];
    let mut z = [0u8; 32];

    let mut xof = {
        let mut hasher = CTurboShake256::<DOMSEP_KGEXPAND>::default();
        hasher.update(sk);
        hasher.update(&[L as u8]);
        hasher.finalize_xof()
    };
    xof.read(&mut mat_seed);
    xof.read(&mut secret_seed);
    xof.read(&mut z);

    let mat_a = gen_matrix_from_seed::<L>(&mat_seed);
    let vec_s = gen_secret_from_seed::<L, MU>(&secret_seed);

    let vec_b = {
        let mut prod = mat_a.mul_transpose(&vec_s);
        prod.wrapping_add_to_all(4);
        prod.shift_right(3);
        prod
    };

    let pk = PkePublicKey {
        matrix_seed: mat_seed,
        vec: vec_b,
    };
    let pkh = pk.hash();

    (PkeSecretKey(vec_s), z, pk, pkh)
}

/// Decrypts a ciphertext using the given secret key. `ciphertext` MUST have length
/// `ciphertext_len::<L, T>()`.
// From the spec:
// fn PkeDecrypt(sk: [u8; 32], ct: [u8; CT_SIZE]) -> [u8; 32]:
//   let (vec_s, ...) = ExpandSecretKey(sk)
//   let vec_bprime = deserialize_vec(10, ct[..256*ℓ*10/8])
//   let cm = deserialize_elem(t, ct[256*ℓ*10/8..])
//   let v = transpose(vec_bprime) * (vec_s as VecR10)
//   let cm10 = (cm as R10) << (10 - t)
//   let mprime = DecodeMsg(v - cm10)
//   return serialize_elem(1, mprime)
pub(crate) fn decrypt<const L: usize, const T: usize>(sk: &PkeSecretKey<L>, ct: &[u8]) -> [u8; 32] {
    assert_eq!(ct.len(), ciphertext_len::<L, T>());
    let (bprime_bytes, cm_bytes) = ct.split_at(256 * L * 10 / 8);

    let vec_s = &sk.0;
    let vec_bprime: Matrix<L, 1> = Matrix::from_bytes(bprime_bytes, 10);
    let mut cm = RingElem::from_bytes(cm_bytes, T);
    let v = vec_bprime.mul_transpose(vec_s).into();

    cm.shift_left(10 - T);
    let cm10 = cm;

    let mprime = decode_msg::<T>(&v - &cm10);

    let mut m = [0u8; 32];
    mprime.serialize(&mut m, 1);
    m
}

/// Encrypts a message with a given public key and randomness (`coins`).
/// `out_buf` MUST have length `ciphertext_len::<L, T>()`.
// From the spec:
// fn PkeEncrypt(
//   randomness: [u8; 32],
//   pk: [u8; PK_SIZE],
//   msg: [u8; 32]
// ) -> [u8; CT_SIZE]:
//   let vec_b = deserialize_vec(10, pk[..256*ℓ*10/8])
//   let mat_seed = pk[256*ℓ*10/8..]
//   let m = deserialize_elem(1, msg)
//
//   let mat_A = GenMat(mat_seed)
//   let vec_sprime = GenSecret(randomness)
//   let vec_bprime = CompressToR10(mat_A * vec_sprime)
//   let vprime = transpose(vec_b) * (vec_sprime as VecR10)
//   let cm = CompressToRt(vprime - ((m as R10) << 9))
//
//   let ct = serialize_vec(10, vec_bprime) || serialize_elem(t, cm)
//   return ct
pub(crate) fn encrypt_deterministic<const L: usize, const MU: usize, const T: usize>(
    randomness: &[u8; 32],
    pk: &PkePublicKey<L>,
    msg: &[u8; 32],
    out_buf: &mut [u8],
) {
    assert_eq!(out_buf.len(), ciphertext_len::<L, T>());

    let vec_b = &pk.vec;
    let mat_seed = &pk.matrix_seed;
    let mut m = RingElem(deserialize(msg, 1));

    let mat_a = gen_matrix_from_seed::<L>(&mat_seed);
    let vec_sprime = gen_secret_from_seed::<L, MU>(randomness);
    let vec_bprime = compress_to_r10(mat_a.mul(&vec_sprime));
    let vprime = vec_b.mul_transpose(&vec_sprime).into();

    m.shift_left(9);
    let cm = compress_to_rt::<T>(&vprime - &m);

    let (bprime_buf, cm_buf) = out_buf.split_at_mut(256 * L * 10 / 8);
    vec_bprime.serialize(bprime_buf, 10);
    cm.serialize(cm_buf, T);
}

// From the spec:
// fn CompressToR10(v: VecR13) -> VecR10:
//   let h1 = make_r13([4u13; 256])
//   let h = make_vec13([h1; ℓ])
//   let s = (v + h) >> 3
//   return (s as VecR10)
#[inline(always)]
fn compress_to_rt<const T: usize>(mut r: RingElem) -> RingElem {
    r.wrapping_add_to_all(4);
    r.shift_right(10 - T);
    r
}

// From the spec:
// fn CompressToRt(r: R10) -> Rt:
//   let h1 = make_r10([4u10; 256])
//   let s = (r + h1) >> (10 - t)
//   return (s as Rt)
#[inline(always)]
fn compress_to_r10<const L: usize>(mut v: Matrix<L, 1>) -> Matrix<L, 1> {
    v.wrapping_add_to_all(4);
    v.shift_right(3);
    v
}

// From the spec:
// fn DecodeMsg(r: R10) -> R1:
//   let h2 = make_r10([2^8 - 2^(10-t-1) + 4; 256])
//   let s = (r + h2) >> 9
//   return (s as R1)
#[inline(always)]
fn decode_msg<const T: usize>(mut r: RingElem) -> RingElem {
    let h2_val = (1 << 8) - (1 << (10 - T - 1)) + 4;
    r.wrapping_add_to_all(h2_val);
    r.shift_right(9);
    r
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::consts::*;

    use rand::RngCore;

    // Tests that Decrypt(Encrypt(m)) == m
    #[test]
    fn encryption_correctness() {
        test_enc_dec::<KOPIS512_L, KOPIS512_T, KOPIS512_MU>();
        test_enc_dec::<KOPIS768_L, KOPIS768_T, KOPIS768_MU>();
        test_enc_dec::<KOPIS1024_L, KOPIS1024_T, KOPIS1024_MU>();
    }

    // Helper function that encrypts and decrypts a random 32-byte message
    fn test_enc_dec<const L: usize, const T: usize, const MU: usize>() {
        let mut rng = rand::rng();
        let mut backing_buf = [0u8; MAX_T * 256 / 8 + MAX_L * 10 * 256 / 8];

        for _ in 0..100 {
            // Generate a random secret key seed and expand it
            let mut sk_seed = [0u8; 32];
            rng.fill_bytes(&mut sk_seed);
            let (sk, _, pk, _) = expand_secret_key::<L, MU>(&sk_seed);

            let mut enc_seed = [0u8; 32];
            let mut msg = [0u8; 32];
            rng.fill_bytes(&mut enc_seed);
            rng.fill_bytes(&mut msg);
            let ct_buf = &mut backing_buf[..ciphertext_len::<L, T>()];

            encrypt_deterministic::<L, MU, T>(&enc_seed, &pk, &msg, ct_buf);
            let recovered_msg = decrypt::<L, T>(&sk, ct_buf);
            assert_eq!(msg, recovered_msg);
        }
    }
}
