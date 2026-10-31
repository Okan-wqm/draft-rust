//! Operating-system CSPRNG helpers.
//!
//! Every random value of the system (salts, tokens, codes, nonces, keys)
//! comes from [`getrandom`], i.e. the kernel CSPRNG. There is no user-space
//! PRNG, no seeding and no fallback: when the OS RNG fails the operation
//! fails ([`CryptoError::Rng`]).

use zeroize::Zeroizing;

use crate::CryptoError;

/// Fills `buf` with CSPRNG bytes.
pub fn fill(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::fill(buf).map_err(|_| CryptoError::Rng)
}

/// `N` CSPRNG bytes in a zeroizing buffer (for key material).
pub fn secret_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, CryptoError> {
    let mut out = Zeroizing::new([0_u8; N]);
    fill(out.as_mut_slice())?;
    Ok(out)
}

/// `N` CSPRNG bytes (for public values such as salts and nonces).
pub fn bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut out = [0_u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// A uniformly distributed integer in `0..bound` (rejection sampling, no
/// modulo bias). `bound` must be non-zero.
pub fn uniform_below(bound: u32) -> Result<u32, CryptoError> {
    if bound == 0 {
        return Err(CryptoError::Internal("uniform_below called with bound 0"));
    }
    // Largest multiple of `bound` that fits in the 2^32 sample space; draws
    // at or above it are rejected so every residue is equally likely.
    let zone = u64::from(u32::MAX) + 1 - ((u64::from(u32::MAX) + 1) % u64::from(bound));
    loop {
        let mut raw = [0_u8; 4];
        fill(&mut raw)?;
        let sample = u64::from(u32::from_le_bytes(raw));
        if sample < zone {
            // `sample % bound < bound <= u32::MAX`, the conversion cannot fail.
            return u32::try_from(sample % u64::from(bound))
                .map_err(|_| CryptoError::Internal("residue out of range"));
        }
    }
}

/// A random string of `len` characters drawn uniformly from `alphabet`
/// (ASCII only, 2..=128 distinct symbols). Used for human-readable codes such
/// as recovery codes (MFA-04).
pub fn string_from_alphabet(alphabet: &[u8], len: usize) -> Result<Zeroizing<String>, CryptoError> {
    if alphabet.len() < 2 || alphabet.len() > 128 || !alphabet.is_ascii() {
        return Err(CryptoError::Internal("invalid alphabet"));
    }
    // A repeated symbol would be drawn more often than the others.
    let mut seen = [false; 128];
    for symbol in alphabet {
        let slot = seen
            .get_mut(usize::from(*symbol))
            .ok_or(CryptoError::Internal("invalid alphabet"))?;
        if *slot {
            return Err(CryptoError::Internal("alphabet symbols must be distinct"));
        }
        *slot = true;
    }
    let bound = u32::try_from(alphabet.len()).map_err(|_| CryptoError::Internal("alphabet"))?;
    let mut out = Zeroizing::new(String::with_capacity(len));
    for _ in 0..len {
        let index = usize::try_from(uniform_below(bound)?)
            .map_err(|_| CryptoError::Internal("index out of range"))?;
        let symbol = alphabet
            .get(index)
            .copied()
            .ok_or(CryptoError::Internal("index out of range"))?;
        out.push(char::from(symbol));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_06_random_bytes_differ() {
        let a = bytes::<32>().unwrap();
        let b = bytes::<32>().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn cry_07_uniform_below_stays_in_range() {
        for bound in [1_u32, 2, 3, 10, 1_000_000, u32::MAX] {
            for _ in 0..200 {
                assert!(uniform_below(bound).unwrap() < bound);
            }
        }
        assert!(uniform_below(0).is_err());
    }

    #[test]
    fn cry_07_uniform_below_is_roughly_uniform() {
        // 10 buckets, 20 000 draws: each bucket expects 2 000; a biased
        // generator (e.g. modulo of a byte) would be far off. The bounds are
        // > 6 sigma, so the test is not flaky.
        let mut buckets = [0_u32; 10];
        for _ in 0..20_000 {
            buckets[uniform_below(10).unwrap() as usize] += 1;
        }
        for count in buckets {
            assert!((1_700..=2_300).contains(&count), "{buckets:?}");
        }
    }

    #[test]
    fn mfa_04_string_from_alphabet() {
        let s = string_from_alphabet(b"abc", 64).unwrap();
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|b| b"abc".contains(&b)));
        assert!(string_from_alphabet(b"a", 4).is_err());
        assert!(string_from_alphabet("é".as_bytes(), 4).is_err());
        assert!(
            string_from_alphabet(b"aab", 4).is_err(),
            "duplicates bias the output"
        );
    }
}
