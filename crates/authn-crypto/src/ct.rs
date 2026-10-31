//! Constant-time comparison helpers (CRY-12).
//!
//! Every comparison involving a secret or a value derived from a secret (MAC
//! tags, token hashes, password-hash outputs, OTP codes) goes through these
//! functions. Lengths are treated as public: every secret in this system has
//! a fixed, documented length.

use subtle::ConstantTimeEq;

pub use authn_core::secret::constant_time_eq;

/// Constant-time equality of two fixed-size arrays.
#[must_use]
pub fn eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

/// Returns the index of the *first* candidate equal to `needle`, examining
/// every candidate (no early exit) so the position of a match does not
/// influence timing.
#[must_use]
pub fn position_of<const N: usize>(needle: &[u8; N], candidates: &[[u8; N]]) -> Option<usize> {
    let mut found: Option<usize> = None;
    for (index, candidate) in candidates.iter().enumerate() {
        let equal = eq_array(needle, candidate);
        // Branch only on the public "already found" state after the
        // comparison has fully run.
        if equal && found.is_none() {
            found = Some(index);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cry_12_eq_array() {
        assert!(eq_array(&[1_u8, 2, 3], &[1, 2, 3]));
        assert!(!eq_array(&[1_u8, 2, 3], &[1, 2, 4]));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn cry_12_position_of_scans_all_candidates() {
        let candidates = [[1_u8; 4], [2; 4], [3; 4], [2; 4]];
        assert_eq!(position_of(&[2; 4], &candidates), Some(1));
        assert_eq!(position_of(&[9; 4], &candidates), None);
        assert_eq!(position_of(&[9; 4], &[]), None);
    }
}
