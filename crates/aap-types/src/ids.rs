//! Random local identifiers are correlation values, not session authentication.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

pub fn random_id(bytes: usize) -> Result<String, getrandom::Error> {
    let mut value = vec![0; bytes];
    getrandom::fill(&mut value)?;
    Ok(URL_SAFE_NO_PAD.encode(value))
}

/// Validate canonical unpadded base64url with the required decoded length.
pub fn valid_id(value: &str, bytes: usize) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == bytes && URL_SAFE_NO_PAD.encode(decoded) == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_identifiers_have_the_right_shape_and_do_not_repeat() {
        let first = random_id(16).unwrap();
        let second = random_id(16).unwrap();
        assert!(valid_id(&first, 16), "generated request ID is invalid");
        assert_ne!(first, second);
        assert!(valid_id(&random_id(32).unwrap(), 32));
    }

    #[test]
    fn accepts_canonical_identifiers_only() {
        assert!(
            valid_id("AAAAAAAAAAAAAAAAAAAAAA", 16),
            "valid request ID rejected"
        );
        for invalid in [
            "",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAA+",
        ] {
            assert!(
                !valid_id(invalid, 16),
                "noncanonical ID accepted: {invalid}"
            );
        }
        assert!(!valid_id("AAAAAAAAAAAAAAAAAAAAAA", 32));
    }
}
