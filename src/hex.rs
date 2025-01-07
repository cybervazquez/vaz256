// This is a feature-reduced implementation of Zeroize. 
// Created by the author to simplify the code and only work with necessary functions.

use std::fmt;

/// Error type for hexadecimal decoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromHexError {
    /// Invalid character encountered
    InvalidHexCharacter { c: char, index: usize },
    /// Invalid string length
    InvalidStringLength,
}

impl fmt::Display for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FromHexError::InvalidHexCharacter { c, index } => {
                write!(f, "Invalid character '{}' at position {}", c, index)
            }
            FromHexError::InvalidStringLength => write!(f, "Invalid string length"),
        }
    }
}

impl std::error::Error for FromHexError {}

/// Encode a slice of bytes as a hex string
pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    let bytes = data.as_ref();
    let mut hex = String::with_capacity(bytes.len() * 2);
    
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    
    hex
}

/// Decode a hex string into a vector of bytes
pub fn decode<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>, FromHexError> {
    let data = data.as_ref();
    
    if data.len() % 2 != 0 {
        return Err(FromHexError::InvalidStringLength);
    }

    let mut bytes = Vec::with_capacity(data.len() / 2);
    
    for chunk in data.chunks(2) {
        let high_nibble = decode_nibble(chunk[0])?;
        let low_nibble = decode_nibble(chunk[1])?;
        bytes.push((high_nibble << 4) | low_nibble);
    }
    
    Ok(bytes)
}

#[inline]
fn decode_nibble(c: u8) -> Result<u8, FromHexError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(FromHexError::InvalidHexCharacter {
            c: c as char,
            index: 0,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode() {
        assert_eq!(encode([0x42, 0x46]), "4246");
        assert_eq!(encode([0xff, 0x00, 0xab]), "ff00ab");
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("4246").unwrap(), vec![0x42, 0x46]);
        assert_eq!(decode("ff00ab").unwrap(), vec![0xff, 0x00, 0xab]);
        assert_eq!(decode("FF00AB").unwrap(), vec![0xff, 0x00, 0xab]);
    }

    #[test]
    fn test_invalid_length() {
        assert!(matches!(
            decode("0").unwrap_err(),
            FromHexError::InvalidStringLength
        ));
    }

    #[test]
    fn test_invalid_character() {
        assert!(matches!(
            decode("0g").unwrap_err(),
            FromHexError::InvalidHexCharacter { c: 'g', .. }
        ));
    }
}

