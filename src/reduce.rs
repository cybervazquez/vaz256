// This module was originally derived from CRYSTALS-Dilithium
// Source: https://github.com/Quantum-Blockchains/dilithium
// Which itself was ported from: https://github.com/pq-crystals/dilithium
// Original implementation by: Quantum Blockchains (https://www.quantumblockchains.io/)
// 
// Modified for use in VAZ256™
// Copyright (C) 2025 Fran Luis Vazquez Alonso
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Changes made to the original code:
// - Extracted and adapted only Dilithium5 implementation
//
// Note: This implementation specifically uses only the Dilithium5 variant
// from the original CRYSTALS-Dilithium implementation for use in VAZ256™
// signature scheme.


pub const Q_INV: i32 = 58728449; // q^(-1) mod 2^32

/// For integer a with -2^{31} * Q <= a <= 2^31 * Q,
/// compute r \equiv 2^{-32} * a (mod Q) such that -Q < r < Q.
///
/// Returns r.
pub fn montgomery_reduce(a: i64) -> i32 {
    let mut t = (a as i32).wrapping_mul(Q_INV) as i64;
    t = (a as i64 - t.wrapping_mul(crate::params_dilithium5::Q as i64)) >> 32;
    t as i32
}

/// For finite field element a with a <= 2^{31} - 2^{22} - 1,
/// compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
//
/// Returns r.
pub fn reduce32(a: i32) -> i32 {
    let mut t = (a + (1 << 22)) >> 23;
    t = a - t.wrapping_mul(crate::params_dilithium5::Q);
    t
}

/// Add Q if input coefficient is negative.
///
/// Returns r.
pub fn caddq(a: i32) -> i32 {
    // In C right-shift of negative signed integers is implementation-defined, so C reference implementation contains bug.
    // In Rust if a < 0 right-shift is defined to fill with 1s, 0s otherwise, so we're bug free here.
    a + ((a >> 31) & crate::params_dilithium5::Q)
}

#[cfg(test)]
mod tests {
    #[test]
    fn montgomery_reduce() {
        let result = super::montgomery_reduce(0);
        assert_eq!(result, 0);
        let result = super::montgomery_reduce(23);
        assert_eq!(result, -2635616);
    }
    #[test]
    fn reduce32() {
        let result = super::reduce32(0);
        assert_eq!(result, 0);
    }
    #[test]
    fn caddq() {
        let result = super::caddq(0);
        assert_eq!(result, 0);
        let result = super::caddq(44);
        assert_eq!(result, 44);
        let result = super::caddq(-123);
        assert_eq!(result, crate::params_dilithium5::Q - 123);
    }
}