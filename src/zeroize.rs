// This is a feature-reduced implementation of Zeroize. 
// Created by the author to simplify the code and only work with necessary functions.

use std::ptr;
use std::sync::atomic::{fence, Ordering};

/// Trait for securely zeroing memory to prevent sensitive data from remaining in memory
pub trait Zeroize {
    /// Zeroize this value, securely wiping it from memory
    fn zeroize(&mut self);
}

// Implementation for common primitive types
impl Zeroize for u8 {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, 0) };
        fence(Ordering::SeqCst);
    }
}

impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            byte.zeroize();
        }
        fence(Ordering::SeqCst);
    }
}

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        for elem in self.iter_mut() {
            elem.zeroize();
        }
        fence(Ordering::SeqCst);
    }
}

impl<T: Zeroize> Zeroize for Vec<T> {
    fn zeroize(&mut self) {
        for elem in self.iter_mut() {
            elem.zeroize();
        }
        self.clear();
        self.shrink_to_fit();
        fence(Ordering::SeqCst);
    }
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        unsafe {
            for b in self.as_bytes_mut() {
                ptr::write_volatile(b, 0);
            }
        }
        self.clear();
        self.shrink_to_fit();
        fence(Ordering::SeqCst);
    }
}

// Macro to help implement Zeroize for primitive integer types
macro_rules! impl_numeric_zeroize {
    ($($t:ty),+) => {
        $(impl Zeroize for $t {
            fn zeroize(&mut self) {
                unsafe { ptr::write_volatile(self, 0) };
                fence(Ordering::SeqCst);
            }
        })*
    }
}

impl_numeric_zeroize!(i8, i16, i32, i64, i128, isize, u16, u32, u64, u128, usize);

// Helper function to prevent dead code elimination
// #[inline(never)]
// fn prevent_optimization<T>(v: *mut T) {
//     fence(Ordering::SeqCst);
//     unsafe { ptr::read_volatile(v); }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_u8() {
        let mut x = 0xFFu8;
        x.zeroize();
        assert_eq!(x, 0);
    }

    #[test]
    fn test_zeroize_array() {
        let mut arr = [0xFFu8; 32];
        arr.zeroize();
        assert_eq!(arr, [0u8; 32]);
    }

    #[test]
    fn test_zeroize_vec() {
        let mut vec = vec![0xFFu8; 32];
        vec.zeroize();
        assert!(vec.is_empty());
    }

    #[test]
    fn test_zeroize_string() {
        let mut string = String::from("sensitive data");
        string.zeroize();
        assert!(string.is_empty());
    }
}