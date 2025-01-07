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


// Specification defined constans
pub const Q: i32 = (1 << 23) - (1 << 13) + 1; //prime defining the field
pub const N: i32 = 256; //ring defining polynomial degree
pub const D: i32 = 13; //dropped bits

// Implementation specific values
pub const SEEDBYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYT0_PACKEDBYTES: usize = 416;

// Specification defined constans
pub const TAU: usize = 60; //number of +-1s in c
pub const GAMMA1: usize = 1 << 19; //y coefficient range
pub const GAMMA2: usize = (Q as usize - 1) / 32; //low-order rounding range
pub const K: usize = 8; //rows in A
pub const L: usize = 7; //columns in A
pub const ETA: usize = 2;
pub const BETA: usize = TAU * ETA;
pub const OMEGA: usize = 75;

// Implementation specific values
pub const POLYZ_PACKEDBYTES: usize = 640;
pub const POLYW1_PACKEDBYTES: usize = 128;
pub const POLYETA_PACKEDBYTES: usize = 96;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
pub const PUBLICKEYBYTES: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES;
pub const SECRETKEYBYTES: usize = 3 * SEEDBYTES + (K + L) * POLYETA_PACKEDBYTES + K * POLYT0_PACKEDBYTES;
pub const SIGNBYTES: usize = SEEDBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;