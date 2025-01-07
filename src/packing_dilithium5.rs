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


use crate::{params_dilithium5, poly_dilithium5, polyvec_dilithium5::{Polyveck, Polyvecl}};
const K: usize = params_dilithium5::K;
const L: usize = params_dilithium5::L;
const N: usize = params_dilithium5::N as usize;

/// Bit-pack public key pk = (rho, t1).
/// 
/// # Arguments
/// 
/// * 'pk' - output for public key value
/// * 'rho' - const reference to rho of params_dilithium5::SEEDBYTES length
/// * 't1' - const reference to t1
pub fn pack_pk(pk: &mut [u8], rho: &[u8], t1: &Polyveck) {
    pk[..params_dilithium5::SEEDBYTES].copy_from_slice(&rho[..params_dilithium5::SEEDBYTES]);
    for i in 0..K {
        poly_dilithium5::t1_pack(&mut pk[params_dilithium5::SEEDBYTES + i * params_dilithium5::POLYT1_PACKEDBYTES..], &t1.vec[i]);
    }
}

/// Unpack public key pk = (rho, t1).
/// 
/// # Arguments
/// 
/// * 'rho' - output for rho value of params_dilithium5::SEEDBYTES length
/// * 't1' - output for t1 value
/// * 'pk' - const reference to public key
pub fn unpack_pk(rho: &mut [u8], t1: &mut Polyveck, pk: &[u8]) {
    rho[..params_dilithium5::SEEDBYTES].copy_from_slice(&pk[..params_dilithium5::SEEDBYTES]);
    for i in 0..K {
        poly_dilithium5::t1_unpack(&mut t1.vec[i], &pk[params_dilithium5::SEEDBYTES + i * params_dilithium5::POLYT1_PACKEDBYTES..]);
    }
}

/// Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn pack_sk(
    sk: &mut [u8],
    rho: &[u8],
    tr: &[u8],
    key: &[u8],
    t0: &Polyveck,
    s1: &Polyvecl,
    s2: &Polyveck
) {
    sk[..params_dilithium5::SEEDBYTES].copy_from_slice(&rho[0..params_dilithium5::SEEDBYTES]);
    let mut idx = params_dilithium5::SEEDBYTES;

    sk[idx..idx + params_dilithium5::SEEDBYTES].copy_from_slice(&key[0..params_dilithium5::SEEDBYTES]);
    idx += params_dilithium5::SEEDBYTES;

    sk[idx..idx + params_dilithium5::SEEDBYTES].copy_from_slice(&tr[0..params_dilithium5::SEEDBYTES]);
    idx += params_dilithium5::SEEDBYTES;

    for i in 0..L {
        poly_dilithium5::eta_pack(&mut sk[idx + i * params_dilithium5::POLYETA_PACKEDBYTES..], &s1.vec[i]);
    }
    idx += L * params_dilithium5::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly_dilithium5::eta_pack(&mut sk[idx + i * params_dilithium5::POLYETA_PACKEDBYTES..], &s2.vec[i]);
    }
    idx += K * params_dilithium5::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly_dilithium5::t0_pack(&mut sk[idx + i * params_dilithium5::POLYT0_PACKEDBYTES..], &t0.vec[i]);
    }
}

/// Unpack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn unpack_sk(
    rho: &mut [u8],
    tr: &mut [u8],
    key: &mut [u8],
    t0: &mut Polyveck,
    s1: &mut Polyvecl,
    s2: &mut Polyveck,
    sk: &[u8]
) {
    rho[..params_dilithium5::SEEDBYTES].copy_from_slice(&sk[..params_dilithium5::SEEDBYTES]);
    let mut idx = params_dilithium5::SEEDBYTES;

    key[..params_dilithium5::SEEDBYTES].copy_from_slice(&sk[idx..idx + params_dilithium5::SEEDBYTES]);
    idx += params_dilithium5::SEEDBYTES;

    tr[..params_dilithium5::SEEDBYTES].copy_from_slice(&sk[idx..idx + params_dilithium5::SEEDBYTES]);
    idx += params_dilithium5::SEEDBYTES;

    for i in 0..L {
        poly_dilithium5::eta_unpack(&mut s1.vec[i], &sk[idx + i * params_dilithium5::POLYETA_PACKEDBYTES..]);
    }
    idx += L * params_dilithium5::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly_dilithium5::eta_unpack(&mut s2.vec[i], &sk[idx + i * params_dilithium5::POLYETA_PACKEDBYTES..]);
    }
    idx += K * params_dilithium5::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly_dilithium5::t0_unpack(&mut t0.vec[i], &sk[idx + i * params_dilithium5::POLYT0_PACKEDBYTES..]);
    }
}

/// Bit-pack signature sig = (c, z, h).
pub fn pack_sig(sig: &mut [u8], c: Option<&[u8]>, z: &Polyvecl, h: &Polyveck) {
    if let Some(challenge) = c {
        sig[..params_dilithium5::SEEDBYTES].copy_from_slice(&challenge[..params_dilithium5::SEEDBYTES]);
    }

    let mut idx = params_dilithium5::SEEDBYTES;
    for i in 0..L {
        poly_dilithium5::z_pack(&mut sig[idx + i * params_dilithium5::POLYZ_PACKEDBYTES..], &z.vec[i]);
    }

    idx += L * params_dilithium5::POLYZ_PACKEDBYTES;
    sig[idx..idx + params_dilithium5::OMEGA + K].copy_from_slice(&[0u8; params_dilithium5::OMEGA + K]);

    let mut k = 0;
    for i in 0..K {
        for j in 0..N {
        if h.vec[i].coeffs[j] != 0 {
            sig[idx + k] = j as u8;
            k += 1;
        }
        }
        sig[idx + params_dilithium5::OMEGA + i] = k as u8;
    }
}

/// Unpack signature sig = (z, h, c).
pub fn unpack_sig(
    c: &mut [u8],
    z: &mut Polyvecl,
    h: &mut Polyveck,
    sig: &[u8],
) -> bool {
    c[..params_dilithium5::SEEDBYTES].copy_from_slice(&sig[..params_dilithium5::SEEDBYTES]);
    
    let mut idx = params_dilithium5::SEEDBYTES;
    for i in 0..L {
        poly_dilithium5::z_unpack(&mut z.vec[i], &sig[idx + i * params_dilithium5::POLYZ_PACKEDBYTES..]);
    }
    idx += L * params_dilithium5::POLYZ_PACKEDBYTES;

    let mut k: usize = 0;
    for i in 0..K {
        if sig[idx + params_dilithium5::OMEGA + i] < k as u8 || sig[idx + params_dilithium5::OMEGA + i] > params_dilithium5::OMEGA as u8 {
            return false;
        }
        for j in k..sig[idx + params_dilithium5::OMEGA + i] as usize {
            if j > k && sig[idx + j as usize] <= sig[idx + j as usize - 1] {
                return false;
            }
            h.vec[i].coeffs[sig[idx + j] as usize] = 1;
        }
        k = sig[idx + params_dilithium5::OMEGA + i] as usize;
    }

    for j in k..params_dilithium5::OMEGA {
        if sig[idx + j as usize] > 0 {
            return false;
        }
    }

    true
}