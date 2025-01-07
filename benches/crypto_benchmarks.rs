// VAZ256™ Cryptographic Comparative Benchmark
//
// Project: Comparative Performance Analysis of Post-Quantum Digital Signature Schemes
// Copyright (C) 2025 Fran Luis Vazquez Alonso
//
// Benchmark Overview:
// This benchmark suite provides a comprehensive comparative performance analysis
// of three cutting-edge post-quantum digital signature schemes:
// 1. VAZ256™ (Proprietary Hybrid Scheme)
// 2. Falcon-1024
// 3. Dilithium5
//
// Benchmark Objectives:
// - Evaluate key generation performance
// - Measure signing operation efficiency
// - Assess signature verification speed
// - Compare full cryptographic cycle performance
//
// Methodology:
// - Uses Criterion.rs for statistically rigorous performance measurements
// - Consistent testing across multiple algorithms
// - Cryptographically secure random message generation
// - Multiple performance metrics calculation
//
// Trademark: VAZ256™ is a trademark of Fran Luis Vazquez Alonso
// License: GNU General Public License v3.0

/// Core Dependencies
/// Imports cryptographic libraries and performance benchmarking tools
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use vaz256::{
    keygen as vaz_keygen, 
    sign as vaz_sign, 
    verify as vaz_verify, 
    Signature as VazSignature, 
    SecretKey as VazSecretKey, 
    PublicKey as VazPublicKey
};
use falcon_rust::falcon1024::{
    keygen as falcon_keygen, 
    sign as falcon_sign, 
    verify as falcon_verify, 
    Signature as FalconSignature1024, 
    SecretKey as FalconSecretKey1024, 
    PublicKey as FalconPublicKey1024
};
use pqcrypto_dilithium::dilithium5::{
    keypair, 
    sign as dilithium_sign, 
    open as dilithium_open, 
    SignedMessage, 
    SecretKey as DilithiumSecretKey, 
    PublicKey as DilithiumPublicKey
};
use rand::rngs::OsRng;
use rand::RngCore;

/// Cryptographically Secure Random Message Generator
///
/// # Arguments
/// * `size` - Desired message length in bytes
///
/// # Returns
/// A vector of cryptographically secure random bytes
///
/// # Security
/// Uses OsRng (operating system's cryptographically secure random number generator)
fn generate_random_message(size: usize) -> Vec<u8> {
    let mut msg = vec![0u8; size];
    let mut rng = OsRng;
    rng.fill_bytes(&mut msg);
    msg
}

/// Enum Wrapper for Cryptographic Key Pairs
///
/// Allows unified handling of different cryptographic key pair types
enum KeyPairWrapper {
    Vaz((VazSecretKey, VazPublicKey)),
    Falcon((FalconSecretKey1024, FalconPublicKey1024)),
    Dilithium((DilithiumSecretKey, DilithiumPublicKey)),
}

/// Enum Wrapper for Cryptographic Signatures
///
/// Enables consistent signature representation across different schemes
enum SignatureWrapper {
    Vaz(VazSignature),
    Falcon(FalconSignature1024),
    Dilithium(SignedMessage),
}

/// Key Generation Performance Benchmark
///
/// # Benchmark Characteristics
/// - Compares key generation performance of:
///   * VAZ256™
///   * Falcon-1024
///   * Dilithium5
/// - Sample size: 10 iterations
/// - Measures computational overhead of key pair generation
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");
    group.sample_size(10);

    for algo in ["VAZ256", "Falcon1024", "Dilithium5"].iter() {
        group.bench_with_input(BenchmarkId::new("Keygen", algo), algo, |b, _| {
            b.iter(|| {
                let keypair = match *algo {
                    "VAZ256" => {
                        let (vaz_sk, vaz_pk) = vaz_keygen().unwrap();
                        KeyPairWrapper::Vaz((vaz_sk, vaz_pk))
                    },
                    "Falcon1024" => {
                        let mut seed = [0u8; 32];
                        OsRng.fill_bytes(&mut seed);
                        let (falcon_sk, falcon_pk) = falcon_keygen(seed);
                        KeyPairWrapper::Falcon((falcon_sk, falcon_pk))
                    },
                    "Dilithium5" => {
                        let (pk, sk) = keypair();
                        KeyPairWrapper::Dilithium((sk, pk))
                    },
                    _ => unreachable!(),
                };

                black_box(keypair)
            });
        });
    }
}

/// Signing Operation Performance Benchmark
///
/// # Benchmark Characteristics
/// - Compares signing performance across algorithms
/// - Fixed message size: 32 bytes
/// - Sample size: 10 iterations
/// - Evaluates efficiency of signature generation
fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signing");
    group.sample_size(10);

    let message = generate_random_message(32);

    for algo in ["VAZ256", "Falcon1024", "Dilithium5"].iter() {
        group.bench_with_input(BenchmarkId::new("Sign", algo), algo, |b, _| {
            let keypair = match *algo {
                "VAZ256" => KeyPairWrapper::Vaz(vaz_keygen().unwrap()),
                "Falcon1024" => {
                    let mut seed = [0u8; 32];
                    OsRng.fill_bytes(&mut seed);
                    KeyPairWrapper::Falcon(falcon_keygen(seed))
                },
                "Dilithium5" => {
                    let (pk, sk) = keypair();
                    KeyPairWrapper::Dilithium((sk, pk))
                },
                _ => unreachable!(),
            };

            b.iter(|| {
                match &keypair {
                    KeyPairWrapper::Vaz((sk, _)) => {
                        let vaz_sig = vaz_sign(&message, sk).unwrap();
                        black_box(SignatureWrapper::Vaz(vaz_sig))
                    },
                    KeyPairWrapper::Falcon((sk, _)) => {
                        let falcon_sig = falcon_sign(&message, sk);
                        black_box(SignatureWrapper::Falcon(falcon_sig))
                    },
                    KeyPairWrapper::Dilithium((sk, _pk)) => {
                        let dilithium_sig = dilithium_sign(&message, sk);
                        black_box(SignatureWrapper::Dilithium(dilithium_sig))
                    },
                }
            });
        });
    }
}


/// Signature Verification Performance Benchmark
///
/// # Benchmark Characteristics
/// - Compares signature verification speed
/// - Fixed message size: 32 bytes
/// - Sample size: 10 iterations
/// - Measures computational cost of signature validation
fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verification");
    group.sample_size(10);

    let message = generate_random_message(32);

    for algo in ["VAZ256", "Falcon1024", "Dilithium5"].iter() {
        group.bench_with_input(BenchmarkId::new("Verify", algo), algo, |b, _| {
            let keypair = match *algo {
                "VAZ256" => KeyPairWrapper::Vaz(vaz_keygen().unwrap()),
                "Falcon1024" => {
                    let mut seed = [0u8; 32];
                    OsRng.fill_bytes(&mut seed);
                    KeyPairWrapper::Falcon(falcon_keygen(seed))
                },
                "Dilithium5" => {
                    let (pk, sk) = keypair();
                    KeyPairWrapper::Dilithium((sk, pk))
                },
                _ => unreachable!(),
            };

            let signature = match &keypair {
                KeyPairWrapper::Vaz((sk, _)) => SignatureWrapper::Vaz(vaz_sign(&message, sk).unwrap()),
                KeyPairWrapper::Falcon((sk, _)) => SignatureWrapper::Falcon(falcon_sign(&message, sk)),
                KeyPairWrapper::Dilithium((sk, _pk)) => SignatureWrapper::Dilithium(dilithium_sign(&message, sk)),
            };

            b.iter(|| {
                match (&keypair, &signature) {
                    (KeyPairWrapper::Vaz((_, pk)), SignatureWrapper::Vaz(sig)) => 
                        black_box(vaz_verify(&message, sig, pk).is_ok()),
                    (KeyPairWrapper::Falcon((_, pk)), SignatureWrapper::Falcon(sig)) => 
                        black_box(falcon_verify(&message, sig, pk)),
                    (KeyPairWrapper::Dilithium((_, pk)), SignatureWrapper::Dilithium(sig)) => 
                        black_box(dilithium_open(sig, pk).is_ok()),
                    _ => false,
                }
            });
        });
    }

    group.finish();
}

/// Full Cryptographic Cycle Performance Benchmark
///
/// # Benchmark Characteristics
/// - Measures end-to-end performance
/// - Includes key generation, signing, and verification
/// - Fixed message size: 32 bytes
/// - Sample size: 10 iterations
/// - Provides comprehensive performance overview
fn bench_full_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("Full Cycle");
    group.sample_size(10);

    let message = generate_random_message(32);

    for algo in ["VAZ256", "Falcon1024", "Dilithium5"].iter() {
        group.bench_with_input(BenchmarkId::new("Full", algo), algo, |b, _| {
            b.iter(|| {
                let keypair = match *algo {
                    "VAZ256" => KeyPairWrapper::Vaz(vaz_keygen().unwrap()),
                    "Falcon1024" => {
                        let mut seed = [0u8; 32];
                        OsRng.fill_bytes(&mut seed);
                        KeyPairWrapper::Falcon(falcon_keygen(seed))
                    },
                    "Dilithium5" => {
                        let (pk, sk) = keypair();
                        KeyPairWrapper::Dilithium((sk, pk))
                    },
                    _ => unreachable!(),
                };

                let signature = match &keypair {
                    KeyPairWrapper::Vaz((sk, _)) => SignatureWrapper::Vaz(vaz_sign(&message, sk).unwrap()),
                    KeyPairWrapper::Falcon((sk, _)) => SignatureWrapper::Falcon(falcon_sign(&message, sk)),
                    KeyPairWrapper::Dilithium((sk, _pk)) => SignatureWrapper::Dilithium(dilithium_sign(&message, sk)),
                };

                match (&keypair, &signature) {
                    (KeyPairWrapper::Vaz((_, pk)), SignatureWrapper::Vaz(sig)) => 
                        black_box(vaz_verify(&message, sig, pk).is_ok()),
                    (KeyPairWrapper::Falcon((_, pk)), SignatureWrapper::Falcon(sig)) => 
                        black_box(falcon_verify(&message, sig, pk)),
                    (KeyPairWrapper::Dilithium((_, pk)), SignatureWrapper::Dilithium(sig)) => 
                        black_box(dilithium_open(sig, pk).is_ok()),
                    _ => false,
                }
            });
        });
    }

    group.finish();
}

// Register benchmarks for execution
criterion_group!(
    benches, 
    bench_keygen, 
    bench_signing, 
    bench_verification, 
    bench_full_cycle
);
criterion_main!(benches);