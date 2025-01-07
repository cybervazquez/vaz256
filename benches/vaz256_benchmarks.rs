// VAZ256™ Cryptographic Benchmark Suite
//
// Project: VAZ256™ - A Hybrid Post-Quantum Digital Signature Scheme
// Author: Fran Luis Vazquez Alonso
// Copyright (C) 2025
//
// Benchmark Overview:
// This comprehensive benchmark suite evaluates the performance characteristics
// of the VAZ256™ cryptographic signature scheme across various dimensions:
// - Key generation performance
// - Signing operation efficiency
// - Signature verification speed
// - Serialization and deserialization capabilities
// - End-to-end cryptographic cycle performance
//
// Benchmark Methodology:
// - Utilizes Criterion.rs for statistically rigorous performance measurements
// - Tests multiple message sizes to assess scalability
// - Provides detailed insights into computational complexity
// - Uses cryptographically secure random number generation
//
// License: GNU General Public License v3.0
// Trademark: VAZ256™ is a trademark of Fran Luis Vazquez Alonso

/// Core dependencies for cryptographic benchmarking
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use vaz256::{
    keygen,     // Key pair generation function
    sign,       // Message signing function
    verify,     // Signature verification function
    SecretKey,  // Private key type
    PublicKey,  // Public key type
    Signature   // Digital signature type
};
use rand::{RngCore, rngs::OsRng};

/// Generates a cryptographically secure random message of specified size
///
/// # Arguments
/// * `size` - Desired message length in bytes
///
/// # Returns
/// A vector of cryptographically random bytes
///
/// # Security
/// Uses OsRng (operating system's cryptographically secure random number generator)
fn generate_random_message(size: usize) -> Vec<u8> {
    let mut msg = vec![0u8; size];
    OsRng.fill_bytes(&mut msg);
    msg
}

/// Benchmarks the key generation performance of VAZ256™
///
/// # Benchmark Characteristics
/// - Sample size: 50 iterations
/// - Measures the computational cost of generating a key pair
/// - Uses black_box to prevent compiler optimizations
fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("VAZ256 Key Generation");
    group.sample_size(50); // Statistically significant sample size
    
    group.bench_function("keygen", |b| {
        b.iter(|| {
            // Prevents compiler optimizations that could skew results
            black_box(keygen().unwrap())
        });
    });

    group.finish();
}

/// Benchmarks the digital signature signing performance
///
/// # Benchmark Characteristics
/// - Tests signing efficiency across multiple message sizes
/// - Message sizes: 32 to 4096 bytes
/// - Sample size: 50 iterations per message size
/// - Evaluates scalability of signing operation
fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("VAZ256 Signing");
    group.sample_size(50);

    // Diverse message sizes to test signature scheme scalability
    let message_sizes = vec![32, 64, 128, 256, 512, 1024, 2048, 4096];
    let (sk, _) = keygen().unwrap();

    for size in message_sizes {
        let message = generate_random_message(size);
        
        group.bench_with_input(
            BenchmarkId::new("sign", size), 
            &(message, sk.clone()),
            |b, (msg, sk)| {
                b.iter(|| {
                    black_box(sign(msg, sk).unwrap())
                });
            }
        );
    }

    group.finish();
}

/// Benchmarks the signature verification performance
///
/// # Benchmark Characteristics
/// - Tests verification efficiency across multiple message sizes
/// - Message sizes: 32 to 4096 bytes
/// - Sample size: 50 iterations per message size
/// - Evaluates computational overhead of signature verification
fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("VAZ256 Verification");
    group.sample_size(50);

    let message_sizes = vec![32, 64, 128, 256, 512, 1024, 2048, 4096];
    let (sk, pk) = keygen().unwrap();

    for size in message_sizes {
        let message = generate_random_message(size);
        let signature = sign(&message, &sk).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("verify", size),
            &(message, signature, pk.clone()),
            |b, (msg, sig, pk)| {
                b.iter(|| {
                    black_box(verify(msg, sig, pk).unwrap())
                });
            }
        );
    }

    group.finish();
}

/// Benchmarks serialization and deserialization performance
///
/// # Benchmark Characteristics
/// - Measures conversion performance for:
///   * Secret Key (to/from hex)
///   * Public Key (to/from hex)
///   * Signature (to/from hex, to/from bytes)
/// - Sample size: 100 iterations for more precise measurements
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("VAZ256 Serialization");
    group.sample_size(100);

    let (sk, pk) = keygen().unwrap();
    let message = generate_random_message(128);
    let signature = sign(&message, &sk).unwrap();

    // Secret Key serialization benchmarks
    group.bench_function("SecretKey to_hex", |b| {
        b.iter(|| {
            black_box(sk.to_hex())
        });
    });

    let sk_hex = sk.to_hex();
    group.bench_function("SecretKey from_hex", |b| {
        b.iter(|| {
            black_box(SecretKey::from_hex(&sk_hex).unwrap())
        });
    });

    // Public Key serialization benchmarks
    group.bench_function("PublicKey to_hex", |b| {
        b.iter(|| {
            black_box(pk.to_hex())
        });
    });

    let pk_hex = pk.to_hex();
    group.bench_function("PublicKey from_hex", |b| {
        b.iter(|| {
            black_box(PublicKey::from_hex(&pk_hex).unwrap())
        });
    });

    // Signature serialization benchmarks
    group.bench_function("Signature to_bytes", |b| {
        b.iter(|| {
            black_box(signature.to_bytes())
        });
    });

    group.bench_function("Signature to_hex", |b| {
        b.iter(|| {
            black_box(signature.to_hex())
        });
    });

    let sig_hex = signature.to_hex();
    group.bench_function("Signature from_hex", |b| {
        b.iter(|| {
            black_box(Signature::from_hex(&sig_hex).unwrap())
        });
    });

    let sig_bytes = signature.to_bytes();
    group.bench_function("Signature from_bytes", |b| {
        b.iter(|| {
            black_box(Signature::from_bytes(&sig_bytes).unwrap())
        });
    });

    group.finish();
}

/// Benchmarks the complete cryptographic operation cycle
///
/// # Benchmark Characteristics
/// - Measures end-to-end performance of:
///   * Key generation
///   * Signing
///   * Signature verification
/// - Tests across various message sizes
/// - Provides comprehensive performance overview
fn bench_full_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("VAZ256 Full Cryptographic Cycle");
    group.sample_size(50);

    let message_sizes = vec![32, 64, 128, 256, 512, 1024, 2048, 4096];

    for size in message_sizes {
        let message = generate_random_message(size);
        
        group.bench_with_input(
            BenchmarkId::new("keygen+sign+verify", size),
            &message,
            |b, msg| {
                b.iter(|| {
                    let (sk, pk) = keygen().unwrap();
                    let signature = sign(msg, &sk).unwrap();
                    black_box(verify(msg, &signature, &pk).unwrap())
                });
            }
        );
    }

    group.finish();
}

// Register benchmarks for execution
criterion_group!(
    benches,
    bench_keygen,
    bench_signing,
    bench_verification,
    bench_serialization,
    bench_full_cycle
);
criterion_main!(benches);