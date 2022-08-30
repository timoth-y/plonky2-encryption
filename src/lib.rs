#![doc = include_str!("../Readme.md")]
#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]

mod circuit;

use std::iter::repeat_with;
use std::time::Instant;

use self::circuit::Circuit;
use clap::Parser;
use eyre::Result;
use plonky2::field::types::Field;
use plonky2_ecdsa::curve::{
    curve_types::Curve as TCurve,
    ecdsa::{sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};
use plonky2_ecdsa::curve::curve_types::{AffinePoint, CurveScalar};
use tracing::instrument;
use rayon::prelude::*;


#[derive(Clone, Debug, Parser)]
pub struct Options {
    #[clap(long, default_value = "4")]
    pub size: usize,
}

type Curve = Secp256K1;
type PublicKey = ECDSAPublicKey<Curve>;
type Plaintext = <Curve as TCurve>::BaseField;
type Ciphertext = <Curve as TCurve>::BaseField;
type Signature = ECDSASignature<Curve>;
type Nonce = <Curve as TCurve>::ScalarField;

fn test_signature() -> (PublicKey, Plaintext, Ciphertext, Nonce) {
    type Field = <Curve as TCurve>::ScalarField;
    let secret_key = ECDSASecretKey(Field::rand());
    let public_key = secret_key.to_public();
    let message = Plaintext::rand();
    let nonce = Nonce::rand();
    let (c1, c2) = encrypt(message.clone(), public_key.clone(), nonce.clone());
    (public_key, message, c2, nonce)
}

fn encrypt(msg: Plaintext, pk: PublicKey, nonce: <Curve as TCurve>::ScalarField) -> (AffinePoint<Secp256K1>, <Curve as TCurve>::BaseField) {
    let c1 = (CurveScalar(nonce.clone()) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
    let dh = CurveScalar(nonce) * pk.0.to_projective();
    let c2 = msg + dh.x;
    return (c1, c2);
}

#[allow(clippy::missing_errors_doc)]
#[allow(clippy::unused_async)]
pub async fn main(options: Options) -> Result<()> {
    let n = options.size;

    let inputs: Vec<_> = repeat_with(test_signature).take(n).map(|args| (Circuit::new(), args)).collect();
    let start = Instant::now();
    let proofs: Result<Vec<_>> = inputs.into_par_iter().map(|(c, args)| c.prove(args)).collect();
    let proof_time = start.elapsed();
    println!("Proof time: {:4}.{:09}", proof_time.as_secs(), proof_time.subsec_nanos());
    //circuit.verify(proof)?;
    Ok(())
}

#[cfg(feature = "bench")]
pub mod bench {
    use criterion::{black_box, BatchSize, Criterion};
    use proptest::{
        strategy::{Strategy, ValueTree},
        test_runner::TestRunner,
    };

    pub fn group(criterion: &mut Criterion) {
        bench_example_proptest(criterion);
    }

    /// Example proptest benchmark
    /// Uses proptest to randomize the benchmark input
    fn bench_example_proptest(criterion: &mut Criterion) {
        let input = (0..5, 0..5);
        let mut runner = TestRunner::deterministic();
        // Note: benchmarks need to have proper identifiers as names for
        // the CI to pick them up correctly.
        criterion.bench_function("example_proptest", move |bencher| {
            bencher.iter_batched(
                || input.new_tree(&mut runner).unwrap().current(),
                |(a, b)| {
                    // Benchmark number addition
                    black_box(a + b)
                },
                BatchSize::LargeInput,
            );
        });
    }
}
