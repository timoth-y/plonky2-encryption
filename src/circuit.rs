use std::time::Instant;

use eyre::{eyre, Result};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField, secp256k1_base::Secp256K1Base,
        secp256k1_scalar::Secp256K1Scalar, types::PrimeField,
    },
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::CompressedProofWithPublicInputs,
    },
};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ecdsa::{
    curve::secp256k1::Secp256K1,
    gadgets::{
        biguint::{
            witness_get_biguint_target, witness_set_biguint_target, BigUintTarget,
            CircuitBuilderBiguint,
        },
        curve::AffinePointTarget,
        ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
        nonnative::{CircuitBuilderNonNative, NonNativeTarget},
    },
};
use plonky2_ecdsa::gadgets::curve::CircuitBuilderCurve;
use tracing::{event, info, info_span, log, span, Level, warn};

use crate::{Plaintext, PublicKey, Signature};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type Builder = CircuitBuilder<F, D>;
type Proof = ProofWithPublicInputs<F, C, D>;
type Inputs = PartialWitness<GoldilocksField>;

pub struct Circuit {
    input: ElGamalInput,
    data:   CircuitData<F, C, D>,
}

#[derive(Clone)]
struct FieldInput<F>
where
    F: PrimeField,
{
    pub biguint:    BigUintTarget,
    pub non_native: NonNativeTarget<F>,
}

impl<F: PrimeField> FieldInput<F> {
    pub fn new(builder: &mut Builder, public: bool) -> Self {
        let biguint = builder.add_virtual_biguint_target(Builder::num_nonnative_limbs::<F>());
        if public {
            biguint.limbs.iter().for_each(|&limb| {
                builder.register_public_input(limb.0);
            });
        }
        let non_native = builder.biguint_to_nonnative(&biguint);
        Self {
            biguint,
            non_native,
        }
    }

    pub fn set(&self, witness: &mut Inputs, value: F) {
        witness_set_biguint_target(witness, &self.biguint, &value.to_canonical_biguint());
    }

    pub fn get(&self, witness: &Inputs) -> F {
        let n = witness_get_biguint_target(witness, &self.biguint);
        F::from_biguint(n)
    }
}

#[derive(Clone)]
struct ElGamalInput {
    pub pubkey_x: FieldInput<Secp256K1Base>,
    pub pubkey_y: FieldInput<Secp256K1Base>,
    pub plaintext:      FieldInput<Secp256K1Base>,
    pub ciphertext:    FieldInput<Secp256K1Base>,
    pub nonce:    FieldInput<Secp256K1Scalar>,
}

impl ElGamalInput {
    pub fn new(builder: &mut Builder) -> Self {
        let span = info_span!("ElgamalInput::new");
        let _guard = span.enter();
        builder.push_context(log::Level::Info, "Secp256K1Verifier");

        // Inputs
        builder.push_context(log::Level::Info, "inputs");
        let si = info_span!("inputs").in_scope(|| Self {
            pubkey_x: FieldInput::new(builder, true),
            pubkey_y: FieldInput::new(builder, true),
            plaintext:      FieldInput::new(builder, false),
            ciphertext:    FieldInput::new(builder, true),
            nonce:    FieldInput::new(builder, false),
        });
        builder.pop_context();

        // Verifier circuit
        builder.push_context(log::Level::Info, "verify_message_circuit");
        info_span!("verify_message_circuit").in_scope(|| {
            let pk = AffinePointTarget {
                x: si.pubkey_x.non_native.clone(),
                y: si.pubkey_y.non_native.clone(),
            };
            let msg = si.plaintext.non_native.clone();
            let ct = si.ciphertext.non_native.clone();
            let nonce = si.nonce.non_native.clone();
            verify_encryption(builder, pk, msg, nonce, ct);
        });
        builder.pop_context();

        builder.pop_context();
        si
    }

    pub fn set(
        &self,
        witness: &mut Inputs,
        (pk, msg, cipher, nonce): (PublicKey, Secp256K1Base, Secp256K1Base, Secp256K1Scalar),
    ) {
        self.pubkey_x.set(witness, pk.0.x);
        self.pubkey_y.set(witness, pk.0.y);
        self.plaintext.set(witness, msg);
        self.ciphertext.set(witness, cipher);
        self.nonce.set(witness, nonce);
    }
}

impl Circuit {
    pub fn new() -> Circuit {
        let span = info_span!("Circuit::new");
        let _guard = span.enter();

        // Configure circuit builder
        let config = CircuitConfig::wide_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Start building circuit
        let span = info_span!("constructing");
        let constructing_guard = span.enter();
        builder.push_context(log::Level::Info, "Circuit");

        // Verifiers
        builder.push_context(log::Level::Info, "Verifiers");
        let input = ElGamalInput::new(&mut builder);
        builder.pop_context();

        // Stop building circuit
        drop(constructing_guard);
        builder.pop_context();

        // Compile circuit
        builder.print_gate_counts(0); // TODO: Add to span
        let data = info_span!("compiling").in_scope(|| builder.build::<C>());

        Self { input, data }
    }

    pub fn prove(
        &self,
        args: (PublicKey, Secp256K1Base, Secp256K1Base, Secp256K1Scalar),
    ) -> Result<Proof> {
        let span = info_span!(
            "proving",
            security_bits = self.data.common.config.security_bits,
            degree = %self.data.common.degree(),
            constraint_degree = %self.data.common.constraint_degree(),
        );
        let _guard = span.enter();

        // Set public inputs
        // TODO: Make sure enough inputs are supplied.
        let pw = span!(Level::INFO, "set_public_inputs").in_scope(|| {
            let mut pw = PartialWitness::new();
            self.input.set(&mut pw, args);
            pw
        });

        // Proof
        let proof = {
            let span = span!(Level::INFO, "computing_compressed_proof");
            let _ = span.enter();
            self.data
                .prove(pw)
                //.and_then(|proof| proof.compress(&self.data.common))
                .map_err(|e| eyre!(e))?
        };
        let proof_bytes = proof.to_bytes().map_err(|e| eyre!(e))?;
        span.record("proof_size", &proof_bytes.len());

        Ok(proof)
    }

    pub fn verify(&self, proof: Proof) -> Result<()> {
        let span = info_span!("verifying");
        let _guard = span.enter();

        // Uncompress proof
        //let proof = proof.decompress(&self.data.common).map_err(|e| eyre!(e))?;

        self.data.verify(proof).map_err(|e| eyre!(e))
    }
}

fn verify_encryption(
    builder: &mut Builder,
    pk: AffinePointTarget<Secp256K1>,
    msg: NonNativeTarget<Secp256K1Base>,
    nonce: NonNativeTarget<Secp256K1Scalar>,
    cipher: NonNativeTarget<Secp256K1Base>,
) {
    let dh = builder.curve_scalar_mul(&pk, &nonce);
    let shared_key = dh.x;
    let ciphertext_target = builder.add_nonnative(&msg, &shared_key);

    //builder.connect_nonnative(&ciphertext_target, &cipher);
}

