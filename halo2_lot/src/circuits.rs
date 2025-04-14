use rand::rngs::OsRng;
use std::io::{Cursor, Error};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof_multi, Circuit, ConstraintSystem,
        ErrorFront, Expression, Selector,
    },
    poly::{
        commitment::CommitmentScheme,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptRead, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};

#[derive()]
pub struct CircuitOutput {
    pub commitment: G1Affine,
    pub proof: Vec<u8>,
    pub params: ParamsKZG<Bn256>,
}

// Function to extract commitments for advice columns from a proof
fn extract_commitments<C: CommitmentScheme>(
    proof: &[u8],
    num_advice_columns: usize,
) -> Vec<G1Affine> {
    // Initialize the transcript reader with the proof data
    let mut transcript =
        Blake2bRead::<std::io::Cursor<&[u8]>, _, Challenge255<_>>::init(Cursor::new(proof));

    // Vector to store the extracted commitments
    let mut commitments = Vec::new();

    // Loop through the number of advice columns and read each commitment
    for _ in 0..num_advice_columns {
        let commitment = transcript.read_point().expect("Failed to read commitment");
        commitments.push(commitment);
    }

    // Return the vector of commitments
    commitments
}

/// A simple configuration struct that holds one Advice column.
#[derive(Clone, Debug)]
pub struct MyConfig {
    advice_col: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    q_bit: Selector,
}

/// In this circuit, `bitvector` could be something you want to prove knowledge of.
#[derive(Clone, Debug)]
pub struct BitvectorCommitmentCircuit {
    /// This will be our witness. We store it as a `Value<Fp>`.
    pub(crate) bitvector: Vec<Fr>,
}

impl Circuit<Fr> for BitvectorCommitmentCircuit {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    /// This is optional “empty” version of the circuit without witness values.
    fn without_witnesses(&self) -> Self {
        Self { bitvector: vec![] }
    }

    /// Configure is where you define circuit structure: which columns exist,
    /// what selectors you need, and how constraints are applied.
    fn configure(meta: &mut ConstraintSystem<Fr>) -> MyConfig {
        // Allocate a single advice column.
        let advice_col = meta.unblinded_advice_column();
        let q_bit = meta.selector();

        // Add a constraint that the bit must be 0 or 1
        meta.create_gate("bit constraint", |meta| {
            let s = meta.query_selector(q_bit);
            let bit = meta.query_advice(advice_col, Rotation::cur());

            vec![s * bit.clone() * (bit - Expression::Constant(Fr::from(1u64)))]
        });

        MyConfig { advice_col, q_bit }
    }

    /// `synthesize` is where you lay out your circuit’s values.
    fn synthesize(
        &self,
        config: MyConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || "assign bits",
            |mut region| {
                for (i, bit) in self.bitvector.iter().enumerate() {
                    // Enable q_bit selector on this row
                    config.q_bit.enable(&mut region, i)?;
                    region.assign_advice(|| "bit", config.advice_col, i, || Value::known(*bit))?;
                }
                Ok(())
            },
        )
    }
}

pub fn kzg_commitment_with_halo2_proof(
    prover_params: ParamsKZG<Bn256>,
    bitvector: Vec<Fr>,
) -> Result<CircuitOutput, Error> {
    let circuit = BitvectorCommitmentCircuit { bitvector };

    // Create verifying and proving keys
    let vk = keygen_vk(&prover_params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&prover_params, vk, &circuit).expect("keygen_pk should not fail");

    // Create a transcript for the proof
    let mut proof_transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    // Actually create the proof (this is where polynomials get committed internally)
    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, BitvectorCommitmentCircuit>(
        &prover_params,
        &pk,
        &[circuit],
        &[(&[]).to_vec()],
        OsRng,
        &mut proof_transcript,
    )
    .expect("proof generation should succeed");

    // Finalize and serialize the proof
    let proof = proof_transcript.finalize();

    // Verify the proof
    let mut verifier_transcript =
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof.as_slice());
    let verifier_params = prover_params.verifier_params();

    assert!(
        verify_proof_multi::<KZGCommitmentScheme<Bn256>, VerifierGWC<Bn256>, _, _, SingleStrategy<_>>(
            &verifier_params,
            &pk.get_vk(),
            &[(&[]).to_vec()],
            &mut verifier_transcript,
        ),
        "failed to verify proof"
    );

    // 10. Extract our advice column commtiment from the proof
    let num_advice_columns = 1; // Number of advice columns in the circuit
    let commitments = extract_commitments::<KZGCommitmentScheme<Bn256>>(&proof, num_advice_columns);

    // Extract the bitvector as advice column commitment from Halo2 proof
    let halo2_commitment = commitments[0];

    Ok(CircuitOutput {
        commitment: halo2_commitment,
        proof,
        params: prover_params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_middleware::zal::impls::PlonkEngineConfig;
    use halo2_proofs::{
        dev::MockProver,
        poly::commitment::{Blind, Params},
    };
    use halo2curves::{
        group::{prime::PrimeCurveAffine, Curve},
        CurveAffine,
    };

    #[test]
    fn test_circuit_layout() {
        // 1. Define your circuit with the desired bitvector witness
        let circuit = BitvectorCommitmentCircuit {
            bitvector: vec![
                Fr::zero(),
                Fr::zero(),
                Fr::one(),
                Fr::one(),
                Fr::zero(),
                Fr::zero(),
                Fr::one(),
                Fr::one(),
            ],
        };

        // 2. Create a MockProver (choose a power-of-two size, say 4 or 8, etc.)
        let k = 4;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        // 3. Verify. If constraints fail, this returns an error with more context.
        prover.assert_satisfied();

        // Uncomment to print the advice column values for debug
        // let advice_vals = prover.advice();
        // println!("Printed Column: {:?}", &advice_vals);
    }

    #[test]
    fn test_circuit_commitment() {
        // Circuit setup
        let k = 4;
        let bitvector = vec![Fr::zero(), Fr::zero(), Fr::one(), Fr::one()];
        let circuit = BitvectorCommitmentCircuit { bitvector };

        // Generate params and keys
        let params: ParamsKZG<Bn256> = ParamsKZG::setup(k, &mut OsRng);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let domain = vk.get_domain();
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("keygen_pk should not fail");

        // Create and verify proof
        let mut proof_transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, BitvectorCommitmentCircuit>(
            &params,
            &pk,
            &[circuit],
            &[(&[]).to_vec()],
            OsRng,
            &mut proof_transcript,
        )
        .expect("proof generation should succeed");

        let proof = proof_transcript.finalize();

        // Verify proof
        let mut verifier_transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof.as_slice());
        let verifier_params = params.verifier_params();
        assert!(
            verify_proof_multi::<
                KZGCommitmentScheme<Bn256>,
                VerifierGWC<Bn256>,
                _,
                _,
                SingleStrategy<_>,
            >(
                &verifier_params,
                &pk.get_vk(),
                &[(&[]).to_vec()],
                &mut verifier_transcript,
            ),
            "failed to verify proof"
        );

        // Extract Halo2 commitment
        let commitments = extract_commitments::<KZGCommitmentScheme<Bn256>>(&proof, 1);
        let halo2_commitment = commitments[0];

        // Generate plain KZG commitment
        let fresh_bitvector = vec![Fr::zero(), Fr::zero(), Fr::one(), Fr::one()];
        let mut a = domain.empty_lagrange();
        for (i, a) in a.iter_mut().enumerate() {
            *a = if i < fresh_bitvector.len() {
                fresh_bitvector[i]
            } else {
                Fr::zero()
            };
        }

        let engine = PlonkEngineConfig::build_default::<G1Affine>();
        let commitment = params.commit_lagrange(&engine.msm_backend, &a, Blind::default());

        let mut advice_commitments_affine = vec![
            <<KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve as PrimeCurveAffine>::identity();
            1
        ];

        <<KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve as CurveAffine>::CurveExt::batch_normalize(
            &[commitment],
            &mut advice_commitments_affine,
        );

        // Assert commitments match
        assert_eq!(halo2_commitment, advice_commitments_affine[0]);
    }
}
