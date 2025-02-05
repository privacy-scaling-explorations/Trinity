use rand::rngs::OsRng;
use std::io::Cursor;

use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};

use halo2_middleware::zal::impls::PlonkEngineConfig;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        group::{prime::PrimeCurveAffine, Curve},
        CurveAffine,
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof_multi, Circuit, ConstraintSystem,
        ErrorFront, Expression, Selector,
    },
    poly::{
        commitment::{Blind, CommitmentScheme, Params},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
        EvaluationDomain, Rotation,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptRead, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};

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

/// CommitmentKey for KZG
pub struct CommitmentKey<E: Pairing> {
    pub lagranges: Vec<E::G1Affine>, // Precomputed Lagrange basis points in G1
}

/// Compute a KZG commitment for the given vector of evaluations
pub fn plain_kzg_com<E: Pairing>(ck: &CommitmentKey<E>, evals: &[E::ScalarField]) -> E::G1Affine {
    assert_eq!(evals.len(), ck.lagranges.len());
    let c = <E::G1 as VariableBaseMSM>::msm(&ck.lagranges, evals).unwrap();
    c.into_affine()
}

/// A simple configuration struct that holds one Advice column.
#[derive(Clone, Debug)]
struct MyConfig {
    advice_col: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
    q_bit: Selector,
}

/// In this circuit, `bitvector` could be something you want to prove knowledge of.
#[derive(Clone, Debug)]
struct BitvectorCommitmentCircuit {
    /// This will be our witness. We store it as a `Value<Fp>`.
    bitvector: Vec<Fr>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

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
}

fn main() {
    // 1. Choose circuit size = 2^k
    let k = 4;

    // 2. Define the bit vector we want to commit (e.g., [1, 0, 1, 1])
    let bitvector = vec![Fr::zero(), Fr::zero(), Fr::one(), Fr::one()];

    // 3. Create circuit instance with the bit vector
    let circuit = BitvectorCommitmentCircuit { bitvector };

    // 4. Generate universal (trusted) parameters for KZG
    let params: ParamsKZG<Bn256> = ParamsKZG::setup(k, &mut OsRng);

    // 5. Create verifying and proving keys
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    // 6. Create a transcript for the proof
    let mut proof_transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    // 7. Actually create the proof (this is where polynomials get committed internally)
    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, BitvectorCommitmentCircuit>(
        &params,
        &pk,
        &[circuit],
        &[(&[]).to_vec()],
        OsRng,
        &mut proof_transcript,
    )
    .expect("proof generation should succeed");

    // 8. Finalize and serialize the proof
    let proof = proof_transcript.finalize();
    println!("Proof created successfully!");

    // 9. Verify the proof
    let mut verifier_transcript =
        Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof.as_slice());
    let verifier_params = params.verifier_params();

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
    println!(
        "Halo2 Commitment to the bitvector column: {:?}",
        halo2_commitment
    );

    // 11. Compute the commitment from the bitvector using plain KZG
    let domain = EvaluationDomain::new(1, k);

    let fresh_bitvector = vec![Fr::zero(), Fr::zero(), Fr::one(), Fr::one()];

    // Convert the bitvector into a polynomial in Lagrange basis
    let mut a = domain.empty_lagrange();
    for (i, a) in a.iter_mut().enumerate() {
        // *a = fresh_bitvector[i].assign().unwrap();
        if i < fresh_bitvector.len() {
            *a = fresh_bitvector[i];
        } else {
            *a = Fr::zero();
        }
    }

    // Compute the commitment using `ParamsKZG`'s `commit_lagrange` function,
    // with default blinding factor and Plonk engine
    let engine = PlonkEngineConfig::build_default::<G1Affine>();
    let alpha = Blind::default();

    let commitment = params.commit_lagrange(&engine.msm_backend, &a, alpha);

    let mut advice_commitments_affine = vec![
        <<KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve as PrimeCurveAffine>::identity(
        );
        1
    ];

    <<KZGCommitmentScheme<Bn256> as CommitmentScheme>::Curve as CurveAffine>::CurveExt::batch_normalize(
            &[commitment],
            &mut advice_commitments_affine,
        );
    let advice_commitments_affine = advice_commitments_affine;

    println!(
        "Commitment to the bitvector: {:?}",
        advice_commitments_affine[0]
    );

    // Compare our commitments
    assert_eq!(halo2_commitment, advice_commitments_affine[0]);
}
