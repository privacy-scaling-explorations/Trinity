// use crate::bitvector::{BitvectorCommitment, CommitmentStrategy};

fn main() {
    // let bits = vec![false, false, true, true];

    // // Using plain KZG
    // let commitment_kzg = BitvectorCommitment::new(bits.clone(), CommitmentStrategy::PlainKZG, 4);

    // // Using Halo2 circuit
    // let commitment_halo2 = BitvectorCommitment::new(bits, CommitmentStrategy::Halo2Circuit, 4);

    run_circuit_commitment();

    // assert_eq!(commitment_kzg.commitment, commitment_halo2.commitment);
}
