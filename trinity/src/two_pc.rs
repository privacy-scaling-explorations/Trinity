use std::sync::Arc;

use crate::commit::{KZGType, Trinity};

const MSG_SIZE: usize = 16;

pub fn u8_vec_to_vec_bool(input: Vec<u8>) -> Vec<bool> {
    let mut result = Vec::with_capacity(input.len() * 8);

    for &byte in &input {
        // Extract all 8 bits from each byte (LSB0 order)
        for i in 0..8 {
            result.push((byte >> i) & 1 == 1);
        }
    }

    result
}

#[derive(Clone)]
pub struct SetupParams {
    pub trinity: Arc<Trinity>,
}

pub fn setup(mode: KZGType) -> SetupParams {
    let trinity = Arc::new(Trinity::setup(mode, MSG_SIZE));

    SetupParams { trinity }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use itybity::IntoBitIterator;
    use mpz_circuits::{types::ValueType, Circuit};
    use mpz_garble_core::Delta;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        commit::KZGType,
        evaluate::{ev_commit, evaluate_circuit},
        garble::generate_garbled_circuit,
        two_pc::setup,
    };

    pub fn u16_to_vec_bool(input: Vec<u16>) -> Vec<bool> {
        (0..16).map(|i| (input[0] >> i) & 1 == 1).collect() // LSB0
    }

    // pub fn u8_to_vec_bool(input: Vec<u8>) -> Vec<bool> {
    //     (0..8).map(|i| (input[0] >> i) & 1 == 1).collect() // LSB0
    // }

    #[test]
    fn two_pc_e2e_plain() {
        let mut rng = StdRng::seed_from_u64(0);

        let circ = Circuit::parse(
            "circuits/simple_16bit_add.txt",
            &[
                ValueType::Array(Box::new(ValueType::Bit), 16),
                ValueType::Array(Box::new(ValueType::Bit), 16),
            ],
            &[ValueType::Array(Box::new(ValueType::Bit), 16)],
        )
        .unwrap();
        let setup_bundle = setup(KZGType::Plain);
        let trinity = setup_bundle.clone().trinity;

        let garbler_input = [6u16];
        let garbler_bits = garbler_input.into_iter_lsb0().collect::<Vec<bool>>();
        let evaluator_input = [4u16];
        let evaluator_bits = evaluator_input.into_iter_lsb0().collect::<Vec<bool>>();
        let expected: [u16; 1] = [10u16];

        let delta = Delta::random(&mut rng);

        let arc_circuit = Arc::new(circ.clone());

        let evaluator_commitment = ev_commit(evaluator_bits.clone(), &setup_bundle).unwrap();

        let garbled = generate_garbled_circuit(
            arc_circuit.clone(),
            garbler_bits,
            &mut rng,
            delta,
            &trinity,
            evaluator_commitment.receiver_commitment,
        );

        let result = evaluate_circuit(
            arc_circuit,
            garbled,
            evaluator_bits,
            evaluator_commitment.ot_receiver,
        )
        .unwrap();

        assert!(result == u16_to_vec_bool(expected.to_vec()));
    }

    #[test]
    fn two_pc_e2e_halo2() {
        let mut rng = StdRng::seed_from_u64(0);

        let circ = Circuit::parse(
            "circuits/simple_16bit_add.txt",
            &[
                ValueType::Array(Box::new(ValueType::Bit), 16),
                ValueType::Array(Box::new(ValueType::Bit), 16),
            ],
            &[ValueType::Array(Box::new(ValueType::Bit), 16)],
        )
        .unwrap();
        let setup_bundle = setup(KZGType::Halo2);
        let trinity = setup_bundle.clone().trinity;

        let garbler_input = [6u16];
        let garbler_bits = garbler_input.into_iter_lsb0().collect::<Vec<bool>>();
        let evaluator_input = [4u16];
        let evaluator_bits = evaluator_input.into_iter_lsb0().collect::<Vec<bool>>();
        let expected: [u16; 1] = [10u16];

        let delta = Delta::random(&mut rng);

        let arc_circuit = Arc::new(circ.clone());

        let evaluator_commitment = ev_commit(evaluator_bits.clone(), &setup_bundle).unwrap();

        let garbled = generate_garbled_circuit(
            arc_circuit.clone(),
            garbler_bits,
            &mut rng,
            delta,
            &trinity,
            evaluator_commitment.receiver_commitment,
        );

        let result = evaluate_circuit(
            arc_circuit,
            garbled,
            evaluator_bits,
            evaluator_commitment.ot_receiver,
        )
        .unwrap();

        assert!(result == u16_to_vec_bool(expected.to_vec()));
    }
}
