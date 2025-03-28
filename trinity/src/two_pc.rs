use std::sync::Arc;

use crate::commit::{KZGType, Trinity, TrinityMsg};

const MSG_SIZE: usize = 16;

pub fn int_to_bits(n: u16) -> Vec<bool> {
    (0..16).map(|i| (n >> i) & 1 == 1).collect()
}

pub fn u8_to_vec_bool(input: [u8; 1]) -> Vec<bool> {
    (0..8).rev().map(|i| (input[0] & (1 << i)) != 0).collect()
}

#[allow(dead_code)]
fn serialize_ciphertexts(ciphertexts: &[TrinityMsg]) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(8 + ciphertexts.len() * 64); // Preallocate reasonable space

    serialized.extend(&(ciphertexts.len() as u64).to_le_bytes()); // encode length

    for ct in ciphertexts {
        let ct_bytes = ct.serialize();
        serialized.extend(&(ct_bytes.len() as u64).to_le_bytes()); // encode message length
        serialized.extend_from_slice(&ct_bytes); // append message content
    }

    serialized.shrink_to_fit(); // Reduce excessive memory allocation
    serialized
}

#[allow(dead_code)]
fn deserialize_ciphertexts(data: &[u8]) -> Vec<TrinityMsg> {
    let mut ciphertexts = Vec::new();
    let mut cursor = 0;

    let len = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap()) as usize;
    cursor += 8;

    for _ in 0..len {
        let ct_len = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;

        let ct_bytes = &data[cursor..cursor + ct_len];
        cursor += ct_len;

        ciphertexts.push(TrinityMsg::deserialize(ct_bytes));
    }
    ciphertexts
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

    use itybity::{FromBitIterator, IntoBitIterator, ToBits};
    use mpz_circuits::{types::ValueType, Circuit};
    use mpz_garble_core::{
        evaluate_garbled_circuits, Delta, EvaluatorOutput, GarbledCircuit, Generator,
        GeneratorOutput, Key, Mac,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::{
        commit::KZGType,
        evaluate::{ev_commit, evaluate_circuit},
        garble::generate_garbled_circuit,
        two_pc::{int_to_bits, setup, u8_to_vec_bool},
    };

    pub fn bool_array_to_u16(arr: &[bool]) -> Vec<u16> {
        arr.iter().map(|&b| if b { 1 } else { 0 }).collect()
    }

    #[test]
    fn two_pc_e2e_plain() {
        let mut rng = StdRng::seed_from_u64(0);

        let circ = Circuit::parse(
            "circuits/simple_8bit_add.txt",
            &[
                ValueType::Array(Box::new(ValueType::U8), 1),
                ValueType::Array(Box::new(ValueType::U8), 1),
            ],
            &[ValueType::Array(Box::new(ValueType::U8), 1)],
        )
        .unwrap();
        let setup_bundle = setup(KZGType::Plain);

        let garbler_input = [0u8];
        let evaluator_input = [0u8];

        let expected: [u8; 1] = [0u8];

        let delta = Delta::random(&mut rng);

        let arc_circuit = Arc::new(circ.clone());

        let evaluator_commitment =
            ev_commit(u8_to_vec_bool(evaluator_input), &setup_bundle).unwrap();

        let garbled = generate_garbled_circuit(
            arc_circuit.clone(),
            garbler_input,
            &mut rng,
            delta,
            &setup_bundle,
            evaluator_commitment.receiver_commitment,
        );

        let result = evaluate_circuit(
            arc_circuit,
            garbled,
            evaluator_input,
            delta,
            evaluator_commitment.ot_receiver,
        )
        .unwrap();

        println!("✅ Result: {:?}", result);

        assert!(result == expected);
    }

    #[test]
    fn two_pc_e2e_halo2() {
        let mut rng = StdRng::seed_from_u64(0);

        let circ = Circuit::parse(
            "circuits/simple_8bit_add.txt",
            &[
                ValueType::Array(Box::new(ValueType::U8), 1),
                ValueType::Array(Box::new(ValueType::U8), 1),
            ],
            &[ValueType::Array(Box::new(ValueType::U8), 1)],
        )
        .unwrap();
        let setup_bundle = setup(KZGType::Halo2);

        let garbler_input = [4u8];
        let evaluator_input = [2u8];

        let expected: [u8; 1] = [6u8];

        let delta = Delta::random(&mut rng);

        let arc_circuit = Arc::new(circ.clone());

        let evaluator_commitment =
            ev_commit(u8_to_vec_bool(evaluator_input), &setup_bundle).unwrap();

        let garbled = generate_garbled_circuit(
            arc_circuit.clone(),
            garbler_input,
            &mut rng,
            delta,
            &setup_bundle,
            evaluator_commitment.receiver_commitment,
        );

        let result = evaluate_circuit(
            arc_circuit,
            garbled,
            evaluator_input,
            delta,
            evaluator_commitment.ot_receiver,
        )
        .unwrap();

        println!("✅ Result: {:?}", result);

        assert!(result == expected);
    }

    #[test]
    fn test_garble_simple_add_ev_private() {
        let mut rng = StdRng::seed_from_u64(0);

        let circ = Circuit::parse(
            "circuits/simple_8bit_add.txt",
            &[
                ValueType::Array(Box::new(ValueType::U8), 1),
                ValueType::Array(Box::new(ValueType::U8), 1),
            ],
            &[ValueType::Array(Box::new(ValueType::U8), 1)],
        )
        .unwrap();

        let arc_circuit = Arc::new(circ.clone());

        let garbler_input = [4u8];
        let evaluator_input = [2u8];

        let expected: [u8; 1] = [6u8];

        let delta = Delta::random(&mut rng);

        // === Step 1: Garbler generates its own input keys and MACs separately ===
        let garbler_bits = garbler_input.into_iter_lsb0().collect::<Vec<bool>>();

        // Keys for garbler inputs (secret keys known to garbler)
        let garbler_input_keys: Vec<Key> = garbler_bits.iter().map(|_| rng.gen()).collect();

        // MACs (authenticated bits for garbler inputs)
        let garbler_macs: Vec<Mac> = garbler_input_keys
            .iter()
            .zip(&garbler_bits)
            .map(|(key, &bit)| key.auth(bit, &delta))
            .collect();

        // === Step 2: Garbler generates evaluator input label pairs (zero/one keys) ===
        let evaluator_label_pairs: Vec<(Key, Key)> = (0..8)
            .map(|_| {
                let zero_label: Key = rng.gen();
                let one_label = Key::from(*zero_label.as_block() ^ delta.as_block());
                (zero_label, one_label)
            })
            .collect();

        // === Step 3: Evaluator privately selects labels based on its inputs ===
        // This step simulates OT without actually performing OT.
        let evaluator_bits = evaluator_input.into_iter_lsb0().collect::<Vec<bool>>();

        let evaluator_selected_labels: Vec<Key> = evaluator_bits
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                let (zero_label, one_label) = evaluator_label_pairs[i];
                if bit {
                    one_label
                } else {
                    zero_label
                }
            })
            .collect();

        // === Step 4: Prepare input keys for garbling ===
        // Use garbler's input keys and evaluator's selected input labels.
        let input_keys_for_garbling: Vec<Key> = garbler_input_keys
            .iter()
            .cloned()
            .chain(evaluator_selected_labels.iter().cloned())
            .collect();

        // === Step 4: Garbler generates the garbled circuit ===
        let mut generator = Generator::default();
        let mut gen_iter = generator
            .generate_batched(&arc_circuit, delta, input_keys_for_garbling)
            .unwrap();

        let mut gates = Vec::new();
        for batch in gen_iter.by_ref() {
            gates.extend(batch.into_array());
        }

        let garbled_circuit = GarbledCircuit { gates };

        let GeneratorOutput {
            outputs: output_keys,
        } = gen_iter.finish().unwrap();

        // === Step 5: Evaluator privately chooses labels (MACs) for its input bits ===
        let evaluator_bits = evaluator_input.into_iter_lsb0().collect::<Vec<bool>>();

        // Evaluator privately picks its own labels based on bits
        let evaluator_labels: Vec<Key> = evaluator_bits
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                let (zero_label, one_label) = evaluator_label_pairs[i];
                if bit {
                    one_label
                } else {
                    zero_label
                }
            })
            .collect();

        // === Step 6: Prepare input MACs for evaluation (garbler MACs + evaluator labels MACs) ===
        // Evaluator MACs (labels authenticated with evaluator bits)
        let evaluator_macs: Vec<Mac> = evaluator_labels
            .iter()
            .zip(evaluator_bits)
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect();

        // Combine all MACs for evaluator (garbler_macs + evaluator_macs)
        let input_macs_for_eval = garbler_macs
            .into_iter()
            .chain(evaluator_macs)
            .collect::<Vec<_>>();

        // === Step 7: Evaluator evaluates the garbled circuit using MACs ===
        let outputs = evaluate_garbled_circuits(vec![(
            arc_circuit.clone(),
            input_macs_for_eval,
            garbled_circuit.clone(),
        )])
        .unwrap();

        for output in outputs {
            let EvaluatorOutput {
                outputs: output_macs,
            } = output;

            assert!(output_keys
                .iter()
                .zip(&output_macs)
                .zip(expected.iter_lsb0())
                .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac));

            let output: Vec<u8> = Vec::from_lsb0_iter(
                output_macs
                    .into_iter()
                    .zip(&output_keys)
                    .map(|(mac, key)| mac.pointer() ^ key.pointer()),
            );

            assert_eq!(output, expected);
        }
    }
}
