use std::{error::Error, sync::Mutex};

use itybity::IntoBitIterator;
use lazy_static::lazy_static;
use mpz_circuits::{types::ValueType, Circuit};
use mpz_core::Block;
use mpz_garble_core::{
    Delta, EncryptedGate, EncryptedGateBatch, Evaluator, EvaluatorError, EvaluatorOutput,
    Generator, GeneratorOutput, Key, Mac,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

#[derive(Debug)]
pub struct GarbledData {
    // Key pairs for evaluator wires;
    pub evaluator_key_pairs: Vec<(Key, Key)>,
    // The transcript (batches of garbled gates) produced during garbling.
    pub transcript: Vec<EncryptedGateBatch<128>>,
    // The output keys from the garbling phase.
    pub output_keys: Vec<Key>,
    pub input_macs: Vec<Mac>,
    pub delta: Delta,
}

lazy_static! {
    static ref PROTOCOL_STATE: Mutex<Option<(GarbledData, EvaluatorOutput)>> = Mutex::new(None);
}

fn u8_to_bits(value: u8) -> [bool; 8] {
    [
        value & 1 != 0,
        value & 2 != 0,
        value & 4 != 0,
        value & 8 != 0,
        value & 16 != 0,
        value & 32 != 0,
        value & 64 != 0,
        value & 128 != 0,
    ]
}

pub fn generate_2pc(
    circuit: &Circuit,
    garbler_input: &[u8],
) -> Result<GarbledData, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(0);
    let garbler_bits: Vec<bool> = garbler_input.iter().flat_map(|&b| u8_to_bits(b)).collect();
    let total_wires = circuit.input_len();
    let garbler_wires = garbler_bits.len();
    let evaluator_wires = total_wires - garbler_wires;

    let garbler_keys: Vec<Key> = (0..garbler_wires).map(|_| rng.gen()).collect();
    let evaluator_key_pairs: Vec<(Key, Key)> = (0..evaluator_wires)
        .map(|_| (rng.gen(), rng.gen()))
        .collect();

    let delta = Delta::random(&mut rng);
    let garbler_macs: Vec<Mac> = garbler_keys
        .iter()
        .zip(garbler_bits.iter())
        .map(|(key, &bit)| key.auth(bit, &delta))
        .collect();

    let evaluator_dummy_keys: Vec<Key> = evaluator_key_pairs
        .iter()
        .map(|(key0, _)| key0.clone())
        .collect();
    let evaluator_dummy_macs: Vec<Mac> = evaluator_dummy_keys
        .iter()
        .map(|key| key.auth(false, &delta))
        .collect();

    let mut input_keys = Vec::new();
    input_keys.extend(garbler_keys.clone());
    input_keys.extend(evaluator_dummy_keys);
    let mut input_macs = Vec::new();
    input_macs.extend(garbler_macs);
    input_macs.extend(evaluator_dummy_macs);

    let mut gen = Generator::default();
    let mut gen_iter = gen.generate_batched(circuit, delta, input_keys)?;
    let mut transcript = Vec::new();
    while let Some(batch) = gen_iter.next() {
        transcript.push(batch);
    }
    let GeneratorOutput {
        outputs: output_keys,
    } = gen_iter.finish()?;

    Ok(GarbledData {
        evaluator_key_pairs,
        transcript,
        output_keys,
        input_macs,
        delta,
    })
}

pub fn evaluate_2pc(
    circuit: &Circuit,
    gd: &mut GarbledData,
    evaluator_input: &[u8],
) -> Result<mpz_garble_core::EvaluatorOutput, EvaluatorError> {
    let evaluator_bits: Vec<bool> = evaluator_input
        .iter()
        .flat_map(|&b| u8_to_bits(b))
        .collect();
    let evaluator_keys: Vec<Key> = gd
        .evaluator_key_pairs
        .iter()
        .zip(evaluator_bits.iter())
        .map(|(&(ref key0, ref key1), &bit)| if bit { key1.clone() } else { key0.clone() })
        .collect();

    let evaluator_macs: Vec<Mac> = evaluator_keys
        .iter()
        .zip(evaluator_bits.iter())
        .map(|(key, &bit)| key.auth(bit, &gd.delta))
        .collect();

    let total_wires = circuit.input_len();
    let garbler_wires = total_wires - gd.evaluator_key_pairs.len();

    gd.input_macs.splice(garbler_wires.., evaluator_macs);

    let mut ev = Evaluator::default();
    let mut ev_consumer = ev.evaluate_batched(circuit, gd.input_macs.clone())?;
    for batch in std::mem::take(&mut gd.transcript) {
        ev_consumer.next(batch);
    }
    ev_consumer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use itybity::{FromBitIterator, IntoBitIterator, ToBits};
    use mpz_circuits::types::ValueType;
    use mpz_garble_core::{EvaluatorOutput, GeneratorOutput};

    #[test]
    fn test_generic_garble_and_evaluate() -> Result<(), Box<dyn std::error::Error>> {
        let circuit_path = "circuits/demo.txt";
        let garbler_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let evaluator_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let output_types = &[ValueType::Array(Box::new(ValueType::U8), 1)];
        let input_types = &[garbler_input_types.clone(), evaluator_input_types.clone()];
        let circ = Circuit::parse(circuit_path, input_types, output_types)
            .unwrap()
            .reverse_input(0)
            .reverse_input(1)
            .reverse_output(0);

        // Provide garbler input values.
        let garbler_inputs = [1u8; 1];
        let evaluator_bits = [1u8; 1];

        let expected = [2u8; 1];

        // Generate the garbled circuit.
        let mut gd = generate_2pc(&circ, &garbler_inputs)?;

        let evaluator_output = evaluate_2pc(&circ, &mut gd, &evaluator_bits)?;

        let output: Vec<u8> = Vec::from_lsb0_iter(
            evaluator_output
                .outputs
                .into_iter()
                .zip(gd.output_keys)
                .map(|(mac, key)| mac.pointer() ^ key.pointer()),
        );

        println!("Decrypted Output: {:?}", output);

        assert_eq!(output, expected);

        Ok(())
    }

    #[test]
    fn test_simple() {
        let circuit_path = "circuits/demo.txt";
        let garbler_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let evaluator_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let output_types = &[ValueType::Array(Box::new(ValueType::U8), 1)];

        let input_types = &[garbler_input_types.clone(), evaluator_input_types.clone()];
        let circ = Circuit::parse(circuit_path, input_types, output_types)
            .unwrap()
            .reverse_input(0)
            .reverse_input(1)
            .reverse_output(0);

        let mut rng = StdRng::seed_from_u64(0);

        let input_a = [1u8; 1];
        let input_b = [1u8; 1];

        let expected: [u8; 1] = [2u8; 1];

        let delta = Delta::random(&mut rng);
        let input_keys = (0..circ.input_len())
            .map(|_| rng.gen())
            .collect::<Vec<Key>>();

        let input_macs = input_keys
            .iter()
            .zip(input_a.iter().copied().chain(input_b).into_iter_lsb0())
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let mut gen = Generator::default();
        let mut ev = Evaluator::default();

        let mut gen_iter = gen.generate_batched(&circ, delta, input_keys).unwrap();
        let mut ev_consumer = ev.evaluate_batched(&circ, input_macs).unwrap();

        for batch in gen_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GeneratorOutput {
            outputs: output_keys,
        } = gen_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        assert!(output_keys
            .iter()
            .zip(&output_macs)
            .zip(expected.iter_lsb0())
            .all(|((key, mac), bit)| &key.auth(bit, &delta) == mac));

        let output: Vec<u8> = Vec::from_lsb0_iter(
            output_macs
                .into_iter()
                .zip(output_keys)
                .map(|(mac, key)| mac.pointer() ^ key.pointer()),
        );

        println!("Output: {:?}", output);

        assert_eq!(output, expected);
    }

    #[test]
    fn test_2pc() {
        let circuit_path = "circuits/demo.txt";
        let garbler_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let evaluator_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let output_types = &[ValueType::Array(Box::new(ValueType::U8), 1)];

        let input_types = &[garbler_input_types.clone(), evaluator_input_types.clone()];
        let circ = Circuit::parse(circuit_path, input_types, output_types)
            .unwrap()
            .reverse_input(0)
            .reverse_input(1)
            .reverse_output(0);

        let mut rng = StdRng::seed_from_u64(0);

        // Define the inputs separately:
        let garbler_input = [5u8; 1];
        let evaluator_input = [7u8; 1];
        let expected: [u8; 1] = [12u8; 1];

        let delta = Delta::random(&mut rng);

        // Decompose the u8 inputs into bits (each will produce 8 bits)
        let garbler_bits: Vec<bool> = garbler_input
            .iter()
            .flat_map(|&byte| u8_to_bits(byte))
            .collect();
        let evaluator_bits: Vec<bool> = evaluator_input
            .iter()
            .flat_map(|&byte| u8_to_bits(byte))
            .collect();

        // --- Garbler's input key generation (one key per bit) ---
        let garbler_keys = (0..garbler_bits.len())
            .map(|_| rng.gen())
            .collect::<Vec<Key>>();

        // --- Evaluator's input key generation (simulate OT for each bit) ---
        let evaluator_key_pairs = (0..evaluator_bits.len())
            .map(|_| (rng.gen::<Key>(), rng.gen::<Key>()))
            .collect::<Vec<_>>();

        // Evaluator selects the correct key based on his input bit:
        let evaluator_keys: Vec<Key> = evaluator_key_pairs
            .iter()
            .zip(evaluator_bits.iter())
            .map(
                |(&(ref key0, ref key1), &bit)| {
                    if bit {
                        key1.clone()
                    } else {
                        key0.clone()
                    }
                },
            )
            .collect();

        // --- Compute MACs for inputs ---
        let garbler_macs = garbler_keys
            .iter()
            .zip(garbler_bits.iter())
            .map(|(key, &bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        let evaluator_macs = evaluator_keys
            .iter()
            .zip(evaluator_bits.iter())
            .map(|(key, &bit)| key.auth(bit, &delta))
            .collect::<Vec<_>>();

        // --- Combine inputs for garbling and evaluation ---
        // The circuit expects keys for every bit.
        let mut input_keys = vec![];
        input_keys.extend(garbler_keys.clone());
        input_keys.extend(evaluator_keys.clone());

        let mut input_macs = vec![];
        input_macs.extend(garbler_macs);
        input_macs.extend(evaluator_macs);

        let mut gen = Generator::default();
        let mut ev = Evaluator::default();

        let mut gen_iter = gen.generate_batched(&circ, delta, input_keys).unwrap();
        let mut ev_consumer = ev.evaluate_batched(&circ, input_macs).unwrap();

        for batch in gen_iter.by_ref() {
            ev_consumer.next(batch);
        }

        let GeneratorOutput {
            outputs: output_keys,
        } = gen_iter.finish().unwrap();
        let EvaluatorOutput {
            outputs: output_macs,
        } = ev_consumer.finish().unwrap();

        // Simulate output recovery by XOR-ing pointer values:
        let output: Vec<u8> = Vec::from_lsb0_iter(
            output_macs
                .into_iter()
                .zip(output_keys)
                .map(|(mac, key)| mac.pointer() ^ key.pointer()),
        );

        println!("Output: {:?}", output);
        assert_eq!(output, expected);
    }
}
