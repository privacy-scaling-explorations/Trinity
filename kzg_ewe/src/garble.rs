use itybity::IntoBitIterator;
use mpz_circuits::{types::ValueType, Circuit};
use mpz_core::Block;
use mpz_garble_core::{
    Delta, EncryptedGate, Evaluator, EvaluatorOutput, Generator, GeneratorOutput, Key, Mac,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

pub struct GarbledData {}

pub fn generate_garbling_generic() -> Result<GarbledData, Box<dyn std::error::Error>> {
    Ok(GarbledData {})
}

pub fn evaluate_circuit_generic(
    gd: &GarbledData,
    evaluator_bits: Vec<u8>,
) -> Result<EvaluatorOutput, Box<dyn std::error::Error>> {
    Ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        cipher::{BlockEncrypt, KeyInit},
        Aes128,
    };
    use itybity::{FromBitIterator, IntoBitIterator, ToBits};
    use mpz_circuits::types::ValueType;
    use mpz_garble_core::{EvaluatorOutput, GeneratorOutput};

    #[test]
    fn test_generic_garble_and_evaluate() -> Result<(), Box<dyn std::error::Error>> {
        let circuit_path = "circuits/demo.txt";
        let garbler_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let evaluator_input_types = &ValueType::Array(Box::new(ValueType::U8), 1);
        let output_types = &[ValueType::Array(Box::new(ValueType::U8), 1)];

        // Provide garbler input values.
        let garbler_inputs = [1u8; 1];
        let evaluator_bits = [1u8; 1];

        // Generate the garbled circuit. Note that evaluator inputs are not consumed here.
        let gd = generate_2pc()?;

        let evaluator_output = evaluate_2pc()?;

        let output: Vec<u8> = Vec::from_lsb0_iter(
            evaluator_output
                .into_iter()
                .zip(gd.output_keys)
                .map(|(mac, key)| mac.pointer() ^ key.pointer()),
        );

        println!("Output: {:?}", output);

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
