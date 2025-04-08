use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_core::Block;
use mpz_garble_core::{Delta, GarbledCircuit, Generator, GeneratorOutput, Key, Mac};
use rand::{rngs::StdRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{
    commit::{TrinityCom, TrinityMsg},
    two_pc::SetupParams,
};

#[derive(Clone, Debug)]
pub struct GarbledBundle {
    pub ciphertexts: Vec<TrinityMsg>,
    pub garbled_circuit: GarbledCircuit,
    pub decoding_bits: Vec<bool>,
    pub all_input_macs: Vec<Mac>,
}

pub fn generate_garbled_circuit(
    circ: Arc<Circuit>,
    garbler_bits: Vec<bool>,
    rng: &mut StdRng,
    delta: Delta,
    setup_params: &SetupParams,
    receiver_commitment: TrinityCom,
) -> GarbledBundle {
    let garbler_input_size = garbler_bits.len();
    let evaluator_input_size = circ.input_len() - garbler_input_size;

    let input_keys = (0..circ.input_len())
        .map(|_| rng.gen())
        .collect::<Vec<Key>>();

    // Instantiating all input MACs
    let mut all_input_macs = Vec::with_capacity(circ.input_len());
    // Create MACs for garbler inputs only (keys + bits)
    for i in 0..garbler_input_size {
        let key = &input_keys[i];
        let bit = garbler_bits[i];
        let mac = key.auth(bit, &delta);
        all_input_macs.push(mac);
    }

    // Prepare OT for evaluator's inputs
    let ot_sender = setup_params
        .trinity
        .create_ot_sender::<()>(receiver_commitment);

    // Create and collect OT ciphertexts (ONLY for evaluator's inputs)
    // Here we need to send message by label in order for the OT receiver to choose
    // the correct label
    // The garbler's input keys are already known, so we can use them directly
    let ciphertexts: Vec<TrinityMsg> = (0..evaluator_input_size)
        .map(|i| {
            let key_idx = garbler_input_size + i;
            let key = &input_keys[key_idx];

            // Create the two possible labels for this bit
            let zero_label = key.clone();
            let one_label = Key::from(*key.as_block() ^ delta.as_block());

            // Convert to bytes for OT
            let m0: [u8; 16] = zero_label.as_block().to_bytes().try_into().unwrap();
            let m1: [u8; 16] = one_label.as_block().to_bytes().try_into().unwrap();

            // Send via OT - this is where evaluator will choose which to receive
            ot_sender.trinity_sender.send(rng, i, m0, m1)
        })
        .collect();

    // Add placeholder MACs for evaluator inputs (these will be replaced during evaluation)
    for _ in 0..evaluator_input_size {
        all_input_macs.push(Mac::from(Block::ZERO));
    }

    // Garble the circuit
    let mut generator = Generator::default();
    let mut gen_iter = generator
        .generate_batched(&circ, delta, input_keys)
        .unwrap();

    let mut gates = Vec::new();
    for batch in gen_iter.by_ref() {
        gates.extend(batch.into_array());
    }

    let garbled_circuit = GarbledCircuit { gates };

    let GeneratorOutput {
        outputs: output_keys,
    } = gen_iter.finish().unwrap();

    // Include decoding bits for the output keys
    // These are the bits that will be used to decode the output
    let decoding_bits: Vec<bool> = output_keys.iter().map(|key| key.pointer()).collect();

    GarbledBundle {
        ciphertexts,
        garbled_circuit,
        decoding_bits,
        all_input_macs,
    }
}
