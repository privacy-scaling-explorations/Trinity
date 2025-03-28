use std::sync::Arc;

use itybity::IntoBitIterator;
use mpz_circuits::Circuit;
use mpz_garble_core::{Delta, GarbledCircuit, Generator, GeneratorOutput, Key, Mac};
use rand::{rngs::StdRng, Rng};

use crate::{
    commit::{TrinityCom, TrinityMsg},
    two_pc::SetupParams,
};

pub struct GarbledBundle {
    pub garbler_macs: Vec<Mac>,
    pub ciphertexts: Vec<TrinityMsg>,
    pub garbled_circuit: GarbledCircuit,
    pub output_keys: Vec<Key>,
}

pub fn generate_garbled_circuit(
    circ: Arc<Circuit>,
    gb_inputs: [u16; 1],
    rng: &mut StdRng,
    delta: Delta,
    setup_params: &SetupParams,
    receiver_commitment: TrinityCom,
) -> GarbledBundle {
    // === Step 1: Garbler generates own input keys and authenticates inputs ===
    let garbler_bits = gb_inputs.into_iter_lsb0().collect::<Vec<bool>>();
    let garbler_input_keys: Vec<Key> = garbler_bits.iter().map(|_| rng.gen()).collect();

    // Authenticated garbler MACs for secure evaluation
    let garbler_macs: Vec<Mac> = garbler_input_keys
        .iter()
        .zip(&garbler_bits)
        .map(|(key, &bit)| key.auth(bit, &delta))
        .collect();

    // === Step 2: Garbler generates evaluator input label pairs (zero/one keys) ===
    let evaluator_label_pairs: Vec<(Key, Key)> = (0..16)
        .map(|_| {
            let zero_label: Key = rng.gen();
            let one_label = Key::from(*zero_label.as_block() ^ delta.as_block());
            (zero_label, one_label)
        })
        .collect();

    // === Step 3: Encrypt evaluator labels via OT ===
    let ot_sender = setup_params
        .trinity
        .create_ot_sender::<()>(receiver_commitment);

    let ciphertexts: Vec<TrinityMsg> = evaluator_label_pairs
        .iter()
        .enumerate()
        .map(|(i, (zero, one))| {
            let m0: [u8; 16] = zero.as_block().to_bytes().try_into().unwrap();
            let m1: [u8; 16] = one.as_block().to_bytes().try_into().unwrap();
            ot_sender.trinity_sender.send(rng, i, m0, m1)
        })
        .collect();

    // === Step 4: Garbler uses evaluator zero-labels for garbling ===
    let evaluator_zero_labels: Vec<Key> = evaluator_label_pairs
        .iter()
        .map(|(zero, _)| *zero)
        .collect();

    // keys used for garbling (garbler keys + evaluator zero-labels)
    let input_keys_for_garbling: Vec<Key> = garbler_input_keys
        .iter()
        .cloned()
        .chain(evaluator_zero_labels)
        .collect();

    // === Step 5: Garble the circuit ===
    let mut generator = Generator::default();
    let mut gen_iter = generator
        .generate_batched(&circ, delta, input_keys_for_garbling)
        .unwrap();

    let mut gates = Vec::new();
    for batch in gen_iter.by_ref() {
        gates.extend(batch.into_array());
    }

    let garbled_circuit = GarbledCircuit { gates };

    let GeneratorOutput {
        outputs: output_keys,
    } = gen_iter.finish().unwrap();

    GarbledBundle {
        garbler_macs,
        ciphertexts,
        garbled_circuit,
        output_keys,
    }
}
