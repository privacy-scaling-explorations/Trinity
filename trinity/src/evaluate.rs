use std::io::Error;
use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_core::Block;
use mpz_garble_core::{evaluate_garbled_circuits, Delta, EvaluatorOutput, Key, Mac};

use itybity::{FromBitIterator, IntoBitIterator};

use crate::commit::{TrinityChoice, TrinityCom};
use crate::garble::GarbledBundle;
use crate::ot::KZGOTReceiver;
use crate::SetupParams;

pub struct EvaluatorBundle<'a> {
    pub ot_receiver: KZGOTReceiver<'a, ()>,
    pub receiver_commitment: TrinityCom,
}

pub fn ev_commit(
    ev_inputs: Vec<bool>,
    setup_params: &SetupParams,
) -> Result<EvaluatorBundle, Error> {
    let ev_trinity: Vec<TrinityChoice> = ev_inputs
        .iter()
        .map(|&b| {
            if b {
                TrinityChoice::One
            } else {
                TrinityChoice::Zero
            }
        })
        .collect();

    // === Evaluator: prepare OT receiver and commitment ===
    let ot_receiver = setup_params.trinity.create_ot_receiver::<()>(&ev_trinity);
    let receiver_commitment = ot_receiver.trinity_receiver.commitment();

    Ok(EvaluatorBundle {
        ot_receiver,
        receiver_commitment,
    })
}

pub fn evaluate_circuit(
    circuit: Arc<Circuit>,
    garbler_bundle: GarbledBundle,
    evaluator_input: [u8; 1],
    delta: Delta,
    ot_receiver: KZGOTReceiver<'_, ()>,
) -> Result<Vec<u8>, Error> {
    // === Step 1: Evaluator decrypts labels for its input using OT ===
    let evaluator_bits = evaluator_input.into_iter_lsb0().collect::<Vec<bool>>();

    let evaluator_labels: Vec<Key> = garbler_bundle
        .ciphertexts
        .iter()
        .enumerate()
        .map(|(i, ct)| {
            let decrypted = ot_receiver.trinity_receiver.recv(i, *ct);
            let block = Block::new(decrypted);
            Key::from(block)
        })
        .collect();

    // === Step 2: Evaluator creates authenticated MACs for its inputs ===
    let evaluator_macs: Vec<Mac> = evaluator_labels
        .iter()
        .zip(&evaluator_bits)
        .map(|(key, &bit)| key.auth(bit, &delta))
        .collect();

    // === Step 3: Combine Garbler MACs with Evaluator MACs ===
    let input_macs_for_eval: Vec<Mac> = garbler_bundle
        .garbler_macs
        .iter()
        .cloned()
        .chain(evaluator_macs)
        .collect();

    // === Step 4: Evaluate garbled circuit using input MACs ===
    let outputs = evaluate_garbled_circuits(vec![(
        circuit.clone(),
        input_macs_for_eval,
        garbler_bundle.garbled_circuit.clone(),
    )])
    .unwrap();

    // Assuming single circuit evaluation here
    let EvaluatorOutput {
        outputs: output_macs,
    } = &outputs[0];

    // === Step 5: Decode output MACs to obtain actual bits ===
    let output: Vec<u8> = Vec::from_lsb0_iter(
        output_macs
            .iter()
            .zip(&garbler_bundle.output_keys)
            .map(|(mac, key)| mac.pointer() ^ key.pointer()),
    );

    Ok(output)
}
