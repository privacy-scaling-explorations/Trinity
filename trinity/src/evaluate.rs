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
        .into_iter()
        .map(|b| {
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
    ot_receiver: KZGOTReceiver<'_, ()>,
) -> Result<Vec<u8>, Error> {
    let evaluator_bits = evaluator_input.into_iter_lsb0().collect::<Vec<bool>>();
    let evaluator_input_size = evaluator_bits.len();
    let garbler_input_size = circuit.input_len() - evaluator_input_size;

    let mut all_input_macs = garbler_bundle.all_input_macs.clone();

    // Replace the placeholder MACs with real ones from OT
    for i in 0..evaluator_input_size {
        let ciphertext = &garbler_bundle.ciphertexts[i];

        // Get MAC via OT
        let decrypted = ot_receiver.trinity_receiver.recv(i, *ciphertext);
        let block = Block::new(decrypted);

        // Replace the placeholder at the correct position
        // (after garbler inputs)
        all_input_macs[garbler_input_size + i] = Mac::from(block);
    }

    // Evaluate the circuit with these input MACs
    let outputs = evaluate_garbled_circuits(vec![(
        circuit,
        all_input_macs,
        garbler_bundle.garbled_circuit,
    )])
    .unwrap();

    let EvaluatorOutput {
        outputs: output_macs,
    } = &outputs[0];

    // Create the final output using the decoding bits
    let output: Vec<u8> = Vec::from_lsb0_iter(
        output_macs
            .iter()
            .enumerate()
            .map(|(i, mac)| mac.pointer() ^ garbler_bundle.decoding_bits[i]),
    );

    Ok(output)
}
