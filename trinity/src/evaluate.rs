use std::io::Error;
use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_core::Block;
use mpz_garble_core::{evaluate_garbled_circuits, EvaluatorOutput, GarbledCircuit, Mac};

use itybity::FromBitIterator;

use crate::commit::{TrinityChoice, TrinityCom, TrinityMsg};
use crate::garble::{GarbledBundle, SerializableGarbledCircuit};
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
    let ot_receiver = setup_params
        .trinity
        .create_ot_receiver::<()>(&ev_trinity)
        .expect("Error while create the ot receiver.");
    let receiver_commitment = ot_receiver.trinity_receiver.commitment();

    Ok(EvaluatorBundle {
        ot_receiver,
        receiver_commitment,
    })
}

pub fn evaluate_circuit(
    circuit: Arc<Circuit>,
    garbler_bundle: GarbledBundle,
    evaluator_bits: Vec<bool>,
    ot_receiver: KZGOTReceiver<'_, ()>,
) -> Result<Vec<bool>, Error> {
    let evaluator_input_size = evaluator_bits.len();
    let garbler_input_size = circuit.input_len() - evaluator_input_size;

    let mut all_input_macs = garbler_bundle.all_input_macs.clone();

    // Replace the placeholder MACs with real ones from OT
    for i in 0..evaluator_input_size {
        let serialized_ciphertext = &garbler_bundle.ciphertexts[i];
        let ciphertext = TrinityMsg::try_from(serialized_ciphertext.clone())
            .expect("Error while converting ciphertext.");

        // Get MAC via OT
        let decrypted = ot_receiver.trinity_receiver.recv(i, ciphertext);
        let block = Block::new(decrypted);

        // Replace the placeholder at the correct position
        // (after garbler inputs)
        all_input_macs[garbler_input_size + i] = Mac::from(block);
    }

    let garbled_circuit: GarbledCircuit =
        SerializableGarbledCircuit::from(garbler_bundle.garbled_circuit).into();

    // Evaluate the circuit with these input MACs
    let outputs =
        evaluate_garbled_circuits(vec![(circuit, all_input_macs, garbled_circuit)]).unwrap();

    let EvaluatorOutput {
        outputs: output_macs,
    } = &outputs[0];

    // Create the final output using the decoding bits
    let output: Vec<bool> = Vec::from_lsb0_iter(
        output_macs
            .iter()
            .enumerate()
            .map(|(i, mac)| mac.pointer() ^ garbler_bundle.decoding_bits[i]),
    );

    Ok(output)
}
