use fancy_garbling::{
    circuit::BinaryCircuit as Circuit, classic::GarbledCircuit, WireLabel, WireMod2,
};
use scuttlebutt::{serialization::CanonicalSerialize, Block};
use std::io::Error;

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
    circuit: Circuit,
    ev: GarbledCircuit<WireMod2, Circuit>,
    garbler_bundle: GarbledBundle,
    ot_receiver: KZGOTReceiver<'_, ()>,
) -> Result<Vec<u16>, Error> {
    // === Evaluator decrypts input labels with OT ===
    let evaluator_labels: Vec<WireMod2> = garbler_bundle
        .ciphertexts
        .iter()
        .enumerate()
        .map(|(i, ct)| {
            let decrypted = ot_receiver.trinity_receiver.recv(i, *ct);
            let block = Block::from_bytes(&decrypted.into()).unwrap();
            WireMod2::from_block(block, 2)
        })
        .collect();

    // === Evaluate circuit ===
    let result = ev
        .eval(&circuit, &garbler_bundle.garbler_labels, &evaluator_labels)
        .unwrap();

    Ok(result)
}
