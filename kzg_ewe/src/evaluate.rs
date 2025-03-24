use fancy_garbling::{
    circuit::BinaryCircuit as Circuit, classic::GarbledCircuit, WireLabel, WireMod2,
};
use scuttlebutt::{serialization::CanonicalSerialize, Block};
use std::io::Error;

use crate::garble::GarbledBundle;
use crate::ot::KZGOTReceiver;

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
