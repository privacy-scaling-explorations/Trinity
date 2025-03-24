use fancy_garbling::{classic::Encoder, WireLabel, WireMod2};
use scuttlebutt::{serialization::CanonicalSerialize, AesRng};

use crate::{
    commit::{TrinityCom, TrinityMsg},
    two_pc::SetupParams,
};

pub struct GarbledBundle {
    pub garbler_labels: Vec<WireMod2>,
    pub ciphertexts: Vec<TrinityMsg>,
}

pub fn generate_garbled_circuit(
    gb_inputs: Vec<bool>,
    en: Encoder<WireMod2>,
    setup_params: &SetupParams,
    receiver_commitment: TrinityCom,
) -> GarbledBundle {
    // Garbler encodes own inputs
    let gb_inputs_u16: Vec<u16> = gb_inputs.iter().map(|&b| if b { 1 } else { 0 }).collect();
    let garbler_labels = en.encode_garbler_inputs(&gb_inputs_u16);

    // === Garbler prepares evaluator wire labels ===
    let evaluator_wire_labels = en.get_evaluator_label_pairs();

    let mut rng = AesRng::new();
    let ot_sender = setup_params
        .trinity
        .create_ot_sender::<()>(receiver_commitment);

    let ciphertexts: Vec<TrinityMsg> = evaluator_wire_labels
        .iter()
        .enumerate()
        .map(|(i, (zero, one))| {
            let m0: [u8; 16] = zero.as_block().to_bytes().try_into().unwrap();
            let m1: [u8; 16] = one.as_block().to_bytes().try_into().unwrap();
            ot_sender.trinity_sender.send(&mut rng, i, m0, m1)
        })
        .collect();

    GarbledBundle {
        garbler_labels,
        ciphertexts,
    }
}
