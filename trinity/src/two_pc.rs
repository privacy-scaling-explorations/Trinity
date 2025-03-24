use fancy_garbling::circuit::BinaryCircuit as Circuit;
use std::io::BufReader;
use std::sync::Arc;
use std::{fs::File, io::Error};

use crate::{
    commit::{KZGType, Trinity, TrinityChoice, TrinityCom, TrinityMsg},
    ot::KZGOTReceiver,
};

const MSG_SIZE: usize = 16;

pub fn int_to_bits(n: u16) -> Vec<bool> {
    (0..16).map(|i| (n >> i) & 1 == 1).collect()
}

pub fn parse_circuit(fname: &str) -> Circuit {
    println!("* Circuit: {}", fname);
    Circuit::parse(BufReader::new(File::open(fname).unwrap())).unwrap()
}

/// Converts a Vec<bool> to Vec<u16> where false -> 0 and true -> 1.
pub fn bools_to_u16(bits: Vec<bool>) -> Vec<u16> {
    bits.into_iter().map(|b| if b { 1 } else { 0 }).collect()
}

#[allow(dead_code)]
fn serialize_ciphertexts(ciphertexts: &[TrinityMsg]) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(8 + ciphertexts.len() * 64); // Preallocate reasonable space

    serialized.extend(&(ciphertexts.len() as u64).to_le_bytes()); // encode length

    for ct in ciphertexts {
        let ct_bytes = ct.serialize();
        serialized.extend(&(ct_bytes.len() as u64).to_le_bytes()); // encode message length
        serialized.extend_from_slice(&ct_bytes); // append message content
    }

    serialized.shrink_to_fit(); // Reduce excessive memory allocation
    serialized
}

#[allow(dead_code)]
fn deserialize_ciphertexts(data: &[u8]) -> Vec<TrinityMsg> {
    let mut ciphertexts = Vec::new();
    let mut cursor = 0;

    let len = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap()) as usize;
    cursor += 8;

    for _ in 0..len {
        let ct_len = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;

        let ct_bytes = &data[cursor..cursor + ct_len];
        cursor += ct_len;

        ciphertexts.push(TrinityMsg::deserialize(ct_bytes));
    }
    ciphertexts
}

pub struct SetupParams {
    pub trinity: Arc<Trinity>,
}

pub fn setup(mode: KZGType) -> SetupParams {
    let trinity = Arc::new(Trinity::setup(mode, MSG_SIZE));

    SetupParams { trinity }
}

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

#[cfg(test)]
mod tests {
    use fancy_garbling::{circuit::BinaryCircuit, classic::garble, WireMod2};

    use crate::{
        commit::KZGType,
        evaluate::evaluate_circuit,
        garble::generate_garbled_circuit,
        two_pc::{ev_commit, int_to_bits, parse_circuit, setup},
    };

    pub fn bool_array_to_u16(arr: &[bool]) -> Vec<u16> {
        arr.iter().map(|&b| if b { 1 } else { 0 }).collect()
    }

    #[test]
    fn two_pc_e2e_plain() {
        let circ = parse_circuit("circuits/simple_add.txt");
        let setup_bundle = setup(KZGType::Plain);

        let garbler_input = int_to_bits(2);
        let evaluator_input = int_to_bits(3);
        let expected_result_bool = int_to_bits(5);

        let expected_result: Vec<u16> = bool_array_to_u16(&expected_result_bool);

        let evaluator_commitment = ev_commit(evaluator_input, &setup_bundle).unwrap();

        let (en, ev) = garble::<WireMod2, BinaryCircuit>(&circ).unwrap();

        let garbled = generate_garbled_circuit(
            garbler_input,
            en,
            &setup_bundle,
            evaluator_commitment.receiver_commitment,
        );

        let result = evaluate_circuit(circ, ev, garbled, evaluator_commitment.ot_receiver).unwrap();

        println!("✅ Result: {:?}", result);

        assert!(result == expected_result);
    }

    #[test]
    fn two_pc_e2e_halo2() {
        let circ = parse_circuit("circuits/simple_add.txt");
        let setup_bundle = setup(KZGType::Halo2);

        let garbler_input = int_to_bits(2);
        let evaluator_input = int_to_bits(3);
        let expected_result_bool = int_to_bits(5);

        let expected_result: Vec<u16> = bool_array_to_u16(&expected_result_bool);

        let evaluator_commitment = ev_commit(evaluator_input, &setup_bundle).unwrap();

        let (en, ev) = garble::<WireMod2, BinaryCircuit>(&circ).unwrap();

        let garbled = generate_garbled_circuit(
            garbler_input,
            en,
            &setup_bundle,
            evaluator_commitment.receiver_commitment,
        );

        let result = evaluate_circuit(circ, ev, garbled, evaluator_commitment.ot_receiver).unwrap();

        println!("✅ Result: {:?}", result);

        assert!(result == expected_result);
    }
}
