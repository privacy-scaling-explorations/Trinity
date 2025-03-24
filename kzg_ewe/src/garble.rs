use fancy_garbling::{
    circuit::BinaryCircuit as Circuit,
    classic::{garble, Encoder, GarbledCircuit},
    WireLabel, WireMod2,
};
use scuttlebutt::{serialization::CanonicalSerialize, AesRng, Block};
use std::io::BufReader;
use std::sync::Arc;
use std::time::SystemTime;
use std::{fs::File, io::Error};

use crate::{
    commit::{KZGType, Trinity, TrinityChoice, TrinityCom, TrinityMsg},
    ot::KZGOTReceiver,
};

const MSG_SIZE: usize = 16;

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
    let start = SystemTime::now();
    let result = ev
        .eval(&circuit, &garbler_bundle.garbler_labels, &evaluator_labels)
        .unwrap();

    Ok(result)
}

/// Run the circuit using bool inputs (each bool representing a bit)
pub fn run_circuit_with_kzg(circuit: Circuit, gb_inputs: Vec<bool>, ev_inputs: Vec<bool>) {
    let trinity = Arc::new(Trinity::setup(KZGType::Halo2, MSG_SIZE));

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
    let ot_receiver = trinity.create_ot_receiver::<()>(&ev_trinity);
    let receiver_commitment = ot_receiver.trinity_receiver.commitment();

    // === Garbler: full garble in memory ===
    let (en, ev) = garble::<WireMod2, Circuit>(&circuit).unwrap();

    // Garbler encodes own inputs
    let gb_inputs_u16: Vec<u16> = gb_inputs.iter().map(|&b| if b { 1 } else { 0 }).collect();
    let garbler_labels = en.encode_garbler_inputs(&gb_inputs_u16);

    // === Garbler prepares evaluator wire labels ===
    let evaluator_wire_labels = en.get_evaluator_label_pairs();

    let mut rng = AesRng::new();
    let ot_sender = trinity.create_ot_sender::<()>(receiver_commitment);

    let ciphertexts: Vec<TrinityMsg> = evaluator_wire_labels
        .iter()
        .enumerate()
        .map(|(i, (zero, one))| {
            let m0: [u8; 16] = zero.as_block().to_bytes().try_into().unwrap();
            let m1: [u8; 16] = one.as_block().to_bytes().try_into().unwrap();
            ot_sender.trinity_sender.send(&mut rng, i, m0, m1)
        })
        .collect();

    // === Evaluator decrypts input labels with OT ===
    let evaluator_labels: Vec<WireMod2> = ciphertexts
        .iter()
        .enumerate()
        .map(|(i, ct)| {
            let decrypted = ot_receiver.trinity_receiver.recv(i, *ct);
            let block = Block::from_bytes(&decrypted.into()).unwrap();
            WireMod2::from_block(block, 2)
        })
        .collect();

    // === Evaluate circuit ===
    let start = SystemTime::now();
    let result = ev
        .eval(&circuit, &garbler_labels, &evaluator_labels)
        .unwrap();
    println!("✅ Result: {:?}", result);
    println!(
        "Circuit evaluation took: {} ms",
        start.elapsed().unwrap().as_millis()
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fancy_garbling::{circuit::BinaryCircuit as Circuit, classic::garble, WireLabel, WireMod2};
    use scuttlebutt::{serialization::CanonicalSerialize, AesRng};

    use crate::{
        commit::{KZGType, Trinity, TrinityChoice},
        garble::ev_commit,
    };

    use super::{
        evaluate_circuit, generate_garbled_circuit, parse_circuit, run_circuit_with_kzg, setup,
    };

    const MSG_SIZE: usize = 16;

    pub fn one() -> Vec<bool> {
        let mut bits = vec![false; 16];
        bits[0] = true; // least-significant bit = 1
        bits
    }

    #[test]
    fn test_garble() {
        let circ = parse_circuit("circuits/simple_add.txt");
        run_circuit_with_kzg(circ, one(), one());
    }

    #[test]
    fn test_modular_flow() {
        let circ = parse_circuit("circuits/simple_add.txt");
        let setup_bundle = setup(KZGType::Plain);

        let evaluator_commitment = ev_commit(one(), &setup_bundle).unwrap();

        let (en, ev) = garble::<WireMod2, Circuit>(&circ).unwrap();

        let garbled = generate_garbled_circuit(
            one(),
            en,
            &setup_bundle,
            evaluator_commitment.receiver_commitment,
        );

        let result = evaluate_circuit(circ, ev, garbled, evaluator_commitment.ot_receiver);

        println!("✅ Result: {:?}", result);
    }

    #[test]
    fn test_laconic_ot_integration() {
        println!("Starting simplified laconic OT test...");

        let ev_inputs = one();

        // Setup Trinity
        let trinity = Arc::new(Trinity::setup(KZGType::Halo2, MSG_SIZE));

        // Convert evaluator inputs to Trinity choices
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

        // Setup OT
        let ot_receiver = trinity.create_ot_receiver::<()>(&ev_trinity);
        let receiver_commitment = ot_receiver.trinity_receiver.commitment();
        let mut rng = AesRng::new();
        let ot_sender = trinity.create_ot_sender::<()>(receiver_commitment);

        // Create wire labels (manually instead of using garbled circuit)
        let n_ev_inputs = ev_inputs.len();
        let mut evaluator_wire_labels = Vec::with_capacity(n_ev_inputs);

        for _ in 0..n_ev_inputs {
            // Create random wire labels (normally done by garbler)
            let zero = WireMod2::rand(&mut rng, 2);
            let one = WireMod2::rand(&mut rng, 2);
            evaluator_wire_labels.push((zero, one));
        }

        // Send wire labels using laconic OT
        let mut ciphertexts = Vec::with_capacity(n_ev_inputs);
        for (i, (zero, one)) in evaluator_wire_labels.iter().enumerate() {
            let m0: [u8; 16] = zero
                .as_block()
                .to_bytes()
                .as_slice()
                .try_into()
                .expect("Invalid length");
            let m1: [u8; 16] = one
                .as_block()
                .to_bytes()
                .as_slice()
                .try_into()
                .expect("Invalid length");
            ciphertexts.push(ot_sender.trinity_sender.send(&mut rng, i, m0, m1));
        }

        // Decrypt wire labels using laconic OT
        let received_labels: Vec<WireMod2> = ciphertexts
            .iter()
            .enumerate()
            .map(|(i, ct)| {
                let decrypted_label = ot_receiver.trinity_receiver.recv(i, *ct);
                let block = scuttlebutt::Block::from_bytes(&decrypted_label.into()).unwrap();
                WireMod2::from_block(block, 2)
            })
            .collect();

        // Verify received labels match expected
        for (i, (choice, label)) in ev_inputs.iter().zip(received_labels.iter()).enumerate() {
            let expected = if *choice {
                &evaluator_wire_labels[i].1 // one label
            } else {
                &evaluator_wire_labels[i].0 // zero label
            };

            assert_eq!(
                label.as_block().to_bytes(),
                expected.as_block().to_bytes(),
                "Label mismatch at position {}",
                i
            );
        }

        println!("✅ Laconic OT correctly transferred the selected wire labels!");
    }
}
