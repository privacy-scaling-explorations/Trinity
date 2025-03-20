use fancy_garbling::{
    circuit::{BinaryCircuit as Circuit, EvaluableCircuit},
    twopac::semihonest::{Evaluator, Garbler},
    Evaluator as Ev, FancyInput, Garbler as Gb, WireLabel, WireMod2,
};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{serialization::CanonicalSerialize, unix_channel_pair, AesRng};
use scuttlebutt::{AbstractChannel, UnixChannel};
use std::io::BufReader;
use std::time::SystemTime;
use std::{fs::File, sync::Arc};

use crate::commit::{KZGType, Trinity, TrinityChoice, TrinityMsg};

const MSG_SIZE: usize = 16;

fn circuit(fname: &str) -> Circuit {
    println!("* Circuit: {}", fname);
    Circuit::parse(BufReader::new(File::open(fname).unwrap())).unwrap()
}

/// Converts a Vec<bool> to Vec<u16> where false -> 0 and true -> 1.
fn bools_to_u16(bits: Vec<bool>) -> Vec<u16> {
    bits.into_iter().map(|b| if b { 1 } else { 0 }).collect()
}

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

/// Run the circuit using bool inputs (each bool representing a bit)
fn run_circuit(circ: &mut Circuit, gb_inputs: Vec<bool>, ev_inputs: Vec<bool>) {
    // Convert bools to u16 bits.
    let gb_inputs_u16 = bools_to_u16(gb_inputs);
    let ev_inputs_u16 = bools_to_u16(ev_inputs);
    let circ_ = circ.clone();
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs_u16.len();
    let n_ev_inputs = ev_inputs_u16.len();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<UnixChannel, AesRng, OtSender, WireMod2>::new(sender, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb
            .encode_many(&gb_inputs_u16, &vec![2; n_gb_inputs])
            .unwrap();
        let ys = gb.receive_many(&vec![2; n_ev_inputs]).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!("ys wires: {:?}", ys);
        let start = SystemTime::now();
        let garbled_data = circ_.eval(&mut gb, &xs, &ys).unwrap();
        println!(
            "Garbler :: Circuit garbling: {} ms",
            start.elapsed().unwrap().as_millis()
        );
    });
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev =
        Evaluator::<UnixChannel, AesRng, OtReceiver, WireMod2>::new(receiver, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![2; n_gb_inputs]).unwrap();
    let ys = ev
        .encode_many(&ev_inputs_u16, &vec![2; n_ev_inputs])
        .unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let result = circ.eval(&mut ev, &xs, &ys).unwrap();
    println!("result: {:?}", result.expect("evaluation failed"));
    println!(
        "Evaluator :: Circuit evaluation: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    // handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

/// Run the circuit using bool inputs (each bool representing a bit)
fn run_circuit_with_kzg<'a>(circ: Circuit, gb_inputs: Vec<bool>, ev_inputs: Vec<bool>) {
    let trinity = Arc::new(Trinity::setup(KZGType::Plain, MSG_SIZE));

    let trinity_gb = Arc::clone(&trinity);
    let trinity_ev = Arc::clone(&trinity);

    let ev_trinity: Vec<TrinityChoice> = ev_inputs
        .clone()
        .into_iter()
        .map(|b| {
            if b {
                TrinityChoice::One
            } else {
                TrinityChoice::Zero
            }
        })
        .collect();

    // Evaluator prepares commitment offline (simulated here for clarity)
    let ot_receiver = trinity_gb.create_ot_receiver::<()>(&ev_trinity);
    let receiver_commitment = ot_receiver.trinity_receiver.commitment();

    // Convert bools to u16 bits
    let gb_inputs_u16 = bools_to_u16(gb_inputs);
    let ev_inputs_u16 = bools_to_u16(ev_inputs);

    let circ_gb = circ.clone();
    let circ_ev = circ;

    let (sender, receiver) = unix_channel_pair();

    let n_gb_inputs = gb_inputs_u16.len();
    let n_ev_inputs = ev_inputs_u16.len();

    let total = SystemTime::now();

    let handle_gb = std::thread::spawn(move || {
        let mut rng = AesRng::new();

        let ot_sender = trinity_ev.create_ot_sender::<()>(receiver_commitment);

        // Garbler initialization
        let mut gb = Gb::<UnixChannel, AesRng, _>::new(sender, rng.clone());

        // Garbler encodes own input wires (no OT required here)
        let (gb_wires, _): (Vec<WireMod2>, Vec<WireMod2>) = gb
            .encode_many_wires(&gb_inputs_u16, &vec![2; n_gb_inputs])
            .unwrap();

        // Garbler explicitly generates evaluator's wires labels for OT replacement
        let evaluator_wire_labels: Vec<(WireMod2, WireMod2)> = (0..n_ev_inputs)
            .map(|_| gb.encode_wire(0, 2)) // Generate fresh zero and one labels
            .collect();

        println!("We're about to send");
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
        println!("Actually sent!");

        let serialized_ciphertexts = serialize_ciphertexts(&ciphertexts);
        // Send ciphertexts instead of classical OT
        println!("Serialization done!");
        println!(
            "Serialized ciphertexts size: {} bytes",
            serialized_ciphertexts.len()
        );

        gb.channel
            .write_usize(serialized_ciphertexts.len())
            .unwrap();
        gb.channel.write_bytes(&serialized_ciphertexts).unwrap();

        gb.channel.flush().unwrap();

        println!("Serialized bytes sent to channel!");

        // Extract only zero-label wires (which garbler keeps for evaluation)
        let ev_wires_garbler_view: Vec<WireMod2> = evaluator_wire_labels
            .iter()
            .map(|(zero_label, _)| zero_label.clone())
            .collect();

        // Now perform circuit garbling with correctly encoded wires
        circ_gb
            .eval(&mut gb, &gb_wires, &ev_wires_garbler_view)
            .unwrap();
    });

    let mut ev = Ev::<UnixChannel, WireMod2>::new(receiver);

    let gb_wires: Vec<WireMod2> = (0..n_gb_inputs).map(|_| ev.read_wire(2).unwrap()).collect();

    // Now safely read the expected number of bytes
    // let ct_len = ev.channel.read_usize().unwrap();
    // let serialized_ciphertexts = ev.channel.read_vec(ct_len).unwrap();

    // In run_circuit_with_kzg, around line 232:
    let ct_len = ev.channel.read_usize().unwrap();
    println!("Read length value: {}", ct_len); // Debug the exact value

    // Add a sanity check to prevent absurd allocations
    const MAX_REASONABLE_SIZE: usize = 10_000_000; // 10MB is more than enough
    if ct_len > MAX_REASONABLE_SIZE {
        panic!(
            "Suspiciously large message size: {} bytes (max allowed: {})",
            ct_len, MAX_REASONABLE_SIZE
        );
    }

    let serialized_ciphertexts = ev.channel.read_vec(ct_len).unwrap();

    println!("Received serialized ciphertexts!");
    println!(
        "Serialized ciphertexts len: {:?}",
        serialized_ciphertexts.len()
    );

    // Deserialize ciphertexts properly
    let ciphertexts: Vec<TrinityMsg> = deserialize_ciphertexts(&serialized_ciphertexts);

    // Explicitly decrypt evaluator wires
    let ev_wires_ev: Vec<WireMod2> = ciphertexts
        .iter()
        .enumerate()
        .map(|(i, ct)| {
            let decrypted_label = ot_receiver.trinity_receiver.recv(i, *ct);
            let block = scuttlebutt::Block::from_bytes(&decrypted_label.into()).unwrap();
            WireMod2::from_block(block, 2)
        })
        .collect();

    // Evaluate circuit explicitly
    let result = circ_ev.eval(&mut ev, &gb_wires, &ev_wires_ev).unwrap();

    // Wait for both threads clearly
    handle_gb.join().unwrap();

    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

fn one() -> Vec<bool> {
    let mut bits = vec![false; 16];
    bits[0] = true; // least-significant bit = 1
    bits
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fancy_garbling::{
        circuit::EvaluableCircuit, Evaluator as Ev, Garbler as Gb, WireLabel, WireMod2,
    };
    use scuttlebutt::{serialization::CanonicalSerialize, unix_channel_pair, AesRng};

    use crate::{
        commit::{KZGType, Trinity, TrinityChoice},
        garble::bools_to_u16,
    };

    use super::{circuit, one, run_circuit, run_circuit_with_kzg};

    const MSG_SIZE: usize = 16;

    #[test]
    fn test_garble() {
        println!("start the test now!");
        let circ = circuit("circuits/8bit_xor.txt");
        run_circuit_with_kzg(circ, one(), one());
    }

    #[test]
    fn test_laconic_ot_integration() {
        println!("Starting simplified laconic OT test...");

        // Load circuit and prepare inputs
        let circ = circuit("circuits/8bit_xor.txt");
        let gb_inputs = one();
        let ev_inputs = one();

        // Setup Trinity
        let trinity = Arc::new(Trinity::setup(KZGType::Plain, MSG_SIZE));

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
