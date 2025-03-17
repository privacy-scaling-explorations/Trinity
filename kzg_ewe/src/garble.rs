#![allow(clippy::all)]
// use fancy_garbling::circuit::BinaryCircuit as Circuit;
use fancy_garbling::garble_ext::{GarbledData, GarblerExt};
// use fancy_garbling::twopac::semihonest::garbler::Garbler;
use fancy_garbling::{
    circuit::{BinaryCircuit as Circuit, EvaluableCircuit},
    twopac::semihonest::{Evaluator, Garbler},
    FancyInput, WireMod2,
};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::UnixChannel;
use scuttlebutt::{unix_channel_pair, AesRng};
use std::fs::File;
use std::io::BufReader;
use std::time::SystemTime;

fn circuit(fname: &str) -> Circuit {
    println!("* Circuit: {}", fname);
    Circuit::parse(BufReader::new(File::open(fname).unwrap())).unwrap()
}

/// Converts a Vec<bool> to Vec<u16> where false -> 0 and true -> 1.
fn bools_to_u16(bits: Vec<bool>) -> Vec<u16> {
    bits.into_iter().map(|b| if b { 1 } else { 0 }).collect()
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
        let start = SystemTime::now();
        circ_.eval(&mut gb, &xs, &ys).unwrap();
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
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

fn one() -> Vec<bool> {
    let mut bits = vec![false; 16];
    bits[0] = true; // least-significant bit = 1
    bits
}

#[cfg(test)]
mod tests {
    use scuttlebutt::{unix_channel_pair, AesRng};

    use super::{circuit, one, run_circuit};

    #[test]
    fn test_garble() {
        let mut circ = circuit("circuits/simple_add.txt");
        run_circuit(&mut circ, one(), one());
    }
}
