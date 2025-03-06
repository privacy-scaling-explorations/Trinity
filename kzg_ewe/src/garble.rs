use mpz_circuits::{
    types::{Value, ValueType},
    Circuit,
};
use mpz_garble_core::{
    encoding_state::Full, ChaChaEncoder, Delta, EncodedValue, Encoder, Evaluator, Generator,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

// export interface GarbledData {
//     circuit: string;
//     garblerInputSize: number;
//     evaluatorInputSize: number;
//     garblerInputLabels?: Label[];
//     inputLabels?: Label[][];
//     evaluatorInputLabelEncryption?: WasmMessage[];
//     outputLabels?: Label[][];
//     R: Label;
//   }

pub struct GarbledData<T> {
    pub circuit: Circuit,
    pub garbler_input_size: usize,
    pub evaluator_input_size: usize,
    pub input_labels: Vec<[EncodedValue<Full>; 2]>, // pairs for each input wire
    pub garbler_input_labels: Vec<EncodedValue<Full>>,
    pub evaluator_input_label_encryption: Vec<T>,
    pub output_labels: Vec<EncodedValue<Full>>,
    pub r: EncodedValue<Full>,
}

pub fn generate_garbling() -> Result<Vec<EncodedValue<Full>>, Box<dyn std::error::Error>> {
    // Parse circuit
    let circ = Circuit::parse(
        "circuits/demo.txt",
        &[
            ValueType::Array(Box::new(ValueType::U8), 1),
            ValueType::Array(Box::new(ValueType::U8), 1),
        ],
        &[ValueType::Array(Box::new(ValueType::Bit), 1)],
    )?;

    // Setup RNG and generate delta
    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);

    let seed: [u8; 32] = rng.gen();
    let encoder = ChaChaEncoder::new(seed);

    let inputs: Vec<EncodedValue<Full>> =
        (0..2).map(|_| encoder.encode::<u64>(0u64).into()).collect();

    // Create generator and generate circuit
    let mut gen = Generator::default();
    let mut gen_iter = gen.generate(&circ, delta, inputs.clone())?;

    // Collect all generated values
    let generated: Vec<_> = gen_iter.by_ref().collect();

    let output_encodings = gen_iter.finish()?;

    let u = output_encodings.outputs;
    u.iter().for_each(|x| println!("{:?}", x));

    // Finish generation and return result
    Ok(u)
}

// pub fn evaluate(circuit_data: Vec<EncodedValue<Full>>) -> Result<(), Box<dyn std::error::Error>> {
//     let circ = Circuit::parse(
//         "circuits/demo.txt",
//         &[
//             ValueType::Array(Box::new(ValueType::U8), 1),
//             ValueType::Array(Box::new(ValueType::U8), 1),
//         ],
//         &[ValueType::Array(Box::new(ValueType::Bit), 1)],
//     )?;

//     let mut evaluator = Evaluator::default();
//     let mut eval_iter = evaluator.evaluate(&circ, circuit_data)?;

//     // Process all evaluated values
//     let _: Vec<_> = eval_iter.by_ref().collect();

//     // Finish evaluation
//     eval_iter.finish()?;

//     Ok(())
// }
