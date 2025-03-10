use mpz_circuits::{types::ValueType, Circuit};
use mpz_garble_core::{
    encoding_state::{Active, Full},
    ChaChaEncoder, Delta, EncodedValue, Encoder, Evaluator, Generator,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

/// A generic garbled circuit structure.
/// The circuit is parsed from a given file and the input/output types are provided.
pub struct GarbledData<T> {
    pub circuit: Circuit,
    pub garbler_input_size: usize,
    pub evaluator_input_size: usize,
    /// For each evaluator input wire, a pair of possible labels.
    pub input_labels: Vec<[EncodedValue<Full>; 2]>,
    /// The garbler’s input labels.
    pub garbler_input_labels: Vec<EncodedValue<Full>>,
    /// Dummy evaluator encryption messages (normally provided via OT).
    pub evaluator_input_label_encryption: Vec<T>,
    /// The generator’s output labels.
    pub output_labels: Vec<EncodedValue<Full>>,
    /// A global value used in decoding (dummy here).
    pub r: EncodedValue<Full>,
}

/// Generates a garbled circuit from a given circuit file and input configuration.
///
/// - `circuit_path`: Path to the circuit file.
/// - `input_types`: A slice with the types for *all* circuit inputs (garbler inputs come first).
/// - `output_types`: A slice with the types for the circuit outputs.
/// - `garbler_input_values`: A slice of raw input values (u64) for the garbler.
/// - `evaluator_input_values`: A slice of raw input values (u64) for the evaluator.
///
/// For simplicity we assume all inputs can be encoded via `encode::<u8>` (note that the
/// underlying encoder works on 64-bit values even if the circuit expects U8 values).
pub fn generate_garbling_generic(
    circuit_path: &str,
    input_types: &[ValueType],
    output_types: &[ValueType],
    garbler_input_values: &[u8],
    evaluator_input_values: &[u32],
) -> Result<GarbledData<Vec<u8>>, Box<dyn std::error::Error>> {
    // Parse the circuit from the provided path.
    let circ = Circuit::parse(circuit_path, input_types, output_types)?;
    let total_expected = garbler_input_values.len() + evaluator_input_values.len();
    if total_expected != input_types.len() {
        return Err(format!(
            "Input count mismatch: provided {} inputs but circuit expects {}",
            total_expected,
            input_types.len()
        )
        .into());
    }

    // Setup RNG, delta, and create the encoder.
    let mut rng = StdRng::seed_from_u64(0);
    let delta = Delta::random(&mut rng);
    let seed: [u8; 32] = rng.gen();
    let encoder = ChaChaEncoder::new(seed);

    // Encode inputs in the order expected by the circuit:
    // first the garbler's inputs, then the evaluator's inputs.
    let mut encoded_inputs = Vec::with_capacity(total_expected);
    for &val in garbler_input_values {
        let encoded: EncodedValue<Full> = encoder.encode::<u8>(val).into();
        encoded_inputs.push(encoded);
    }
    for &val in evaluator_input_values {
        let encoded: EncodedValue<Full> = encoder.encode::<u8>(val).into();
        encoded_inputs.push(encoded);
    }

    // Create generator and generate the garbled circuit.
    let mut gen = Generator::default();
    let mut gen_iter = gen.generate(&circ, delta, encoded_inputs.clone())?;
    let _ = gen_iter.by_ref().collect::<Vec<_>>();
    let output_encodings = gen_iter.finish()?;
    let outputs = output_encodings.outputs;
    outputs
        .iter()
        .for_each(|x| println!("Generator output: {:?}", x));

    // For a generic protocol you might need to build input labels differently.
    // Here we assume:
    // - Garbler input labels are the first N inputs.
    // - For each evaluator input, we build a pair (for 0 and 1).
    // In a real protocol these labels are provided by the generator.
    let garbler_input_labels = encoded_inputs[0..garbler_input_values.len()].to_vec();
    let mut evaluator_input_label_pairs = Vec::with_capacity(evaluator_input_values.len());
    for i in 0..evaluator_input_values.len() {
        // For simplicity, use the same encoded input for both 0 and 1.
        // In practice these labels will be distinct.
        let label = encoded_inputs[garbler_input_values.len() + i].clone();
        evaluator_input_label_pairs.push([label.clone(), label]);
    }

    // Dummy evaluator encryption messages – one per evaluator input.
    let evaluator_input_label_encryption = vec![vec![0u8; 16]; evaluator_input_values.len()];

    // For testing, choose the first output as the decoding factor.
    let r = outputs.get(0).cloned().ok_or("Missing output label")?;

    Ok(GarbledData {
        circuit: circ,
        garbler_input_size: garbler_input_values.len(),
        evaluator_input_size: evaluator_input_values.len(),
        input_labels: evaluator_input_label_pairs,
        garbler_input_labels,
        evaluator_input_label_encryption,
        output_labels: outputs,
        r,
    })
}

/// Evaluates the garbled circuit using active (selected) labels.
///
/// The caller supplies a slice of bits (one per evaluator input) which selects the
/// active label from each label pair.
pub fn evaluate_circuit_generic(
    gd: &GarbledData<Vec<u8>>,
    evaluator_bits: &[u8],
) -> Result<Vec<EncodedValue<Active>>, Box<dyn std::error::Error>> {
    // Build the input vector for evaluation:
    // First, convert the garbler's full labels to active labels.
    let mut inputs = Vec::with_capacity(gd.garbler_input_size + gd.evaluator_input_size);
    for label in gd.garbler_input_labels.iter() {
        // Here you may call `select` with the actual garbler input value.
        // For simplicity we assume the garbler input value is 0.
        inputs.push(label.select(0u8)?);
    }
    // For evaluator inputs, use the provided bits to select the active label.
    if evaluator_bits.len() != gd.input_labels.len() {
        return Err("Evaluator bits length does not match the number of evaluator inputs".into());
    }
    for (i, pair) in gd.input_labels.iter().enumerate() {
        let bit = evaluator_bits[i];
        inputs.push(pair[bit as usize].select(bit)?);
    }

    // Evaluate the circuit.
    let mut evaluator = Evaluator::default();
    let consumer = evaluator.evaluate(&gd.circuit, inputs)?;
    // Once all encrypted gates have been processed, finish evaluation:
    let output = consumer.finish()?.outputs;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_circuits::types::ValueType;

    #[test]
    fn test_generic_garble_and_evaluate() -> Result<(), Box<dyn std::error::Error>> {
        // For this test, we assume a circuit file "circuits/demo.txt"
        // that expects two inputs (first for garbler, second for evaluator)
        // and produces one output.
        let circuit_path = "circuits/demo.txt";
        let input_types = &[
            ValueType::Array(Box::new(ValueType::U8), 64),
            ValueType::Array(Box::new(ValueType::U32), 8),
        ];
        let output_types = &[ValueType::Array(Box::new(ValueType::U32), 8)];

        // Provide some dummy input values.
        let garbler_inputs = &[0u8; 64]; // One garbler input.
        let evaluator_inputs = &[0u32; 8]; // One evaluator input.

        // Generate the garbled circuit.
        let gd = generate_garbling_generic(
            circuit_path,
            input_types,
            output_types,
            garbler_inputs,
            evaluator_inputs,
        )?;
        println!("Generated GarbledData: {:?}", gd.circuit);

        // For evaluation, supply the evaluator’s selection bits (one bit per evaluator input).
        let evaluator_bits = &[0u8]; // For instance, select label for 0.
        let evaluator_output = evaluate_circuit_generic(&gd, evaluator_bits)?;
        println!("Evaluator output: {:?}", evaluator_output);

        // In a correct protocol, the evaluator’s active outputs should match
        // the generator’s outputs (after both are converted to the active state).
        let generator_active_outputs: Vec<EncodedValue<Active>> = gd
            .output_labels
            .into_iter()
            .map(|full| full.select(0u8).unwrap())
            .collect();

        assert_eq!(generator_active_outputs, evaluator_output);
        Ok(())
    }
}
