mod commit;
mod evaluate;
mod garble;
mod ot;
mod two_pc;

use std::sync::Arc;

use commit::{KZGType, TrinityCom};
use evaluate::{ev_commit, evaluate_circuit};
use garble::{generate_garbled_circuit, GarbledBundle};
use itybity::IntoBitIterator;
use mpz_circuits::{types::ValueType, Circuit};
use mpz_garble_core::Delta;
use ot::KZGOTReceiver;
use rand::{rngs::StdRng, SeedableRng};
use two_pc::{setup, u8_vec_to_vec_bool, SetupParams};

use wasm_bindgen::prelude::*;

/// Parse a circuit from a string
#[wasm_bindgen]
pub fn parse_circuit(
    circuit_str: &str,
    evaluator_input_size: usize,
    garbler_input_size: usize,
    output_size: usize,
) -> Result<CircuitWrapper, JsError> {
    let circuit = Circuit::parse_str(
        circuit_str,
        &[
            ValueType::Array(Box::new(ValueType::Bit), evaluator_input_size),
            ValueType::Array(Box::new(ValueType::Bit), garbler_input_size),
        ],
        &[ValueType::Array(Box::new(ValueType::Bit), output_size)],
    )
    .map_err(|e| JsError::new(&format!("Failed to parse circuit: {}", e)))?;

    Ok(CircuitWrapper(Arc::new(circuit)))
}

/// Wrapper for Circuit to expose to JavaScript
#[wasm_bindgen]
pub struct CircuitWrapper(Arc<Circuit>);

/// This struct holds the setup parameters
#[wasm_bindgen]
pub struct TrinityWasmSetup {
    params: SetupParams,
}

#[wasm_bindgen]
impl TrinityWasmSetup {
    #[wasm_bindgen(constructor)]
    pub fn new(mode_str: &str) -> TrinityWasmSetup {
        let mode = match mode_str {
            "Plain" => KZGType::Plain,
            "Halo2" => KZGType::Halo2,
            _ => panic!("Invalid mode"),
        };
        TrinityWasmSetup {
            params: setup(mode),
        }
    }
}

/// WASM wrapper for evaluator commitment
#[wasm_bindgen]
pub struct WasmCommitment {
    commitment: TrinityCom,
}

/// WASM wrapper for evaluator
#[wasm_bindgen]
pub struct TrinityEvaluator {
    commitment: WasmCommitment,
    ot_receiver: Option<KZGOTReceiver<'static, ()>>,
    evaluator_bits: Vec<bool>,
}

#[wasm_bindgen]
impl TrinityEvaluator {
    #[wasm_bindgen(constructor)]
    pub fn new(setup: &TrinityWasmSetup, evaluator_input: Vec<u8>) -> TrinityEvaluator {
        let evaluator_bits = u8_vec_to_vec_bool(evaluator_input.clone())
            .into_iter_lsb0()
            .collect::<Vec<bool>>();

        // Create static parameters
        let params: &'static SetupParams = Box::leak(Box::new(setup.params.clone()));

        // Generate commitment
        let bundle = ev_commit(evaluator_bits.clone(), params).unwrap();

        TrinityEvaluator {
            commitment: WasmCommitment {
                commitment: bundle.receiver_commitment,
            },
            ot_receiver: Some(bundle.ot_receiver),
            evaluator_bits: evaluator_bits.clone(),
        }
    }

    /// Get evaluator commitment
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> WasmCommitment {
        self.commitment.clone()
    }

    /// Evaluate circuit
    #[wasm_bindgen]
    pub fn evaluate(&mut self, garbled_data: &TrinityGarbler, circuit: &CircuitWrapper) -> Vec<u8> {
        // Take OT receiver
        let ot_receiver = self.ot_receiver.take().unwrap();

        // Evaluate garbled circuit
        let result = evaluate_circuit(
            circuit.0.clone(),
            garbled_data.bundle.clone(),
            self.evaluator_bits.clone(),
            ot_receiver,
        )
        .unwrap();

        result.into_iter().map(u8::from).collect()
    }
}

/// WASM wrapper for garbler
#[wasm_bindgen]
pub struct TrinityGarbler {
    bundle: GarbledBundle,
}

#[wasm_bindgen]
impl TrinityGarbler {
    /// Generate garbled circuit with hardcoded inputs
    #[wasm_bindgen(constructor)]
    pub fn new(
        evaluator_commitment: &WasmCommitment,
        setup: &TrinityWasmSetup,
        garbler_input: Vec<u8>,
        circuit: &CircuitWrapper,
    ) -> TrinityGarbler {
        let garbler_bits = u8_vec_to_vec_bool(garbler_input)
            .into_iter_lsb0()
            .collect::<Vec<bool>>();

        // Create deterministic RNG
        let mut rng = StdRng::seed_from_u64(42);

        // Generate random delta
        let delta = Delta::random(&mut rng);

        // Generate garbled circuit
        let bundle = generate_garbled_circuit(
            circuit.0.clone(),
            garbler_bits,
            &mut rng,
            delta,
            &setup.params,
            evaluator_commitment.commitment,
        );

        TrinityGarbler { bundle }
    }
}

// Clone implementation for WasmCommitment
impl Clone for WasmCommitment {
    fn clone(&self) -> Self {
        WasmCommitment {
            commitment: self.commitment,
        }
    }
}

// Default implementations to create default empty instances for JS
#[wasm_bindgen]
impl WasmCommitment {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        unimplemented!("Cannot create WasmCommitment directly from JS")
    }
}
