mod commit;
mod evaluate;
mod garble;
mod ot;
mod two_pc;

use std::sync::Arc;

use commit::{KZGType, TrinityCom};
use evaluate::{ev_commit, evaluate_circuit};
use garble::{generate_garbled_circuit, GarbledBundle};
use mpz_circuits::{ops::WrappingAdd, types::ValueType, Circuit, CircuitBuilder};
use mpz_garble_core::Delta;
use ot::KZGOTReceiver;
use rand::{rngs::StdRng, SeedableRng};
use two_pc::{setup, u16_to_vec_bool, SetupParams};

use wasm_bindgen::prelude::*;

// Helper function to create a circuit
pub fn create_circuit_from_path() -> Circuit {
    Circuit::parse(
        "circuits/simple_16bit_add.txt",
        &[
            ValueType::Array(Box::new(ValueType::U16), 1),
            ValueType::Array(Box::new(ValueType::U16), 1),
        ],
        &[ValueType::Array(Box::new(ValueType::U16), 1)],
    )
    .unwrap()
}

fn create_circuit() -> Circuit {
    let builder = CircuitBuilder::new();

    let a = builder.add_input::<u16>();
    let b = builder.add_input::<u16>();

    let c = a.wrapping_add(b);

    builder.add_output(c);

    builder.build().unwrap()
}

/// This struct holds the setup parameters
#[wasm_bindgen]
pub struct TrinityWasmSetup {
    params: SetupParams,
}

#[wasm_bindgen]
impl TrinityWasmSetup {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TrinityWasmSetup {
        // Hardcode to Plain KZG for simplicity
        TrinityWasmSetup {
            params: setup(KZGType::Plain),
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
}

#[wasm_bindgen]
impl TrinityEvaluator {
    /// Create evaluator with hardcoded input
    #[wasm_bindgen(constructor)]
    pub fn new(setup: &TrinityWasmSetup) -> TrinityEvaluator {
        // Hardcode evaluator input to 2
        let evaluator_input = [2u16];
        let evaluator_bits = u16_to_vec_bool(evaluator_input);

        // Create static parameters
        let params: &'static SetupParams = Box::leak(Box::new(setup.params.clone()));

        // Generate commitment
        let bundle = ev_commit(evaluator_bits, params).unwrap();

        TrinityEvaluator {
            commitment: WasmCommitment {
                commitment: bundle.receiver_commitment,
            },
            ot_receiver: Some(bundle.ot_receiver),
        }
    }

    /// Get evaluator commitment
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> WasmCommitment {
        self.commitment.clone()
    }

    /// Evaluate circuit
    #[wasm_bindgen]
    pub fn evaluate(&mut self, garbled_data: &TrinityGarbler) -> u16 {
        // Hardcode evaluator input to 2
        let evaluator_input = [2u16];

        // Create circuit
        let circuit = Arc::new(create_circuit());

        // Take OT receiver
        let ot_receiver = self.ot_receiver.take().unwrap();

        // Evaluate garbled circuit
        let result = evaluate_circuit(
            circuit,
            garbled_data.bundle.clone(),
            evaluator_input,
            garbled_data.delta,
            ot_receiver,
        )
        .unwrap();

        result
    }
}

/// WASM wrapper for garbler
#[wasm_bindgen]
pub struct TrinityGarbler {
    bundle: GarbledBundle,
    delta: Delta,
}

#[wasm_bindgen]
impl TrinityGarbler {
    /// Generate garbled circuit with hardcoded inputs
    #[wasm_bindgen(constructor)]
    pub fn new(evaluator: &TrinityEvaluator, setup: &TrinityWasmSetup) -> TrinityGarbler {
        // Hardcode garbler input to 4
        let garbler_input = [4u16];

        // Create deterministic RNG
        let mut rng = StdRng::seed_from_u64(42);

        // Generate random delta
        let delta = Delta::random(&mut rng);

        // Create circuit
        let circuit = Arc::new(create_circuit());

        // Generate garbled circuit
        let bundle = generate_garbled_circuit(
            circuit,
            garbler_input,
            &mut rng,
            delta,
            &setup.params,
            evaluator.commitment.commitment,
        );

        TrinityGarbler { bundle, delta }
    }

    /// Compute expected result (for testing)
    #[wasm_bindgen]
    pub fn expected_result(&self) -> u16 {
        // Hardcoded result: 4 + 2 = 6
        6
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
