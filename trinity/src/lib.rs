mod commit;
mod evaluate;
mod garble;
mod ot;
mod two_pc;

use commit::{KZGType, TrinityCom, TrinityMsg};
pub use evaluate::{ev_commit, evaluate_circuit};
use fancy_garbling::{
    circuit::BinaryCircuit,
    classic::{garble, GarbledCircuit},
    WireMod2,
};
pub use garble::{generate_garbled_circuit, GarbledBundle};
use ot::KZGOTReceiver;
pub use two_pc::{int_to_bits, parse_circuit, setup, SetupParams};

use serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

/// This struct holds the setup parameters.
#[wasm_bindgen]
pub struct TrinityWasmSetup {
    params: SetupParams,
}

#[wasm_bindgen]
impl TrinityWasmSetup {
    #[wasm_bindgen(constructor)]
    pub fn new(kzg_type: &str) -> TrinityWasmSetup {
        let mode = match kzg_type {
            "Plain" => KZGType::Plain,
            "Halo2" => KZGType::Halo2,
            _ => panic!("invalid type"),
        };
        TrinityWasmSetup {
            params: setup(mode),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmCommitment {
    commitment: TrinityCom,
}

#[wasm_bindgen]
pub struct WasmMessage {
    message: TrinityMsg,
}

/// Evaluator holds the commitment (exposed to JS) and the OT receiver (kept internal)
#[wasm_bindgen]
pub struct TrinityEvaluator {
    commitment: WasmCommitment,
    // OT receiver is stored privately
    ot_receiver: Option<KZGOTReceiver<'static, ()>>,
    _params: SetupParams,
}

#[wasm_bindgen]
impl TrinityEvaluator {
    /// Create a new evaluator and commit evaluator’s inputs.
    /// This function performs the OT commitment phase and stores the OT receiver internally.
    #[wasm_bindgen]
    pub fn new(ev_bits: JsValue, setup: TrinityWasmSetup) -> TrinityEvaluator {
        let bits: Vec<bool> =
            serde_wasm_bindgen::from_value(ev_bits).expect("failed to deserialize evaluator bits");
        // Use the owned parameters from setup so they remain alive
        // To do: better memory management, not the best to leak value here
        let params: &'static SetupParams = Box::leak(Box::new(setup.params.clone()));
        let bundle = ev_commit(bits, &params).expect("ev_commit failed");
        let ot_receiver = bundle.ot_receiver;
        let receiver_commitment = WasmCommitment {
            commitment: bundle.receiver_commitment,
        };

        TrinityEvaluator {
            commitment: receiver_commitment,
            ot_receiver: Some(ot_receiver),
            _params: setup.params,
        }
    }

    /// Returns the commitment so that it can be sent to the garbler.
    #[wasm_bindgen(getter)]
    pub fn commitment(&self) -> WasmCommitment {
        self.commitment.clone()
    }

    /// Perform the evaluation phase.
    /// This method consumes (takes) the stored OT receiver.
    #[wasm_bindgen]
    pub fn evaluate(&mut self, circuit_json: &str, garbled_data: TrinityGarbler) -> JsValue {
        let circuit = parse_circuit(circuit_json);

        let labels: Vec<WireMod2> = serde_wasm_bindgen::from_value(garbled_data.garbler_labels)
            .expect("failed to deserialize garbler labels");

        let ot_receiver = self
            .ot_receiver
            .take()
            .expect("OT receiver already used or not set");
        let bundle = GarbledBundle {
            garbler_labels: labels,
            ciphertexts: garbled_data
                .ciphertexts
                .into_iter()
                .map(|msg| msg)
                .collect(),
        };
        let ev: GarbledCircuit<WireMod2, BinaryCircuit> =
            serde_wasm_bindgen::from_value(garbled_data.ev)
                .expect("failed to deserialize evaluator");

        let result =
            evaluate_circuit(circuit, ev, bundle, ot_receiver).expect("circuit evaluation failed");
        serde_wasm_bindgen::to_value(&result).expect("failed to serialize result")
    }
}

/// Garbler builds the garbled circuit from the garbler’s inputs.
/// Only the outputs that need to be sent to the evaluator are returned.
#[wasm_bindgen]
pub struct TrinityGarbler {
    garbler_labels: JsValue,
    ciphertexts: Vec<TrinityMsg>,
    ev: JsValue,
}

#[wasm_bindgen]
impl TrinityGarbler {
    /// Returns the garbler labels.
    #[wasm_bindgen(getter)]
    pub fn garbler_labels(&self) -> JsValue {
        self.garbler_labels.clone()
    }

    // /// Returns the ciphertexts.
    // #[wasm_bindgen(getter)]
    // pub fn ciphertexts(&self) -> Vec<TrinityMsg> {
    //     self.ciphertexts.clone()
    // }

    /// Generate the garbled circuit given the garbler’s inputs, the commitment from the evaluator, and the circuit.
    #[wasm_bindgen]
    pub fn generate(
        gb_bits: JsValue,
        commitment: WasmCommitment,
        setup: &TrinityWasmSetup,
        circuit_json: &str,
    ) -> TrinityGarbler {
        let bits: Vec<bool> =
            serde_wasm_bindgen::from_value(gb_bits).expect("failed to deserialize garbler bits");
        let circuit = parse_circuit(circuit_json);
        let (en, ev) = garble::<WireMod2, _>(&circuit)
            .expect("failed to create garbling encoder and evaluator");

        let bundle = generate_garbled_circuit(bits, en, &setup.params, commitment.commitment);
        TrinityGarbler {
            garbler_labels: serde_wasm_bindgen::to_value(&bundle.garbler_labels)
                .expect("failed to serialize garbler labels"),
            ciphertexts: bundle.ciphertexts,
            ev: serde_wasm_bindgen::to_value(&ev).expect("failed to serialize ciphertexts"),
        }
    }
}
