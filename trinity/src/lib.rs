mod commit;
mod evaluate;
mod garble;
mod ot;
mod two_pc;

use std::sync::Arc;

use commit::{KZGType, SerializableTrinityCom, TrinityCom, TrinityMsg};
use evaluate::{ev_commit, evaluate_circuit};
use garble::{generate_garbled_circuit, GarbledBundle};
use itybity::IntoBitIterator;
use mpz_circuits::{types::ValueType, Circuit};
use mpz_garble_core::Delta;
use ot::KZGOTReceiver;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SerializableTrinityMsg {
    Plain(laconic_ot::SerializableMsg),
    Halo2(halo2_we_kzg::laconic_ot::SerializableMsg),
}

impl From<TrinityMsg> for SerializableTrinityMsg {
    fn from(msg: TrinityMsg) -> Self {
        match msg {
            TrinityMsg::Plain(m) => Self::Plain(m.into()),
            TrinityMsg::Halo2(m) => Self::Halo2(m.into()),
        }
    }
}

impl TryFrom<SerializableTrinityMsg> for TrinityMsg {
    type Error = &'static str;

    fn try_from(s: SerializableTrinityMsg) -> Result<Self, Self::Error> {
        match s {
            SerializableTrinityMsg::Plain(m) => Ok(Self::Plain(
                laconic_ot::Msg::try_from(m).map_err(|_| "deserialize plain failed")?,
            )),
            SerializableTrinityMsg::Halo2(m) => Ok(Self::Halo2(
                halo2_we_kzg::Msg::try_from(m).map_err(|_| "deserialize halo2 failed")?,
            )),
        }
    }
}

impl TrinityMsg {
    pub fn serialize(&self) -> Vec<u8> {
        let serializable: SerializableTrinityMsg = self.clone().into();
        serde_json::to_vec(&serializable).expect("Serialization failed")
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let serializable: SerializableTrinityMsg =
            serde_json::from_slice(data).map_err(|_| "JSON deserialization failed")?;
        TrinityMsg::try_from(serializable)
    }
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

    pub fn to_sender_setup(&self) -> Vec<u8> {
        self.params.to_sender_bytes()
    }

    #[wasm_bindgen(static_method_of = TrinityWasmSetup)]
    pub fn from_sender_setup(bytes: &[u8]) -> Result<TrinityWasmSetup, JsError> {
        let params = SetupParams::from_sender_bytes(bytes)
            .map_err(|_| JsError::new("Failed to deserialize sender parameters"))?;
        Ok(TrinityWasmSetup { params })
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

    /// Get serialized evaluator commitment
    #[wasm_bindgen(getter)]
    pub fn commitment_serialized(&self) -> String {
        let com: SerializableTrinityCom = self.commitment.commitment.clone().into();
        serde_json::to_string(&com).expect("Failed to serialize commitment")
    }

    /// Evaluate circuit
    #[wasm_bindgen]
    pub fn evaluate(&mut self, garbled_data: &TrinityGarbler, circuit: &CircuitWrapper) -> Vec<u8> {
        // Take OT receiver
        let ot_receiver = self.ot_receiver.take().unwrap();

        let received_bundle: GarbledBundle = bincode::deserialize(&garbled_data.bundle)
            .expect("Failed to deserialize GarbledBundle");

        // Evaluate garbled circuit
        let result = evaluate_circuit(
            circuit.0.clone(),
            received_bundle,
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
    bundle: Vec<u8>,
}

#[wasm_bindgen]
impl TrinityGarbler {
    /// Generate garbled circuit with hardcoded inputs
    #[wasm_bindgen(constructor)]
    pub fn new(
        evaluator_commitment: String,
        setup: &TrinityWasmSetup,
        garbler_input: Vec<u8>,
        circuit: &CircuitWrapper,
    ) -> TrinityGarbler {
        let deserialized_commitment = TrinityCom::deserialize(evaluator_commitment.as_bytes())
            .expect("Failed to deserialize commitment");
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
            &setup.params.trinity,
            deserialized_commitment,
        );

        let serialized_bundle =
            bincode::serialize(&bundle).expect("Failed to serialize GarbledBundle");

        TrinityGarbler {
            bundle: serialized_bundle,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn bundle(&self) -> Vec<u8> {
        self.bundle.clone()
    }

    #[wasm_bindgen(static_method_of = TrinityGarbler)]
    pub fn from_bundle(bundle_bytes: &[u8]) -> TrinityGarbler {
        TrinityGarbler {
            bundle: bundle_bytes.to_vec(),
        }
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

#[cfg(test)]
mod tests {
    use crate::commit::{Trinity, TrinityChoice};

    use super::*;

    fn u16_vec_to_vec_bool(values: Vec<u16>) -> Vec<bool> {
        let mut result = Vec::new();
        for value in values {
            // Convert each u16 to its bit representation (16 bits)
            for i in 0..16 {
                result.push(((value >> i) & 1) == 1);
            }
        }
        result
    }

    #[test]
    fn test_trinity_com_serialization_roundtrip() {
        use crate::commit::TrinityCom;

        let original = TrinityCom::Plain(ark_bn254::G1Affine::default().into());
        let json = original.serialize();
        let deserialized = TrinityCom::deserialize(&json).unwrap();
        match deserialized {
            TrinityCom::Plain(g1) => assert_eq!(g1, ark_bn254::G1Affine::default()),
            _ => panic!("Expected Plain commitment"),
        }
    }

    #[test]
    fn test_trinity_msg_serialization_roundtrip_halo2() {
        use crate::commit::TrinityMsg;
        use halo2_we_kzg::laconic_ot::Msg;
        use halo2curves::bn256::G2Affine;

        let g2 = G2Affine::generator();
        let original_msg = TrinityMsg::Halo2(Msg {
            h: [(g2, [1u8; 16]), (g2, [2u8; 16])],
        });

        let serialized = original_msg.serialize();
        let deserialized = TrinityMsg::deserialize(&serialized).unwrap();

        if let TrinityMsg::Halo2(m2) = deserialized {
            assert_eq!(m2.h[0].1, [1u8; 16]);
            assert_eq!(m2.h[1].1, [2u8; 16]);
            assert_eq!(m2.h[0].0, g2);
            assert_eq!(m2.h[1].0, g2);
        } else {
            panic!("Expected Halo2 message");
        }
    }

    #[test]
    fn two_pc_serialization_flow_halo2() {
        // Setup RNG
        let mut rng = StdRng::seed_from_u64(0);

        // Load the circuit
        let circ = Circuit::parse(
            "circuits/simple_16bit_add.txt",
            &[
                ValueType::Array(Box::new(ValueType::Bit), 16),
                ValueType::Array(Box::new(ValueType::Bit), 16),
            ],
            &[ValueType::Array(Box::new(ValueType::Bit), 16)],
        )
        .unwrap();
        let arc_circuit = Arc::new(circ.clone());

        // Define inputs and expected output
        let garbler_input = [6u16];
        let garbler_bits = garbler_input.into_iter_lsb0().collect::<Vec<bool>>();
        let evaluator_input = [4u16];
        let evaluator_bits = evaluator_input.into_iter_lsb0().collect::<Vec<bool>>();
        let expected: [u16; 1] = [10u16];

        // === EVALUATOR SETUP (SERVER) ===
        // Create full Trinity setup
        let evaluator_trinity = Trinity::setup(KZGType::Plain, 16);

        // Create OT receiver and commitment
        let ot_receiver = evaluator_trinity
            .create_ot_receiver::<()>(
                &evaluator_bits
                    .iter()
                    .map(|&b| {
                        if b {
                            TrinityChoice::One
                        } else {
                            TrinityChoice::Zero
                        }
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("Failed to create receiver");

        let commitment = ot_receiver.trinity_receiver.commitment();

        // === SERIALIZATION FOR NETWORK TRANSFER ===
        // Serialize parameters for garbler
        let serialized_params = evaluator_trinity.to_sender_bytes();
        println!("Serialized params size: {} bytes", serialized_params.len());

        // === GARBLER SETUP (CLIENT) ===

        // === SERIALIZE AND TRANSFER TO GARBLER ===
        let serialized_params = evaluator_trinity.to_sender_bytes();

        // === GARBLER SETUP ===
        let garbler_trinity = Trinity::from_sender_bytes(&serialized_params)
            .expect("Failed to deserialize sender parameters");

        // Generate random delta
        let delta = Delta::random(&mut rng);

        // Generate garbled circuit
        let garbled = generate_garbled_circuit(
            arc_circuit.clone(),
            garbler_bits,
            &mut rng,
            delta,
            &garbler_trinity, // Note: we'd need to adjust this to use garbler_trinity
            commitment,
        );

        // === BACK TO EVALUATOR ===
        // Evaluate garbled circuit
        let result = evaluate_circuit(arc_circuit, garbled, evaluator_bits, ot_receiver).unwrap();

        // Verify result
        assert_eq!(result, u16_vec_to_vec_bool(expected.to_vec()));
    }
}
