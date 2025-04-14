use std::marker::PhantomData;

use ark_bn254::{Bn254, Fr, G1Affine};
use ark_poly::Radix2EvaluationDomain;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use halo2_we_kzg::{
    params::SerializableHalo2Params, Com as Halo2Com, Halo2Params, LaconicOTRecv as Halo2OTRecv,
    LaconicOTSender as Halo2OTSender, LaconicParams,
};
use laconic_ot::{
    Com as PlainCom, CommitmentKey, LaconicOTRecv as PlainOTRecv, LaconicOTSender as PlainOTSender,
};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use crate::ot::{KZGOTReceiver, KZGOTSender};

const MSG_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrinityChoice {
    Zero,
    One,
}

impl From<laconic_ot::Choice> for TrinityChoice {
    fn from(ch: laconic_ot::Choice) -> Self {
        match ch {
            laconic_ot::Choice::Zero => TrinityChoice::Zero,
            laconic_ot::Choice::One => TrinityChoice::One,
        }
    }
}

impl From<TrinityChoice> for laconic_ot::Choice {
    fn from(ch: TrinityChoice) -> Self {
        match ch {
            TrinityChoice::Zero => laconic_ot::Choice::Zero,
            TrinityChoice::One => laconic_ot::Choice::One,
        }
    }
}

impl From<TrinityChoice> for halo2_we_kzg::Choice {
    fn from(ch: TrinityChoice) -> Self {
        match ch {
            TrinityChoice::Zero => halo2_we_kzg::Choice::Zero,
            TrinityChoice::One => halo2_we_kzg::Choice::One,
        }
    }
}

#[derive(Serialize)]
pub enum KZGType {
    Plain,
    Halo2,
}

#[derive(Clone)]
pub enum TrinityParams {
    Plain(Arc<CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>>>),
    Halo2(Arc<Halo2Params>),
}

#[derive(Clone)]
pub enum TrinitySenderParams {
    Plain(Arc<CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>>>),
    Halo2(Arc<LaconicParams>),
}

pub enum TrinityInnerParams {
    // Full parameters (for evaluator)
    Full(TrinityParams),
    // Minimal parameters (for garbler/sender)
    Sender(TrinitySenderParams),
}

#[derive(Clone, Copy)]
pub enum TrinityCom {
    Plain(PlainCom<Bn254>),
    Halo2(Halo2Com),
}

#[derive(Serialize, Deserialize)]
pub enum SerializableTrinityCom {
    Plain(Vec<u8>), // Compressed G1
    Halo2(Vec<u8>), // halo2 Com
}

impl From<TrinityCom> for SerializableTrinityCom {
    fn from(com: TrinityCom) -> Self {
        match com {
            TrinityCom::Plain(g1) => {
                let mut bytes = Vec::new();
                g1.serialize_compressed(&mut bytes).unwrap();
                SerializableTrinityCom::Plain(bytes)
            }
            TrinityCom::Halo2(halo2_com) => {
                let bytes = bincode::serialize(&halo2_com).unwrap();
                SerializableTrinityCom::Halo2(bytes)
            }
        }
    }
}

impl TryFrom<SerializableTrinityCom> for TrinityCom {
    type Error = &'static str;

    fn try_from(value: SerializableTrinityCom) -> Result<Self, Self::Error> {
        match value {
            SerializableTrinityCom::Plain(bytes) => {
                let g1 = G1Affine::deserialize_compressed(&*bytes)
                    .map_err(|_| "Failed to deserialize PlainCom")?;
                Ok(TrinityCom::Plain(g1.into()))
            }
            SerializableTrinityCom::Halo2(bytes) => {
                let com: Halo2Com =
                    bincode::deserialize(&bytes).map_err(|_| "Failed to deserialize Halo2Com")?;
                Ok(TrinityCom::Halo2(com))
            }
        }
    }
}

impl TrinityCom {
    pub fn serialize(&self) -> Vec<u8> {
        let serializable: SerializableTrinityCom = (*self).into();
        serde_json::to_vec(&serializable).expect("JSON serialization failed")
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        let serializable: SerializableTrinityCom =
            serde_json::from_slice(data).map_err(|_| "JSON deserialization failed")?;
        TrinityCom::try_from(serializable)
    }
}

pub enum TrinityReceiver<'a> {
    Plain(PlainOTRecv<'a, Bn254, Radix2EvaluationDomain<Fr>>),
    Halo2(Halo2OTRecv),
}

pub enum TrinitySender<'a> {
    Plain(PlainOTSender<'a, Bn254, Radix2EvaluationDomain<Fr>>),
    Halo2(Halo2OTSender),
}

pub struct Trinity {
    pub mode: KZGType,
    pub params: TrinityInnerParams,
}

#[derive(Clone, Copy, Debug)]
pub enum TrinityMsg {
    Plain(laconic_ot::Msg<Bn254>),
    Halo2(halo2_we_kzg::Msg),
}

#[derive(Serialize, Deserialize)]
pub struct SerializablePlainParams {
    pub commitment_key_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum TrinitySerializableParams {
    Plain(SerializablePlainParams),
    Halo2(SerializableHalo2Params),
}

impl From<&CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>>> for SerializablePlainParams {
    fn from(ck: &CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>>) -> Self {
        let mut bytes = Vec::new();
        ck.serialize_uncompressed(&mut bytes)
            .expect("Serialization failed");

        SerializablePlainParams {
            commitment_key_bytes: bytes,
        }
    }
}

impl TryFrom<SerializablePlainParams> for CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>> {
    type Error = &'static str;

    fn try_from(s: SerializablePlainParams) -> Result<Self, Self::Error> {
        CommitmentKey::deserialize_uncompressed(&mut &s.commitment_key_bytes[..])
            .map_err(|_| "Failed to deserialize CommitmentKey")
    }
}

impl TrinityParams {
    pub fn to_sender_params(&self) -> TrinitySenderParams {
        match self {
            TrinityParams::Plain(ck) => TrinitySenderParams::Plain(ck.clone()),
            TrinityParams::Halo2(params) => {
                // Extract LaconicParams from Halo2Params
                // As the garbler doesn't need the full Halo2Params
                let laconic_params = LaconicParams::from(params.as_ref());
                TrinitySenderParams::Halo2(Arc::new(laconic_params))
            }
        }
    }
}

impl Trinity {
    pub fn setup(mode: KZGType, message_length: usize) -> Self {
        let rng = &mut OsRng;

        let params = match mode {
            KZGType::Plain => {
                let plainparams =
                    CommitmentKey::<Bn254, Radix2EvaluationDomain<Fr>>::setup(rng, message_length)
                        .expect("setup failed");
                TrinityParams::Plain(Arc::new(plainparams))
            }
            KZGType::Halo2 => {
                // To Do: Have cleaner way to transpose message_length to degree for Halo2
                let degree = message_length;
                let halo2params =
                    Halo2Params::setup(rng, degree).expect("Failed to setup Halo2Params");
                TrinityParams::Halo2(Arc::new(halo2params))
            }
        };

        Self {
            mode,
            params: TrinityInnerParams::Full(params),
        }
    }

    pub fn setup_for_garbler(sender_params: TrinitySenderParams) -> Self {
        let mode = match sender_params {
            TrinitySenderParams::Plain(_) => KZGType::Plain,
            TrinitySenderParams::Halo2(_) => KZGType::Halo2,
        };

        Self {
            mode,
            params: TrinityInnerParams::Sender(sender_params),
        }
    }

    // Convert to sender params (for network transfer)
    pub fn to_sender_params(&self) -> Option<TrinitySenderParams> {
        match &self.params {
            TrinityInnerParams::Full(full_params) => Some(full_params.to_sender_params()),
            TrinityInnerParams::Sender(sender_params) => Some(sender_params.clone()),
        }
    }

    // Serialize directly to minimal bytes for transfer
    pub fn to_sender_bytes(&self) -> Vec<u8> {
        if let Some(sender_params) = self.to_sender_params() {
            match sender_params {
                TrinitySenderParams::Plain(ck) => {
                    let mut bytes = vec![0]; // Tag byte for Plain
                    let mut param_bytes = Vec::new();
                    ck.serialize_uncompressed(&mut param_bytes)
                        .expect("Serialization failed");
                    bytes.append(&mut param_bytes);
                    bytes
                }
                TrinitySenderParams::Halo2(laconic_params) => {
                    let mut bytes = vec![1]; // Tag byte for Halo2
                    let mut param_bytes =
                        bincode::serialize(laconic_params.as_ref()).expect("Serialization failed");
                    bytes.append(&mut param_bytes);
                    bytes
                }
            }
        } else {
            panic!("No sender params available");
        }
    }

    // Create Trinity from sender bytes
    pub fn from_sender_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Err("Empty bytes");
        }

        match bytes[0] {
            0 => {
                let ck: CommitmentKey<_, _> =
                    CommitmentKey::deserialize_uncompressed(&mut &bytes[1..])
                        .map_err(|_| "Failed to deserialize CommitmentKey")?;
                Ok(Self::setup_for_garbler(TrinitySenderParams::Plain(
                    Arc::new(ck),
                )))
            }
            1 => {
                // Deserialize Halo2 sender params (LaconicParams)
                let laconic_params: LaconicParams = bincode::deserialize(&bytes[1..])
                    .map_err(|_| "Failed to deserialize LaconicParams")?;

                Ok(Self::setup_for_garbler(TrinitySenderParams::Halo2(
                    Arc::new(laconic_params),
                )))
            }
            _ => Err("Invalid tag byte"),
        }
    }

    pub fn create_ot_receiver<Ctx>(
        &self,
        bits: &[TrinityChoice],
    ) -> Result<KZGOTReceiver<Ctx>, &'static str> {
        match &self.params {
            TrinityInnerParams::Full(params) => {
                let trinity_receiver = TrinityReceiver::new(params, bits);
                Ok(KZGOTReceiver {
                    trinity_receiver,
                    _phantom: PhantomData,
                })
            }
            TrinityInnerParams::Sender(_) => Err("Cannot create receiver from sender params"),
        }
    }

    pub fn create_ot_sender<'a, Ctx>(&'a self, com: TrinityCom) -> KZGOTSender<'a, Ctx> {
        let trinity_sender = match &self.params {
            TrinityInnerParams::Full(params) => TrinitySender::new(params, com),
            TrinityInnerParams::Sender(sender_params) => {
                match (sender_params, com) {
                    (TrinitySenderParams::Plain(ck), TrinityCom::Plain(com)) => {
                        // Create Plain sender directly from plain sender params
                        TrinitySender::Plain(PlainOTSender::new(ck.as_ref(), com))
                    }
                    (TrinitySenderParams::Halo2(laconic_params), TrinityCom::Halo2(com)) => {
                        TrinitySender::Halo2(Halo2OTSender::new_from(
                            laconic_params.as_ref().clone(),
                            com,
                        ))
                    }
                    _ => panic!("Mismatched commitment type"),
                }
            }
        };

        KZGOTSender {
            trinity_sender,
            _phantom: PhantomData,
        }
    }
}

impl<'a> TrinityReceiver<'a> {
    pub fn new(params: &'a TrinityParams, bits: &[TrinityChoice]) -> Self {
        match params {
            TrinityParams::Plain(ck_arc) => {
                let plain_bits: Vec<laconic_ot::Choice> = bits.iter().map(|&b| b.into()).collect();
                let plain_recv = PlainOTRecv::new(ck_arc.as_ref(), &plain_bits);
                TrinityReceiver::Plain(plain_recv)
            }
            TrinityParams::Halo2(halo2_params_arc) => {
                let halo2_bits: Vec<halo2_we_kzg::Choice> = bits
                    .iter()
                    .map(|&b| TrinityChoice::from(b).into())
                    .collect();
                let halo2_recv = Halo2OTRecv::new((halo2_params_arc.as_ref()).clone(), &halo2_bits);
                TrinityReceiver::Halo2(halo2_recv)
            }
        }
    }

    pub fn recv(&self, i: usize, msg: TrinityMsg) -> [u8; MSG_SIZE] {
        match (self, msg) {
            (TrinityReceiver::Plain(recv), TrinityMsg::Plain(msg)) => recv.recv(i, msg),
            (TrinityReceiver::Halo2(recv), TrinityMsg::Halo2(msg)) => recv.recv(i, msg),
            _ => panic!("Mismatched receiver and message types"),
        }
    }

    pub fn commitment(&self) -> TrinityCom {
        match self {
            TrinityReceiver::Plain(recv) => TrinityCom::Plain(recv.commitment()),
            TrinityReceiver::Halo2(recv) => TrinityCom::Halo2(recv.commitment()),
        }
    }
}

impl<'a> TrinitySender<'a> {
    pub fn new(params: &'a TrinityParams, com: TrinityCom) -> Self {
        match (params, com) {
            (TrinityParams::Plain(ck), TrinityCom::Plain(com)) => {
                TrinitySender::Plain(PlainOTSender::new(ck.as_ref(), com))
            }
            (TrinityParams::Halo2(params_arc), TrinityCom::Halo2(com)) => {
                TrinitySender::Halo2(Halo2OTSender::new(params_arc.as_ref().clone().params, com))
            }
            _ => panic!("Mismatched commitment type"),
        }
    }

    // pub fn new_from_params(params: LaconicParams, com: TrinityCom) -> Self {
    //     match com {
    //         TrinityCom::Plain(com) => todo!(),
    //         TrinityCom::Halo2(com) => TrinitySender::Halo2(Halo2OTSender::new_from(params, com)),
    //     }
    // }

    pub fn send<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
    ) -> TrinityMsg {
        match self {
            TrinitySender::Plain(sender) => TrinityMsg::Plain(sender.send(rng, i, m0, m1)),
            TrinitySender::Halo2(sender) => TrinityMsg::Halo2(sender.send(rng, i, m0, m1)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_plain_laconic_ot() {
        let rng = &mut OsRng;
        let message_length = 4;

        let trinity = Trinity::setup(KZGType::Plain, message_length);

        let bits = vec![
            TrinityChoice::Zero,
            TrinityChoice::One,
            TrinityChoice::Zero,
            TrinityChoice::One,
        ];

        // Trinity remains alive through receiver/sender
        let ot_receiver = trinity
            .create_ot_receiver::<()>(&bits)
            .expect("Error while create the ot receiver.");
        let commitment = ot_receiver.trinity_receiver.commitment();
        let ot_sender = trinity.create_ot_sender::<()>(commitment);

        let m0 = [0u8; MSG_SIZE];
        let m1 = [1u8; MSG_SIZE];

        let msg = ot_sender.trinity_sender.send(rng, 0, m0, m1);
        let res = ot_receiver.trinity_receiver.recv(0, msg);
        assert_eq!(res, m0);
    }

    #[test]
    fn test_halo2_laconic_ot() {
        let rng = &mut OsRng;
        let message_length = 4;

        let trinity = Trinity::setup(KZGType::Halo2, message_length);

        let bits = vec![
            TrinityChoice::Zero,
            TrinityChoice::One,
            TrinityChoice::Zero,
            TrinityChoice::One,
        ];

        // Trinity remains alive through receiver/sender
        let ot_receiver = trinity
            .create_ot_receiver::<()>(&bits)
            .expect("Error while create the ot receiver.");
        let commitment = ot_receiver.trinity_receiver.commitment();
        let ot_sender = trinity.create_ot_sender::<()>(commitment);

        let m0 = [0u8; MSG_SIZE];
        let m1 = [1u8; MSG_SIZE];

        let msg = ot_sender.trinity_sender.send(rng, 0, m0, m1);
        let res = ot_receiver.trinity_receiver.recv(0, msg);
        assert_eq!(res, m0);
    }
}
