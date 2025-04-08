use std::marker::PhantomData;

use ark_bn254::{Bn254, Fr};
use ark_poly::Radix2EvaluationDomain;
use halo2_we_kzg::{
    Com as Halo2Com, Halo2Params, LaconicOTRecv as Halo2OTRecv, LaconicOTSender as Halo2OTSender,
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

#[derive(Clone, Copy)]
pub enum TrinityCom {
    Plain(PlainCom<Bn254>),
    Halo2(Halo2Com),
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
    pub params: TrinityParams,
}

#[derive(Clone, Copy, Debug)]
pub enum TrinityMsg {
    Plain(laconic_ot::Msg<Bn254>),
    Halo2(halo2_we_kzg::Msg),
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

        Self { mode, params }
    }

    pub fn create_ot_receiver<Ctx>(&self, bits: &[TrinityChoice]) -> KZGOTReceiver<Ctx> {
        let trinity_receiver = TrinityReceiver::new(&self.params, bits);
        KZGOTReceiver {
            trinity_receiver,
            _phantom: PhantomData,
        }
    }

    pub fn create_ot_sender<'a, Ctx>(&'a self, com: TrinityCom) -> KZGOTSender<'a, Ctx> {
        let trinity_sender = TrinitySender::new(&self.params, com);
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
                TrinitySender::Halo2(Halo2OTSender::new(
                    params_arc.as_ref().clone().params,
                    com,
                    params_arc.as_ref().clone().domain,
                ))
            }
            _ => panic!("Mismatched commitment type"),
        }
    }

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
        let ot_receiver = trinity.create_ot_receiver::<()>(&bits);
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
        let ot_receiver = trinity.create_ot_receiver::<()>(&bits);
        let commitment = ot_receiver.trinity_receiver.commitment();
        let ot_sender = trinity.create_ot_sender::<()>(commitment);

        let m0 = [0u8; MSG_SIZE];
        let m1 = [1u8; MSG_SIZE];

        let msg = ot_sender.trinity_sender.send(rng, 0, m0, m1);
        let res = ot_receiver.trinity_receiver.recv(0, msg);
        assert_eq!(res, m0);
    }
}
