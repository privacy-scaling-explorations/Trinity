use std::marker::PhantomData;

use ark_bn254::{Bn254, Fr};
use ark_poly::Radix2EvaluationDomain;
// Assume these are from your separate crates:
use halo2_we_kzg::{
    Com as Halo2Com, Halo2Params, LaconicOTRecv as Halo2OTRecv, LaconicOTSender as Halo2OTSender,
};
use laconic_ot::{
    Choice, Com as PlainCom, CommitmentKey, LaconicOTRecv as PlainOTRecv,
    LaconicOTSender as PlainOTSender,
};
use rand::{rngs::OsRng, Rng};

use crate::ot::{KZGOTReceiver, KZGOTSender};

const MSG_SIZE: usize = 32;

pub enum KZGType {
    Plain,
    Halo2,
}

pub enum TrinityParams {
    Plain(CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>>),
    Halo2(Halo2Params),
}

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
                        .expect("Failed to setup plain CommitmentKey");
                TrinityParams::Plain(plainparams)
            }
            KZGType::Halo2 => {
                // To Do: Have cleaner way to transpose message_length to degree for Halo2
                let degree = message_length;
                let halo2params =
                    Halo2Params::setup(rng, degree).expect("Failed to setup Halo2Params");
                TrinityParams::Halo2(halo2params)
            }
        };

        Self { mode, params }
    }

    pub fn create_ot_receiver<Ctx>(&self) -> KZGOTReceiver<Ctx> {
        let trinity_receiver = match &self.params {
            TrinityParams::Plain(ck) => {
                let bits = Vec::new();
                TrinityReceiver::Plain(PlainOTRecv::new(ck, &bits))
            }
            TrinityParams::Halo2(params) => {
                let bits = Vec::new();
                TrinityReceiver::Halo2(Halo2OTRecv::new(params.clone(), &bits))
            }
        };

        KZGOTReceiver {
            trinity_receiver: trinity_receiver,
            _phantom: PhantomData,
        }
    }

    pub fn create_ot_sender<Ctx>(&self) -> KZGOTSender<Ctx> {
        let trinity_sender = match &self.params {
            TrinityParams::Plain(ck) => {
                let com = PlainCom::<Bn254>::default();
                TrinitySender::Plain(PlainOTSender::new(ck, com))
            }
            TrinityParams::Halo2(params) => {
                let com = Halo2Com::default();
                TrinitySender::Halo2(Halo2OTSender::new(
                    params.clone().params,
                    com,
                    params.clone().domain,
                ))
            }
        };

        KZGOTSender {
            trinity_sender: trinity_sender,
            _phantom: PhantomData,
        }
    }
}

impl<'a> TrinityReceiver<'a> {
    pub fn new(params: &'a TrinityParams, bits: &[Choice]) -> Self {
        match params {
            TrinityParams::Plain(ck) => {
                let plain_recv = PlainOTRecv::new(ck, bits);
                TrinityReceiver::Plain(plain_recv)
            }
            TrinityParams::Halo2(halo2_params) => {
                let halo2_bits: Vec<halo2_we_kzg::Choice> = bits
                    .iter()
                    .map(|b| match b {
                        laconic_ot::Choice::Zero => halo2_we_kzg::Choice::Zero,
                        laconic_ot::Choice::One => halo2_we_kzg::Choice::One,
                    })
                    .collect();
                let halo2_recv = Halo2OTRecv::new(halo2_params.clone(), &halo2_bits);
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

    // pub fn params(&self) -> &TrinityParams {
    //     match self {
    //         TrinityReceiver::Plain(recv) => recv.params(),
    //         TrinityReceiver::Halo2(recv) => recv.params(),
    //     }
    // }
}

impl<'a> TrinitySender<'a> {
    pub fn sender_new(params: &'a TrinityParams, com: TrinityCom) -> Self {
        match (params, com) {
            (TrinityParams::Plain(ck), TrinityCom::Plain(com)) => {
                TrinitySender::Plain(PlainOTSender::new(ck, com))
            }
            (TrinityParams::Halo2(params), TrinityCom::Halo2(com)) => TrinitySender::Halo2(
                Halo2OTSender::new(params.clone().params, com, params.clone().domain),
            ),
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

        // Setup Trinity with Plain mode
        let trinity = Trinity::setup(KZGType::Plain, message_length);

        // Create receiver with bits
        let bits = vec![Choice::Zero, Choice::One, Choice::Zero, Choice::One];
        let receiver = TrinityReceiver::new(&trinity.params, &bits);

        // Create sender
        let sender = TrinitySender::sender_new(&trinity.params, receiver.commitment());

        // Test sending and receiving
        let m0 = [0u8; MSG_SIZE];
        let m1 = [1u8; MSG_SIZE];
        let msg = sender.send(rng, 0, m0, m1);
        let res = receiver.recv(0, msg);
        assert_eq!(res, m0);
    }

    #[test]
    fn test_halo2_laconic_ot() {
        let rng = &mut OsRng;
        let message_length = 4;

        // Setup Trinity with Halo2 mode
        let trinity = Trinity::setup(KZGType::Halo2, message_length);

        // Create receiver with bits
        let bits = vec![Choice::Zero, Choice::One, Choice::Zero, Choice::One];
        let receiver = TrinityReceiver::new(&trinity.params, &bits);

        // Create sender
        let sender = TrinitySender::sender_new(&trinity.params, receiver.commitment());

        // Test sending and receiving
        let m0 = [0u8; MSG_SIZE];
        let m1 = [1u8; MSG_SIZE];
        let msg = sender.send(rng, 0, m0, m1);
        let res = receiver.recv(0, msg);
        assert_eq!(res, m0);
    }
}
