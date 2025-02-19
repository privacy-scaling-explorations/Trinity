use ark_bn254::{Bn254, Fr};
use ark_poly::Radix2EvaluationDomain;
// Assume these are from your separate crates:
use halo2_we_kzg::{
    params, Com as Halo2Com, Halo2Params, LaconicOTRecv as Halo2OTRecv,
    LaconicOTSender as Halo2OTSender,
};
use laconic_ot::{
    Choice, Com as PlainCom, CommitmentKey, LaconicOTRecv as PlainOTRecv,
    LaconicOTSender as PlainOTSender,
};
use rand::{rngs::OsRng, Rng};

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
    mode: KZGType,
    params: TrinityParams,
    plain_recv: Option<PlainOTRecv<'static, Bn254, Radix2EvaluationDomain<Fr>>>,
    halo2_recv: Option<halo2_we_kzg::LaconicOTRecv>,
    plain_sender: Option<PlainOTSender<'static, Bn254, Radix2EvaluationDomain<Fr>>>,
    halo2_sender: Option<halo2_we_kzg::LaconicOTSender>,
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
                let degree = message_length / 4;
                let halo2params =
                    Halo2Params::setup(rng, degree).expect("Failed to setup Halo2Params");
                TrinityParams::Halo2(halo2params)
            }
        };

        Self {
            mode,
            params,
            plain_recv: todo!(),
            halo2_recv: todo!(),
            plain_sender: todo!(),
            halo2_sender: todo!(),
        }
    }

    pub fn receiver_commit(&self, bits: &[Choice]) -> TrinityReceiver {
        match &self.params {
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

    pub fn receiver_receive(&self, i: usize, msg: TrinityMsg) {
        match &self.params {
            TrinityParams::Plain(_) => {
                if let Some(plain_recv) = &self.plain_recv {
                    if let TrinityMsg::Plain(inner_msg) = msg {
                        plain_recv.recv(i, inner_msg);
                    } else {
                        panic!("Expected plain message, got halo2 message");
                    }
                } else {
                    panic!("Plain receiver not initialized");
                }
            }
            TrinityParams::Halo2(_) => {
                if let Some(halo2_recv) = &self.halo2_recv {
                    if let TrinityMsg::Halo2(inner_msg) = msg {
                        halo2_recv.recv(i, inner_msg);
                    } else {
                        panic!("Expected halo2 message, got plain message");
                    }
                } else {
                    panic!("Halo2 OT receiver not initialized");
                }
            }
        }
    }

    // To do: Not sure if necessary for now
    // pub fn get_commitment() {
    // };

    pub fn sender_new(&self, com: TrinityCom) {
        match &self.params {
            TrinityParams::Plain(ck) => {
                if let TrinityCom::Plain(plain_com) = com {
                    let plain_sender = PlainOTSender::new(ck, plain_com);
                    TrinitySender::Plain(plain_sender);
                } else {
                    panic!("Expected plain commitment, got halo2 commitment");
                }
            }
            TrinityParams::Halo2(params) => {
                if let TrinityCom::Halo2(halo2_com) = com {
                    let halo2_sender =
                        Halo2OTSender::new(params.clone().params, halo2_com, params.clone().domain);
                    TrinitySender::Halo2(halo2_sender);
                } else {
                    panic!("Expected halo2 commitment, got plain commitment");
                }
            }
        }
    }

    pub fn sender_send<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
    ) {
        match &self.params {
            TrinityParams::Plain(_) => {
                if let Some(plain_sender) = &self.plain_sender {
                    plain_sender.send(rng, i, m0, m1);
                } else {
                    panic!("Plain sender not initialized");
                }
            }
            TrinityParams::Halo2(_) => {
                if let Some(halo2_sender) = &self.halo2_sender {
                    halo2_sender.send(rng, i, m0, m1);
                } else {
                    panic!("Halo2 OT sender not initialized");
                }
            }
        }
    }
}
