use ark_bn254::{Bn254, Fr};
use ark_poly::Radix2EvaluationDomain;
// Assume these are from your separate crates:
use halo2_we_kzg::{Halo2Params, LaconicOTRecv as Halo2OTRecv};
use laconic_ot::{Choice, CommitmentKey, LaconicOTRecv as PlainOTRecv};
use rand::rngs::OsRng;

pub enum KZGType {
    Plain,
    Halo2,
}

pub enum TrinityParams {
    Plain(CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>>),
    Halo2(Halo2Params),
}

pub enum TrinityReceiver<'a> {
    Plain(laconic_ot::LaconicOTRecv<'a, Bn254, Radix2EvaluationDomain<Fr>>),
    Halo2(halo2_we_kzg::LaconicOTRecv),
}

pub struct Trinity {
    mode: KZGType,
    params: TrinityParams,
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
                let degree = message_length / 4;
                let halo2params =
                    Halo2Params::setup(rng, degree).expect("Failed to setup Halo2Params");
                TrinityParams::Halo2(halo2params)
            }
        };

        Self { mode, params }
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

    pub fn receiver_receive();

    pub fn get_commitment();

    pub fn sender_new();

    pub fn sender_send();
}
