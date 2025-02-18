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

pub enum OTRecv<'a> {
    Plain(PlainOTRecv<'a, Bn254, Radix2EvaluationDomain<Fr>>),
    Halo2(Halo2OTRecv),
}

pub enum TrinityCommitmentKey {
    Plain(CommitmentKey<Bn254, Radix2EvaluationDomain<Fr>>),
    Halo2(Halo2Params),
}

impl TrinityCommitmentKey {
    pub fn setup(&self, rng: &mut OsRng, message_length: usize) -> TrinityCommitmentKey {
        match self {
            TrinityCommitmentKey::Plain(_) => {
                // Supply the required arguments and unwrap the Result
                let ck =
                    CommitmentKey::setup(rng, message_length).expect("CommitmentKey setup failed");
                TrinityCommitmentKey::Plain(ck)
            }
            TrinityCommitmentKey::Halo2(_) => {
                let params =
                    Halo2Params::setup(rng, message_length).expect("Halo2Params setup failed");
                TrinityCommitmentKey::Halo2(params)
            }
        }
    }
}

impl<'a> OTRecv<'a> {
    pub fn setup(kzg_type: KZGType, message_length: usize) -> Self {
        let rng = &mut OsRng;

        match kzg_type {
            KZGType::Plain => OTRecv::Plain(PlainOTRecv::new(rng, message_length)),
            KZGType::Halo2 => OTRecv::Halo2(Halo2OTRecv::new(bits)),
        }
    }

    pub fn commitment(&self) -> CommitmentType {
        match self {
            OTRecv::Plain(inner) => inner.commitment(),
            OTRecv::Halo2(inner) => inner.commitment(),
        }
    }

    pub fn recv(&self, index: usize, msg: MsgType) -> [u8; MSG_SIZE] {
        match self {
            OTRecv::Plain(inner) => inner.recv(index, msg),
            OTRecv::Halo2(inner) => inner.recv(index, msg),
        }
    }
}
