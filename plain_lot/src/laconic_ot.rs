use crate::kzg_utils::plain_kzg_com;
use crate::{kzg_fk_open::all_openings_single, kzg_types::CommitmentKey};

use ark_ec::pairing::Pairing;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use ark_std::UniformRand;
use ark_std::Zero;
use rand::Rng;
use serde::{Deserialize, Serialize};

const MSG_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Choice {
    Zero,
    One,
}

impl<E: Pairing> Msg<E> {
    pub fn serialize(&self) -> Vec<u8> {
        let serializable = SerializableMsg {
            h: self.h.map(|(g2, msg)| {
                let mut g2_bytes = Vec::new();
                g2.serialize_compressed(&mut g2_bytes).unwrap();
                (g2_bytes, msg)
            }),
        };
        serde_json::to_vec(&serializable).unwrap()
    }

    pub fn deserialize(data: &[u8]) -> Self {
        let serializable: SerializableMsg = serde_json::from_slice(data).unwrap();
        let h = serializable.h.map(|(g2_bytes, msg)| {
            let g2 = E::G2Affine::deserialize_compressed(&*g2_bytes)
                .expect("Failed to deserialize G2Affine");
            (g2, msg)
        });
        Self { h }
    }
}
pub type Com<E: Pairing> = E::G1;

impl Choice {
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let b: bool = rng.gen();
        if b {
            Choice::One
        } else {
            Choice::Zero
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Msg<E: Pairing> {
    pub h: [(E::G2Affine, [u8; MSG_SIZE]); 2],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableMsg {
    pub h: [(Vec<u8>, [u8; MSG_SIZE]); 2],
}

impl<E: Pairing> From<Msg<E>> for SerializableMsg {
    fn from(msg: Msg<E>) -> Self {
        let mut buf0 = Vec::new();
        let mut buf1 = Vec::new();
        let _ = msg.h[0].0.serialize_uncompressed(&mut buf0);
        let _ = msg.h[1].0.serialize_uncompressed(&mut buf1);

        SerializableMsg {
            h: [(buf0, msg.h[0].1), (buf1, msg.h[1].1)],
        }
    }
}

impl<E: Pairing> TryFrom<SerializableMsg> for Msg<E> {
    type Error = ark_serialize::SerializationError;

    fn try_from(s: SerializableMsg) -> Result<Self, Self::Error> {
        Ok(Msg {
            h: [
                (
                    E::G2Affine::deserialize_uncompressed(&s.h[0].0[..])?,
                    s.h[0].1,
                ),
                (
                    E::G2Affine::deserialize_uncompressed(&s.h[1].0[..])?,
                    s.h[1].1,
                ),
            ],
        })
    }
}

pub struct LaconicOT<E: Pairing, D: EvaluationDomain<E::ScalarField>> {
    ck: CommitmentKey<E, D>,
}

#[derive(Debug, Clone)]
pub struct LaconicOTRecv<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> {
    ck: &'a CommitmentKey<E, D>,
    qs: Vec<E::G1>,
    com: E::G1,
    bits: Vec<Choice>,
}

pub struct LaconicOTSender<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> {
    ck: &'a CommitmentKey<E, D>,
    com: E::G1,
}

impl<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> LaconicOTRecv<'a, E, D> {
    pub fn new(ck: &'a CommitmentKey<E, D>, bits: &[Choice]) -> Self {
        let mut elems: Vec<_> = bits
            .iter()
            .map(|b| {
                if *b == Choice::One {
                    E::ScalarField::one()
                } else {
                    E::ScalarField::zero()
                }
            })
            .collect();

        // pad with random elements
        assert!(elems.len() <= ck.domain.size());
        elems.resize_with(ck.domain.size(), || {
            E::ScalarField::rand(&mut ark_std::test_rng())
        });

        // compute commitment
        let com = plain_kzg_com(ck, &elems);

        // compute all openings
        let qs = all_openings_single::<E, D>(&ck.y, &ck.domain, &elems);

        Self {
            ck,
            qs,
            com: com.into(),
            bits: bits.to_vec(),
        }
    }

    pub fn recv(&self, i: usize, msg: Msg<E>) -> [u8; MSG_SIZE] {
        let j: usize = if self.bits[i] == Choice::One { 1 } else { 0 };
        let h = msg.h[j].0;
        let c = msg.h[j].1;
        let m = E::pairing(self.qs[i], h);
        decrypt::<E, MSG_SIZE>(m.0, &c)
    }

    pub fn commitment(&self) -> Com<E> {
        self.com
    }
}

fn encrypt<E: Pairing, const N: usize>(pad: E::TargetField, msg: &[u8; N]) -> [u8; N] {
    // hash the pad
    let mut hsh = blake3::Hasher::new();
    pad.serialize_uncompressed(&mut hsh).unwrap();

    // xor the message with the pad
    let mut xof = hsh.finalize_xof();
    let mut res = [0u8; N];
    xof.fill(&mut res);

    for i in 0..N {
        res[i] ^= msg[i];
    }
    res
}

fn decrypt<E: Pairing, const N: usize>(pad: E::TargetField, ct: &[u8; N]) -> [u8; N] {
    encrypt::<E, N>(pad, ct)
}

impl<'a, E: Pairing, D: EvaluationDomain<E::ScalarField>> LaconicOTSender<'a, E, D> {
    pub fn new(ck: &'a CommitmentKey<E, D>, com: Com<E>) -> Self {
        Self { ck, com }
    }

    pub fn send<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
    ) -> Msg<E> {
        let x = self.ck.domain.element(i);
        let r0 = E::ScalarField::rand(rng);
        let r1 = E::ScalarField::rand(rng);

        let g1 = self.ck.u[0];
        let g2 = self.ck.g2;
        let tau = self.ck.r;

        // y = 0/1
        let l0 = self.com * r0; // r * (c - [y])
        let l1 = (self.com - g1) * r1; // r * (c - [y])

        // m0, m1
        let msk0 = E::pairing(l0, self.ck.g2);
        let msk1 = E::pairing(l1, self.ck.g2);

        // h0, h1
        let cm = Into::<E::G2>::into(tau) - g2 * x;
        let h0: E::G2 = cm * r0;
        let h1: E::G2 = cm * r1;

        // encapsulate the messages
        Msg {
            h: [
                (h0.into(), encrypt::<E, MSG_SIZE>(msk0.0, &m0)),
                (h1.into(), encrypt::<E, MSG_SIZE>(msk1.0, &m1)),
            ],
        }
    }
}

#[test]
fn test_laconic_ot() {
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    let rng = &mut test_rng();

    let degree = 4;
    let ck = CommitmentKey::<Bls12_381, Radix2EvaluationDomain<Fr>>::setup(rng, degree).unwrap();

    let sender = LaconicOTRecv::new(&ck, &[Choice::Zero, Choice::One, Choice::Zero, Choice::One]);
    let receiver = LaconicOTSender::new(&ck, sender.commitment());

    let m0 = [0u8; MSG_SIZE];
    let m1 = [1u8; MSG_SIZE];
    let msg = receiver.send(rng, 0, m0, m1);
    let res = sender.recv(0, msg);
    assert_eq!(res, m0);
}

#[test]
fn test_msg_serialization() {
    use ark_bls12_381::{Bls12_381, Fr, G2Affine};
    use rand::rngs::OsRng;

    // Create dummy Msg
    let rng = &mut OsRng;
    let h = [
        (G2Affine::rand(rng), [1u8; MSG_SIZE]),
        (G2Affine::rand(rng), [2u8; MSG_SIZE]),
    ];

    let original_msg = Msg::<Bls12_381> { h };

    // Serialize
    let serialized = original_msg.serialize();

    // Deserialize
    let deserialized_msg = Msg::<Bls12_381>::deserialize(&serialized);

    // Verify equality
    assert_eq!(original_msg.h[0].1, deserialized_msg.h[0].1);
    assert_eq!(original_msg.h[1].1, deserialized_msg.h[1].1);
    assert_eq!(original_msg.h[0].0, deserialized_msg.h[0].0);
    assert_eq!(original_msg.h[1].0, deserialized_msg.h[1].0);
}
