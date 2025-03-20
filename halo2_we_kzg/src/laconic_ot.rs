use std::marker::PhantomData;

use crate::{
    kzg_commitment_with_halo2_proof,
    poly_op::{eval_polynomial, poly_divide, serialize_cubic_ext_field},
    Halo2Params,
};
use halo2_backend::poly::{kzg::commitment::ParamsKZG, Coeff, Polynomial};
use halo2_middleware::zal::impls::PlonkEngineConfig;
use halo2_proofs::{
    arithmetic::Field,
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine, G2Affine, G1, G2},
    halo2curves::ff_ext::{cubic::CubicExtField, quadratic::QuadExtField},
    halo2curves::group::Curve,
    halo2curves::pairing::Engine,
    poly::{
        commitment::{Blind, ParamsProver},
        EvaluationDomain,
    },
};
use halo2curves::{bn256::Gt, serde::SerdeObject};
use rand::Rng;
use serde::{Deserialize, Serialize};

const MSG_SIZE: usize = 16;

fn fq12_to_bytes(gt: Gt) -> Vec<u8> {
    // Here we assume gt.get_base() returns an Fq12‑like type that has methods c0() and c1(),
    // each of which returns a CubicExtField.
    let base: QuadExtField<CubicExtField<QuadExtField<Fq>>> = gt.get_base();

    let mut out = Vec::new();
    // Serialize the first cubic extension (c0)
    out.extend_from_slice(&serialize_cubic_ext_field(base.c0()));
    // Serialize the second cubic extension (c1)
    out.extend_from_slice(&serialize_cubic_ext_field(base.c1()));
    out
}

#[derive(Clone, Copy, Debug)]
pub struct Msg {
    pub h: [(G2Affine, [u8; MSG_SIZE]); 2],
}

#[derive(Serialize, Deserialize)]
pub struct SerializableMsg {
    pub h: [(Vec<u8>, [u8; MSG_SIZE]); 2],
}

impl Msg {
    pub fn serialize(&self) -> Vec<u8> {
        let serializable = SerializableMsg {
            h: self.h.map(|(g2, msg)| {
                let g2_bytes = g2.to_raw_bytes(); // Vec<u8> with length 128
                (g2_bytes, msg)
            }),
        };
        serde_json::to_vec(&serializable).unwrap()
    }

    pub fn deserialize(data: &[u8]) -> Self {
        let serializable: SerializableMsg = serde_json::from_slice(data).unwrap();
        let h = serializable.h.map(|(g2_bytes, msg)| {
            assert_eq!(g2_bytes.len(), 128, "Invalid length for G2Affine");
            let g2 = G2Affine::from_raw_bytes(&g2_bytes).expect("Deserialization failed");
            (g2, msg)
        });
        Self { h }
    }
}

impl AsMut<[u8]> for Msg {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.h[0].1
    }
}

pub type Com = G1;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Choice {
    Zero,
    One,
}

impl Choice {
    pub fn to_fr<F: Field>(&self) -> Fr {
        match self {
            Choice::Zero => Fr::from(0),
            Choice::One => Fr::from(1),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LaconicOTRecv {
    qs: Vec<G1>,
    com: Com,
    bits: Vec<Choice>,
    pub halo2params: Halo2Params,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LaconicOTSender {
    params: ParamsKZG<Bn256>,
    com: Com,
    domain: EvaluationDomain<Fr>,
}

impl LaconicOTRecv {
    pub fn new(halo2params: Halo2Params, bits: &[Choice]) -> Self {
        let elems: Vec<_> = bits
            .iter()
            .map(|b| {
                if *b == Choice::One {
                    Fr::from(1)
                } else {
                    Fr::from(0)
                }
            })
            .collect();

        // pad with random elements, comment out for now
        // assert!(elems.len() <= ck.domain.size());
        // elems.resize_with(ck.domain.size(), || {
        //     E::ScalarField::rand(&mut ark_std::test_rng())
        // });

        let circuit_params = halo2params.params.clone();
        let circuit_output =
            kzg_commitment_with_halo2_proof(circuit_params, elems.clone()).unwrap();

        // Compute the commitment using `ParamsKZG`'s `commit_lagrange` function,
        // with default blinding factor and Plonk engine
        let engine = PlonkEngineConfig::build_default::<G1Affine>();

        let mut a = halo2params.domain.empty_lagrange();
        for (i, a) in a.iter_mut().enumerate() {
            if i < elems.len() {
                *a = elems[i];
            } else {
                *a = Fr::zero();
            }
        }

        // Convert polynomial f from Lagrange to coefficient form.
        let poly_coeff = halo2params.domain.lagrange_to_coeff(a.clone());

        // Get domain points
        let n = elems.len();
        let points: Vec<Fr> = (0..n)
            .map(|i| halo2params.domain.get_omega().pow(&[i as u64]))
            .collect();

        // Openings at the points
        let qs: Vec<G1> = points
            .iter()
            .map(|&z| {
                // Evaluate f at z.
                let f_z = eval_polynomial(&poly_coeff.values, z);

                // Compute quotient q(x) = (f(x) - f(z)) / (x - z).
                let quotient: Vec<Fr> = poly_divide(&poly_coeff.values, z, f_z);
                let quotient_poly = Polynomial {
                    values: quotient,
                    _marker: PhantomData::<Coeff>,
                };

                let alpha = Blind::default();

                // Commit to the quotient polynomial (in coefficient form).
                let point = halo2params
                    .params
                    .commit(&engine.msm_backend, &quotient_poly, alpha);
                point
            })
            .collect();

        Self {
            qs,
            com: circuit_output.commitment.into(),
            bits: bits.to_vec(),
            halo2params,
            proof: circuit_output.proof,
        }
    }

    pub fn recv(&self, i: usize, msg: Msg) -> [u8; MSG_SIZE] {
        let j: usize = if self.bits[i] == Choice::One { 1 } else { 0 };
        let h = msg.h[j].0;
        let c = msg.h[j].1;
        let q_affine: G1Affine = self.qs[i].to_affine();
        let m: Gt = <Bn256 as Engine>::pairing(&q_affine, &h);
        decrypt::<MSG_SIZE>(m, &c)
    }

    pub fn commitment(&self) -> Com {
        self.com
    }
}

fn encrypt<const N: usize>(pad: Gt, msg: &[u8; N]) -> [u8; N] {
    let pad_bytes = fq12_to_bytes(pad);
    // Hash the pad, converting it to bytes with to_bytes()
    let mut hasher = blake3::Hasher::new();
    hasher.update(&pad_bytes);

    // Finalize as an XOF and fill a buffer
    let mut xof = hasher.finalize_xof();
    let mut res = [0u8; N];
    xof.fill(&mut res);

    // XOR the generated bytes with the message to encrypt/decrypt.
    for i in 0..N {
        res[i] ^= msg[i];
    }
    res
}

fn decrypt<const N: usize>(pad: Gt, ct: &[u8; N]) -> [u8; N] {
    encrypt::<N>(pad, ct)
}

impl LaconicOTSender {
    pub fn new(params: ParamsKZG<Bn256>, com: Com, domain: EvaluationDomain<Fr>) -> Self {
        Self {
            params,
            com,
            domain,
        }
    }

    pub fn send<R: Rng>(
        &self,
        rng: &mut R,
        i: usize,
        m0: [u8; MSG_SIZE],
        m1: [u8; MSG_SIZE],
    ) -> Msg {
        let x = self.domain.get_omega().pow_vartime([i as u64]);
        let r0 = Fr::random(&mut *rng);
        let r1 = Fr::random(&mut *rng);

        let g1 = self.params.g[0];
        let g2 = self.params.g2;
        let tau = self.params.s_g2;

        // y = 0/1
        let l0 = self.com * r0; // r * (c - [y])
        let l1 = (self.com - g1) * r1; // r * (c - [y])

        let l0_affine = l0.to_affine();
        let l1_affine = l1.to_affine();

        // m0, m1
        let msk0 = <Bn256 as Engine>::pairing(&l0_affine, &self.params.g2);
        let msk1 = <Bn256 as Engine>::pairing(&l1_affine, &self.params.g2);

        // h0, h1
        let cm = Into::<G2>::into(tau) - g2 * x;
        let h0: G2 = cm * r0;
        let h1: G2 = cm * r1;

        // encapsulate the messages
        Msg {
            h: [
                (h0.into(), encrypt::<MSG_SIZE>(msk0, &m0)),
                (h1.into(), encrypt::<MSG_SIZE>(msk1, &m1)),
            ],
        }
    }
}

#[test]
fn test_laconic_ot() {
    use rand::rngs::OsRng;

    let rng = &mut OsRng;

    let degree = 4;
    let bitvector = [Choice::Zero, Choice::One, Choice::Zero, Choice::One];

    let halo2params = Halo2Params::setup(rng, degree).unwrap();

    let receiver = LaconicOTRecv::new(halo2params, &bitvector);

    let sender = LaconicOTSender::new(
        receiver.halo2params.params.clone(),
        receiver.commitment(),
        receiver.halo2params.domain.clone(),
    );

    let m0 = [0u8; MSG_SIZE];
    let m1 = [1u8; MSG_SIZE];
    let msg = sender.send(rng, 0, m0, m1);
    let res = receiver.recv(0, msg);
    assert_eq!(res, m0);
}

// fn main() {
//     let bits = vec![Choice::One, Choice::Zero, Choice::One, Choice::Zero];
//     let k = 4;
//     let ot_recv = LaconicOTRecv::new(&bits, k);
//     for i in 0..3 {
//         ot_recv.recv(
//             i,
//             Msg {
//                 h: [
//                     (G2Affine::random(OsRng), [0; MSG_SIZE]),
//                     (G2Affine::random(OsRng), [0; MSG_SIZE]),
//                 ],
//             },
//         );
//     }
//     println!("{:?}", ot_recv);
// }

#[test]
fn test_msg_halo2_serialization() {
    use halo2_proofs::halo2curves::bn256::G2Affine;
    use rand::rngs::OsRng;

    let rng = &mut OsRng;

    let original_msg = Msg {
        h: [
            (G2Affine::random(rng.clone()), [3u8; MSG_SIZE]),
            (G2Affine::random(rng), [4u8; MSG_SIZE]),
        ],
    };

    let serialized = original_msg.serialize();
    let deserialized_msg = Msg::deserialize(&serialized);

    assert_eq!(original_msg.h[0].1, deserialized_msg.h[0].1);
    assert_eq!(original_msg.h[1].1, deserialized_msg.h[1].1);
    assert_eq!(original_msg.h[0].0, deserialized_msg.h[0].0);
    assert_eq!(original_msg.h[1].0, deserialized_msg.h[1].0);
}
