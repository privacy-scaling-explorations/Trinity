use crate::{
    kzg_commitment_with_halo2_proof, params::LaconicParams, poly_op::serialize_cubic_ext_field,
    Halo2Params,
};
use halo2_proofs::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine, G2Affine, G1, G2},
        ff_ext::{cubic::CubicExtField, quadratic::QuadExtField},
        group::Curve,
        pairing::Engine,
    },
    poly::{commitment::Params, kzg::commitment::ParamsKZG, EvaluationDomain},
};
use halo2curves::{bn256::Gt, serde::SerdeObject};
use rand::Rng;
use serde::{Deserialize, Serialize};

const MSG_SIZE: usize = 16;

fn fq12_to_bytes(gt: Gt) -> Vec<u8> {
    // Here gt.get_base() returns an Fq12‑like type that has methods c0() and c1(),
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableMsg {
    pub h: [(Vec<u8>, [u8; MSG_SIZE]); 2],
}

// Implement From trait to convert Msg to SerializableMsg
impl From<Msg> for SerializableMsg {
    fn from(msg: Msg) -> Self {
        SerializableMsg {
            h: [
                (msg.h[0].0.to_raw_bytes(), msg.h[0].1),
                (msg.h[1].0.to_raw_bytes(), msg.h[1].1),
            ],
        }
    }
}

// Implement TryFrom trait to convert SerializableMsg to Msg
impl TryFrom<SerializableMsg> for Msg {
    type Error = &'static str;

    fn try_from(s: SerializableMsg) -> Result<Self, Self::Error> {
        let g2_0 =
            G2Affine::from_raw_bytes(&s.h[0].0).ok_or("Failed to deserialize first G2Affine")?;
        let g2_1 =
            G2Affine::from_raw_bytes(&s.h[1].0).ok_or("Failed to deserialize second G2Affine")?;

        Ok(Msg {
            h: [(g2_0, s.h[0].1), (g2_1, s.h[1].1)],
        })
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
    params: LaconicParams,
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

        let circuit_params = halo2params.params.clone();
        let circuit_output = kzg_commitment_with_halo2_proof(circuit_params, elems.clone())
            .expect("kzg_commitment_with_halo2_proof failed");

        let domain_size = 1 << halo2params.k;
        let mut elems_padded = elems.clone();
        if elems_padded.len() < domain_size {
            elems_padded.resize(domain_size, Fr::zero());
        }

        let qs = crate::poly_op::all_openings_fk(
            &halo2params.precomputed_y,
            &halo2params.domain,
            &elems_padded,
        )
        .expect("Failed to compute all openings FK");
        // let n = elems.clone().len();
        // let points: Vec<Fr> = (0..n)
        //     .map(|i| halo2params.domain.get_omega().pow(&[i as u64]))
        //     .collect();
        // let qs: Vec<G1> = points
        //     .iter()
        //     .map(|&z| kzg_open(z, halo2params.clone(), elems.clone()))
        //     .collect();

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
    pub fn new(_params: ParamsKZG<Bn256>, com: Com) -> Self {
        let verifier_params = _params.verifier_params();
        let domain = EvaluationDomain::new(1, verifier_params.k());
        let params = LaconicParams {
            k: verifier_params.k(),
            g0: _params.g[0],
            g2: _params.g2,
            s_g2: _params.s_g2,
        };

        Self {
            params,
            com,
            domain,
        }
    }

    pub fn new_from(params: LaconicParams, com: Com) -> Self {
        let domain = EvaluationDomain::new(1, params.k);
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

        let g1 = self.params.g0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kzg_commitment_with_halo2_proof,
        poly_op::{eval_polynomial, poly_divide},
        Halo2Params,
    };

    use halo2_backend::poly::{Coeff, Polynomial};
    use halo2_middleware::zal::impls::PlonkEngineConfig;
    use halo2_proofs::{
        arithmetic::Field,
        halo2curves::bn256::{Fr, G1Affine, G1},
        poly::commitment::{Blind, ParamsProver},
    };
    use rand::{rngs::OsRng, Rng};
    use std::io::{self, Write};
    use std::marker::PhantomData;
    use std::time::Instant;

    fn generate_bitvector(size: usize) -> Vec<Choice> {
        let mut rng = OsRng;
        (0..size)
            .map(|_| {
                if rng.gen::<bool>() {
                    Choice::One
                } else {
                    Choice::Zero
                }
            })
            .collect()
    }

    fn bitvector_to_fr(bitvector: &[Choice]) -> Vec<Fr> {
        bitvector
            .iter()
            .map(|b| {
                if *b == Choice::One {
                    Fr::from(1)
                } else {
                    Fr::from(0)
                }
            })
            .collect()
    }

    #[test]
    fn test_laconic_ot() {
        use rand::rngs::OsRng;

        let rng = &mut OsRng;

        let degree = 4;
        let bitvector = [Choice::Zero, Choice::One, Choice::Zero, Choice::One];

        let halo2params = Halo2Params::setup(rng, degree).unwrap();
        let laconic_params = LaconicParams::from(&halo2params);

        let receiver = LaconicOTRecv::new(halo2params, &bitvector);

        let sender = LaconicOTSender::new_from(laconic_params, receiver.commitment());

        let m0 = [0u8; MSG_SIZE];
        let m1 = [1u8; MSG_SIZE];
        let msg = sender.send(rng, 0, m0, m1);
        let res = receiver.recv(0, msg);
        assert_eq!(res, m0);
    }

    #[test]
    fn test_msg_halo2_serialization() {
        use halo2_proofs::halo2curves::bn256::G2Affine;
        use rand::rngs::OsRng;
        use std::convert::{From, TryFrom};

        let rng = &mut OsRng;

        // Create original message
        let original_msg = Msg {
            h: [
                (G2Affine::random(rng.clone()), [3u8; MSG_SIZE]),
                (G2Affine::random(rng), [4u8; MSG_SIZE]),
            ],
        };

        // Convert to serializable form
        let serializable_msg = SerializableMsg::from(original_msg);

        // Verify raw bytes are correct length
        assert!(serializable_msg.h[0].0.len() > 0);
        assert!(serializable_msg.h[1].0.len() > 0);

        // Convert back to original type
        let deserialized_msg = Msg::try_from(serializable_msg).expect("Deserialization failed");

        // Verify everything matches
        assert_eq!(original_msg.h[0].1, deserialized_msg.h[0].1);
        assert_eq!(original_msg.h[1].1, deserialized_msg.h[1].1);
        assert_eq!(original_msg.h[0].0, deserialized_msg.h[0].0);
        assert_eq!(original_msg.h[1].0, deserialized_msg.h[1].0);

        // Optional: For compatibility, verify we can still use bincode or serde_json if needed
        let json_bytes = serde_json::to_vec(&SerializableMsg::from(original_msg))
            .expect("JSON serialization failed");
        let from_json = serde_json::from_slice::<SerializableMsg>(&json_bytes)
            .expect("JSON deserialization failed");
        let from_json_msg = Msg::try_from(from_json).expect("Conversion failed");

        assert_eq!(original_msg.h[0].0, from_json_msg.h[0].0);
        assert_eq!(original_msg.h[1].0, from_json_msg.h[1].0);
    }

    #[test]
    fn test_laconic_ot_recv_single_open() {
        let degree = 8;
        let size = 1 << degree;

        // Setup
        let bitvector = generate_bitvector(size - 10);
        let elems = bitvector_to_fr(&bitvector);
        let halo2params = Halo2Params::setup(&mut OsRng, degree).unwrap();
        let engine = PlonkEngineConfig::build_default::<G1Affine>();

        let start_time = Instant::now();

        // Polynomial prep
        let prep_start = Instant::now();
        println!("Element preparation took: {:?}", prep_start.elapsed());

        // KZG commitment with Halo2 proof
        let kzg_start = Instant::now();
        let circuit_params = halo2params.params.clone();
        let _circuit_output =
            kzg_commitment_with_halo2_proof(circuit_params, elems.clone()).unwrap();
        println!(
            "KZG commitment with Halo2 proof took: {:?}",
            kzg_start.elapsed()
        );

        // Polynomial conversion
        let poly_start = Instant::now();
        let mut lagrange = halo2params.domain.empty_lagrange();
        for (i, val) in elems.iter().enumerate() {
            lagrange[i] = *val;
        }
        let poly_coeff = halo2params.domain.lagrange_to_coeff(lagrange);
        println!("Polynomial conversion took: {:?}", poly_start.elapsed());

        // Domain point computation
        let domain_start = Instant::now();
        let points: Vec<Fr> = (0..elems.len())
            .map(|i| halo2params.domain.get_omega().pow(&[i as u64]))
            .collect();
        println!(
            "Domain point computation took: {:?}",
            domain_start.elapsed()
        );

        // Openings
        let openings_start = Instant::now();
        let qs: Vec<G1> = points
            .iter()
            .map(|&z| {
                let f_z = eval_polynomial(&poly_coeff.values, z);
                let quotient = poly_divide(&poly_coeff.values, z, f_z);
                let quotient_poly = Polynomial {
                    values: quotient,
                    _marker: PhantomData::<Coeff>,
                };
                let alpha = Blind::default();
                halo2params
                    .params
                    .commit(&engine.msm_backend, &quotient_poly, alpha)
            })
            .collect();
        println!(
            "Openings at the points took: {:?}",
            openings_start.elapsed()
        );

        println!(
            "LaconicOTRecv::new execution time: {:?}",
            start_time.elapsed()
        );

        assert!(!qs.is_empty());
        io::stdout().flush().unwrap();
    }

    #[test]
    fn test_laconic_ot_recv_fk_openings() {
        let degree = 8;
        let size = 1 << degree;

        println!("Testing LaconicOTRecv::all_openings_fk with size: {}", size);

        // Setup
        let bitvector = generate_bitvector(size);
        let elems = bitvector_to_fr(&bitvector);
        let halo2params = Halo2Params::setup(&mut OsRng, degree).unwrap();

        let start_time = Instant::now();

        // Polynomial prep
        let prep_start = Instant::now();
        println!("Element preparation took: {:?}", prep_start.elapsed());

        // Precomputation
        let precompute_start = Instant::now();
        let powers = &halo2params.params.g[..size];
        let y = crate::poly_op::precompute_y(powers, &halo2params.domain);
        println!("precompute took: {:?}", precompute_start.elapsed());

        // FK-style all-openings
        let fk_start = Instant::now();
        let fk_qs = crate::poly_op::all_openings_fk(&y, &halo2params.domain, &elems)
            .expect("Failed to compute all openings FK");
        println!("all_openings_fk openings took: {:?}", fk_start.elapsed());

        println!(
            "LaconicOTRecv::all_openings_fk execution time: {:?}",
            start_time.elapsed()
        );

        assert_eq!(fk_qs.len(), size);
        io::stdout().flush().unwrap();
    }
}
