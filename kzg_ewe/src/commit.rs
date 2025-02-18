// use ark_bn254::{Bn254, Fr as bn254Fr};
// use ark_ff::Field;
// use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
// use halo2_proofs::{
//     halo2curves::bn256::{Bn256, Fr as bn256Fr, G1Affine},
//     poly::kzg::commitment::ParamsKZG,
// };
// use laconic_ot::{plain_kzg_com, Choice, CommitmentKey, all_openings_single};
// use rand::{rngs::OsRng, Rng};

// use crate::{halo2_circuit::BitvectorCommitmentCircuit, kzg_params::CurveAdapter};

// pub enum CommitmentStrategy {
//     PlainKZG,
//     Halo2Circuit,
// }

// pub struct BitvectorCommitment {
//     pub bits: Vec<bool>,
//     pub commitment: G1Affine,
//     pub halo2_params: ParamsKZG<Bn256>,
//     pub ck: CommitmentKey<Bn254, Radix2EvaluationDomain<bn254Fr>>,
// }

// impl BitvectorCommitment {

//     pub fn new(bits: Vec<bool>, strategy: CommitmentStrategy, k: u32) -> Self {
//         let message_length = bits.len();
//         let rng = &mut OsRng;
//         let ck =
//             CommitmentKey::<Bn254, Radix2EvaluationDomain<bn254Fr>>::setup(rng, message_length)
//                 .expect("Failed to setup CommitmentKey");

//         // Convert CommitmentKey parameters to Halo2 format
//         let g = CurveAdapter::convert_g1_vec(&ck.u);
//         let g_lagrange = CurveAdapter::convert_g1_vec(&ck.lagranges);
//         let g2 = CurveAdapter::convert_g2_element(&ck.g2);
//         let s_g2 = CurveAdapter::convert_g2_element(&ck.r);

//         let halo2_params = ParamsKZG::from_parts(_, k, g, Some(g_lagrange), g2, s_g2);

//         let commitment = match strategy {
//             CommitmentStrategy::PlainKZG => Self::commit_plain_kzg(&ck, &bits),
//             CommitmentStrategy::Halo2Circuit => Self::commit_halo2(&bits, &halo2_params),
//         };

//         Self {
//             bits,
//             commitment,
//             halo2_params,
//             ck,
//         }
//     }

//     fn commit_plain_kzg(
//         ck: &CommitmentKey<Bn254, Radix2EvaluationDomain<bn254Fr>>,
//         bits: &[bool],
//     ) -> G1Affine {
//         let bitvector: Vec<bn254Fr> = bits
//             .iter()
//             .map(|&b| if b { bn254Fr::from(1) } else { bn254Fr::from(0) })
//             .collect();

//         // pad with random elements
//         assert!(bitvector.len() <= ck.domain.size());
//         // bitvector.resize_with(ck.domain.size(), || {
//         //     E::ScalarField::rand(&mut ark_std::test_rng())
//         // });

//         // compute commitment
//         let com = plain_kzg_com(ck, &bitvector);

//         // compute all openings
//         let qs = all_openings_single::<E, D>(&ck.y, &ck.domain, &bitvector);

//         {ck,
//             qs,
//             com: com.into(),
//             bits: bits.to_vec()}
//     }

//     fn commit_halo2(bits: &[bool], params: &KZGParamsWrapper) -> G1Affine {
//         let circuit = BitvectorCommitmentCircuit {
//             bitvector: bits
//                 .iter()
//                 .map(|&b| if b { bn256Fr::one() } else { bn256Fr::zero() })
//                 .collect(),
//         };

//         // Use params.get_params() for Halo2 circuit commitment
//         // Implement Halo2 commitment logic
//         unimplemented!()
//     }
// }
