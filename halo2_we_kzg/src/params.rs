use ark_bn254::{G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use halo2_middleware::halo2curves::CurveAffine;
use halo2_proofs::halo2curves::{
    bn256::{Fq, G1Affine as Halo2G1, G2Affine as Halo2G2},
    ff_ext::quadratic::QuadExtField,
};

pub struct CurveAdapter;

impl CurveAdapter {
    pub fn convert_g1_element(ark_g1: &ArkG1) -> Halo2G1 {
        let (x, y) = ark_g1.xy().unwrap();
        Halo2G1::from_xy(
            Fq::from_raw(x.into_bigint().0),
            Fq::from_raw(y.into_bigint().0),
        )
        .unwrap()
    }

    pub fn convert_g2_element(ark_g2: &ArkG2) -> Halo2G2 {
        let (x, y) = ark_g2.xy().unwrap();
        Halo2G2::from_xy(
            QuadExtField::new(
                Fq::from_raw(x.c0.into_bigint().0),
                Fq::from_raw(x.c1.into_bigint().0),
            ),
            QuadExtField::new(
                Fq::from_raw(y.c0.into_bigint().0),
                Fq::from_raw(y.c1.into_bigint().0),
            ),
        )
        .unwrap()
    }

    pub fn convert_g1_vec(ark_vec: &[ArkG1]) -> Vec<Halo2G1> {
        ark_vec
            .iter()
            .map(|g| Self::convert_g1_element(g))
            .collect()
    }
}
