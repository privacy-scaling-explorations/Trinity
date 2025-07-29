use halo2_proofs::poly::{kzg::commitment::ParamsKZG, EvaluationDomain};
use halo2curves::{
    bn256::{Bn256, Fr, G1Affine, G2Affine},
    serde::SerdeObject,
};
use serde::{Deserialize, Serialize};

use crate::poly_op::precompute_y;

#[derive(Debug, Clone)]
pub struct Halo2Params {
    pub k: usize,
    pub domain: EvaluationDomain<Fr>,
    pub params: ParamsKZG<Bn256>,
    pub precomputed_y: Vec<G1Affine>,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableHalo2Params {
    pub k: u32,
    pub g0: Vec<u8>,
    pub g2: Vec<u8>,
    pub s_g2: Vec<u8>,
}

impl Halo2Params {
    pub fn setup<R: rand::Rng>(rng: &mut R, k: usize) -> Result<Halo2Params, ()> {
        let params: ParamsKZG<Bn256> = ParamsKZG::setup(k as u32, rng);
        let domain = EvaluationDomain::new(1, k as u32);

        let size = 1 << k;
        let powers = &params.g[..size];
        let precomputed_y = precompute_y(powers, &domain);

        Ok(Halo2Params {
            k,
            domain,
            params,
            precomputed_y,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let serializable = SerializableHalo2Params {
            k: self.k as u32,
            g0: self.params.g[0].to_raw_bytes(),
            g2: self.params.g2.to_raw_bytes(),
            s_g2: self.params.s_g2.to_raw_bytes(),
        };

        bincode::serialize(&serializable).unwrap_or_default()
    }

    pub fn to_laconic_bytes(&self) -> Vec<u8> {
        // Direct conversion to SerializableLaconicParams
        let serializable = SerializableLaconicParams {
            k: self.k as u32,
            g0: self.params.g[0].to_raw_bytes(),
            g2: self.params.g2.to_raw_bytes(),
            s_g2: self.params.s_g2.to_raw_bytes(),
        };

        bincode::serialize(&serializable).unwrap_or_default()
    }

    // pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
    //     let serializable: SerializableHalo2Params =
    //         bincode::deserialize(bytes).map_err(|_| "Failed to deserialize Halo2Params")?;

    //     // Convert the serializable format to Halo2Params
    //     let k = serializable.k as usize;
    //     let domain = EvaluationDomain::new(1, serializable.k);

    //     // Deserialize curve points
    //     let g0 =
    //         G1Affine::from_raw_bytes(&serializable.g0).ok_or("Failed to deserialize G1 point")?;
    //     let g2 =
    //         G2Affine::from_raw_bytes(&serializable.g2).ok_or("Failed to deserialize G2 point")?;
    //     let s_g2 =
    //         G2Affine::from_raw_bytes(&serializable.s_g2).ok_or("Failed to deserialize G2 point")?;

    //     // Create ParamsKZG
    //     let params = ParamsKZG {
    //         k: serializable.k,
    //         n: 1 << serializable.k as u64,
    //         g: vec![g0],
    //         g_lagrange: vec![],
    //         g2,
    //         s_g2,
    //     };

    //     Ok(Halo2Params { k, domain, params })
    // }
}

/// Minimal parameters needed for LaconicOT protocols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaconicParams {
    pub k: u32,
    pub g0: G1Affine,   // Just the first generator point
    pub g2: G2Affine,   // G2 generator
    pub s_g2: G2Affine, // G2 s-value
}

#[derive(Serialize, Deserialize)]
pub struct SerializableLaconicParams {
    pub k: u32,
    pub g0: Vec<u8>,
    pub g2: Vec<u8>,
    pub s_g2: Vec<u8>,
}

// Conversion from Halo2Params to LaconicParams
impl From<&Halo2Params> for LaconicParams {
    fn from(params: &Halo2Params) -> Self {
        LaconicParams {
            k: params.k as u32,
            g0: params.params.g[0],
            g2: params.params.g2,
            s_g2: params.params.s_g2,
        }
    }
}

// Serialization impl
impl From<&LaconicParams> for SerializableLaconicParams {
    fn from(params: &LaconicParams) -> Self {
        SerializableLaconicParams {
            k: params.k,
            g0: params.g0.to_raw_bytes(),
            g2: params.g2.to_raw_bytes(),
            s_g2: params.s_g2.to_raw_bytes(),
        }
    }
}

// Deserialization impl
impl TryFrom<SerializableLaconicParams> for LaconicParams {
    type Error = &'static str;

    fn try_from(s: SerializableLaconicParams) -> Result<Self, Self::Error> {
        let g0 = G1Affine::from_raw_bytes(&s.g0).ok_or("Failed to deserialize g0")?;
        let g2 = G2Affine::from_raw_bytes(&s.g2).ok_or("Failed to deserialize g2")?;
        let s_g2 = G2Affine::from_raw_bytes(&s.s_g2).ok_or("Failed to deserialize s_g2")?;

        Ok(LaconicParams {
            k: s.k,
            g0,
            g2,
            s_g2,
        })
    }
}

impl LaconicParams {
    pub fn to_bytes(&self) -> Vec<u8> {
        let serializable = SerializableLaconicParams::from(self);
        bincode::serialize(&serializable).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let serializable: SerializableLaconicParams =
            bincode::deserialize(bytes).map_err(|_| "Failed to deserialize LaconicParams")?;

        LaconicParams::try_from(serializable)
    }
}
