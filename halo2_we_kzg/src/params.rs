use halo2_proofs::poly::{kzg::commitment::ParamsKZG, EvaluationDomain};
use halo2curves::bn256::{Bn256, Fr};

#[derive(Debug, Clone)]
pub struct Halo2Params {
    pub k: usize,
    pub domain: EvaluationDomain<Fr>,
    pub params: ParamsKZG<Bn256>,
}

impl Halo2Params {
    pub fn setup<R: rand::Rng>(rng: &mut R, k: usize) -> Result<Halo2Params, ()> {
        let params: ParamsKZG<Bn256> = ParamsKZG::setup(k as u32, rng);
        // Create evaluation domain
        let domain = EvaluationDomain::new(1, k as u32);

        Ok(Halo2Params { k, domain, params })
    }
}
