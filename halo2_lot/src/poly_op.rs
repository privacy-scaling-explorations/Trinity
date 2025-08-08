use std::marker::PhantomData;

use halo2_backend::poly::{Coeff, Polynomial};
use halo2_middleware::{multicore, zal::impls::PlonkEngineConfig};
use halo2_proofs::{
    arithmetic::Field,
    poly::{
        commitment::{Blind, ParamsProver},
        EvaluationDomain,
    },
};
use halo2curves::{
    bn256::{Fq, Fr, G1Affine, G1},
    ff_ext::{cubic::CubicExtField, quadratic::QuadExtField},
    fft::best_fft,
    group::{cofactor::CofactorCurveAffine, Curve, Group},
};

use crate::Halo2Params;

pub fn poly_divide<Fr: Field>(poly: &[Fr], c: Fr, f_c: Fr) -> Vec<Fr> {
    // poly: coefficients [a0, a1, ..., a_{n-1}] of f(x)
    // We want to return q(x) such that f(x)-f(c) = (x-c)*q(x).
    let n = poly.len();
    if n == 0 {
        return vec![];
    }
    // Allocate quotient polynomial of degree n-1.
    let mut q = vec![Fr::ZERO; n - 1];
    // Start with highest-degree coefficient.
    q[n - 2] = poly[n - 1];
    // Process remaining coefficients in reverse order.
    for i in (1..n - 1).rev() {
        q[i - 1] = poly[i] + c * q[i];
    }
    // At this point, the synthetic division remainder is:
    // remainder = poly[0] + c * q[0] (which should equal f_c).
    // Optionally, you can assert that equality.
    assert_eq!(poly[0] + c * q[0], f_c);
    q
}

/// This evaluates a provided polynomial (in coefficient form) at `point`.
pub fn eval_polynomial<Fr: Field>(poly: &[Fr], point: Fr) -> Fr {
    fn evaluate<F: Field>(poly: &[F], point: F) -> F {
        poly.iter()
            .rev()
            .fold(F::ZERO, |acc, coeff| acc * point + coeff)
    }
    let n = poly.len();
    let num_threads = multicore::current_num_threads();
    if n * 2 < num_threads {
        evaluate(poly, point)
    } else {
        let chunk_size = (n + num_threads - 1) / num_threads;
        let mut parts = vec![Fr::ZERO; num_threads];
        multicore::scope(|scope| {
            for (chunk_idx, (out, poly)) in
                parts.chunks_mut(1).zip(poly.chunks(chunk_size)).enumerate()
            {
                scope.spawn(move |_| {
                    let start = chunk_idx * chunk_size;
                    out[0] = evaluate(poly, point) * point.pow_vartime([start as u64, 0, 0, 0]);
                });
            }
        });
        parts.iter().fold(Fr::ZERO, |acc, coeff| acc + coeff)
    }
}

// Serialize a quadratic extension field element.
pub fn serialize_quad_ext_field(quad: &QuadExtField<Fq>) -> Vec<u8> {
    let mut out = Vec::new();
    // Append the serialization of the two field components.
    out.extend_from_slice(quad.c0().to_bytes().as_ref());
    out.extend_from_slice(quad.c1().to_bytes().as_ref());
    out
}

// Serialize a cubic extension field element.
pub fn serialize_cubic_ext_field(cubic: &CubicExtField<QuadExtField<Fq>>) -> Vec<u8> {
    let mut out = Vec::new();
    // The CubicExtField is assumed to have three components: c0, c1, c2.
    out.extend_from_slice(&serialize_quad_ext_field(cubic.c0()));
    out.extend_from_slice(&serialize_quad_ext_field(cubic.c1()));
    out.extend_from_slice(&serialize_quad_ext_field(cubic.c2()));
    out
}

// Compute the KZG opening for a polynomial at a given point.
pub fn kzg_open(point: Fr, halo2params: Halo2Params, elems: Vec<Fr>) -> G1 {
    let engine = PlonkEngineConfig::build_default::<G1Affine>();
    let mut a = halo2params.domain.empty_lagrange();
    for (i, a) in a.iter_mut().enumerate() {
        if i < elems.len() {
            *a = elems[i];
        } else {
            *a = Fr::zero();
        }
    }
    let poly_coeff = halo2params.domain.lagrange_to_coeff(a.clone());

    // Evaluate f at z.
    let f_z = eval_polynomial(&poly_coeff.values, point);

    // Compute quotient q(x) = (f(x) - f(z)) / (x - z).
    let quotient: Vec<Fr> = poly_divide(&poly_coeff.values, point, f_z);
    let quotient_poly = Polynomial {
        values: quotient,
        _marker: PhantomData::<Coeff>,
    };

    let alpha = Blind::default();

    // Commit to the quotient polynomial (in coefficient form).
    halo2params
        .params
        .commit(&engine.msm_backend, &quotient_poly, alpha)
}

pub fn precompute_y(
    powers: &[G1Affine],
    domain: &halo2_proofs::poly::EvaluationDomain<Fr>,
) -> Vec<G1Affine> {
    let domain_size = 1 << domain.k();
    let d = domain_size - 1;

    // Extended domain
    let domain2 = EvaluationDomain::new(1, domain.k() + 1);
    let domain2_size = 1 << domain2.k();

    assert_eq!(domain2_size, 2 * d + 2, "domain2 size must equal 2d + 2");
    assert!(
        powers.len() >= d,
        "Powers must contain at least d elements, got {}",
        powers.len()
    );

    // Construct hat_s = [powers[d-1],...,powers[0], d+2 zeros]
    let mut hat_s = vec![G1::identity(); 2 * d + 2];
    for (i, p) in powers[..d].iter().rev().enumerate() {
        hat_s[i] = (*p).into();
    }

    best_fft(
        &mut hat_s,
        domain2.get_extended_omega(),
        domain2.extended_k(),
    );

    // Return normalized y
    let mut y_affine = vec![G1Affine::identity(); domain2_size];
    G1::batch_normalize(&hat_s, &mut y_affine);

    y_affine
}

/// Fast amortized computation of all KZG openings using the FK technique.
/// Returns a vector of G1 elements, each corresponding to an opening at a domain point.
/// - `y`: precomputed vector y = DFT(hat_s)
/// - `domain`: the evaluation domain
/// - `evals`: evaluations of the polynomial over the domain (length = 1 << domain.k())
pub fn all_openings_fk(
    y: &[G1Affine],
    domain: &halo2_proofs::poly::EvaluationDomain<Fr>,
    evals: &[Fr],
) -> Result<Vec<G1>, String> {
    let domain_size = 1 << domain.k();
    let d = domain_size - 1;

    let domain2 = EvaluationDomain::new(1, domain.k() + 1);
    let domain2_size = 1 << domain2.k();

    assert_eq!(
        evals.len(),
        domain_size,
        "Error: evals length ({}) != domain size ({})",
        evals.len(),
        domain_size
    );

    assert_eq!(
        y.len(),
        domain2_size,
        "Error: precomputed y length ({}) != domain2 size ({})",
        y.len(),
        domain2_size
    );

    // Step 1: Convert evals to coefficients
    let coeff_poly = domain.lagrange_to_coeff(Polynomial {
        values: evals.to_vec(),
        _marker: PhantomData,
    });
    let coeffs = coeff_poly.values;

    assert_eq!(coeffs.len(), d + 1, "coeffs should be of length d+1");

    // Step 2: Construct hat_c
    let mut hat_c = vec![Fr::zero(); 2 * d + 2];
    hat_c[0] = coeffs[d]; // c_d
    hat_c[d + 1] = coeffs[d]; // c_d again
    hat_c[(d + 2)..(2 * d + 2)].copy_from_slice(&coeffs[..d]); // c_0..c_{d-1}
    best_fft(
        &mut hat_c,
        domain2.get_extended_omega(),
        domain2.extended_k(),
    );

    // Step 3: Component-wise multiplication u = y * hat_c
    let mut u: Vec<G1> = y
        .iter()
        .zip(hat_c.iter())
        .map(|(y_elem, v_elem)| *y_elem * v_elem)
        .collect();

    // Step 4: Inverse FFT and scaling
    best_fft(
        &mut u,
        domain2.get_extended_omega_inv(),
        domain2.extended_k(),
    );
    u.iter_mut()
        .for_each(|x| *x *= domain2.get_extended_ifft_divisor());

    // Step 5: Normalize and truncate to domain size
    let domain_size = 1 << domain.k();
    let d = domain_size - 1;

    let mut h = vec![G1::identity(); domain_size];
    for i in 0..d {
        h[i] = u[i];
    }
    h[d] = G1::identity(); // zero for the x^d coeff

    best_fft(&mut h, domain.get_omega(), domain.k());

    let mut out_affine = vec![G1Affine::identity(); domain_size];
    G1::batch_normalize(&h, &mut out_affine);
    Ok(out_affine.iter().map(|p| G1::from(*p)).collect())
}

/// Compare FK20 openings with direct KZG openings
pub fn compare_fk_vs_kzg(halo2params: &Halo2Params, elems: &[Fr]) -> Result<(), String> {
    let domain = &halo2params.domain;
    let domain_size = 1 << domain.k();

    // Padding
    let mut padded = elems.to_vec();
    if padded.len() < domain_size {
        padded.resize(domain_size, Fr::zero());
    }

    // Compute FK openings
    let fk_openings = all_openings_fk(&halo2params.precomputed_y, domain, &padded)?;

    let omega = domain.get_omega();

    // Compare with direct KZG openings
    for i in 0..domain_size {
        let z_i = domain.get_omega().pow_vartime([i as u64]);

        let kzg = kzg_open(z_i, halo2params.clone(), elems.to_vec());
        let fk = fk_openings[i];

        let z = omega.pow_vartime([i as u64]);

        println!("z^{} = {:?}", i, z);
        println!("KZG = {:?}", kzg);
        println!("FK  = {:?}", fk);

        let kzg_affine = G1Affine::from(kzg);
        let fk_affine = G1Affine::from(fk);

        if kzg_affine != fk_affine {
            println!(
                "Mismatch at i = {}: \n  kzg = {:?}\n  fk  = {:?}",
                i, kzg_affine, fk_affine
            );
            return Err(format!("Mismatch at i = {}", i));
        }
    }

    println!("✅ FK and KZG openings match at all points.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Halo2Params;
    use halo2_proofs::poly::kzg::commitment::ParamsKZG;
    use halo2curves::bn256::{Bn256, Fr};

    #[test]
    fn test_fk_openings_match_kzg_openings() {
        let k = 4; // domain size 2^k = 16
        let size = 1 << k;
        let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
        let domain = EvaluationDomain::new(1, k);
        let powers = &params.g[..size];
        let precomputed_y = precompute_y(powers.as_ref(), &domain);

        let elems = vec![Fr::from(0), Fr::from(1), Fr::from(0), Fr::from(1)];

        let halo2params = Halo2Params {
            k: k as usize,
            params,
            domain,
            precomputed_y,
        };

        compare_fk_vs_kzg(&halo2params, &elems).unwrap();
    }
}
