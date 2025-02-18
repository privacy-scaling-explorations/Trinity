use halo2_middleware::multicore;
use halo2_proofs::arithmetic::Field;
use halo2curves::{
    bn256::Fq,
    ff_ext::{cubic::CubicExtField, quadratic::QuadExtField},
};

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
