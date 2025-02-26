use std::sync::Arc;

// use mpz_circuits::Circuit;
use mpz_circuits::{
    types::{StaticValueType, ValueType},
    Circuit,
};
use mpz_common::executor::test_st_executor;
use mpz_ot::ideal::ot::ideal_ot;

use mpz_garble::{config::Visibility, Evaluator, Generator, GeneratorConfigBuilder, ValueMemory};

#[derive(Debug)]
struct JobMatchingTestCase {
    party_a_bits: [u8; 30],
    party_b_bits: [u8; 30],
    expected_result: bool,
}

pub fn init() {
    todo!()
}

pub fn garble() {
    todo!()
}

pub fn evaluate() {
    todo!()
}

async fn run_job_matching_test(test_case: JobMatchingTestCase) {
    let circ = Circuit::parse(
        "circuits/job_matching.txt",
        &[
            ValueType::Array(Box::new(ValueType::U8), 30),
            ValueType::Array(Box::new(ValueType::U8), 30),
        ],
        &[ValueType::Array(Box::new(ValueType::Bit), 1)],
    )
    .unwrap()
    .reverse_inputs()
    .reverse_input(0)
    .reverse_input(1)
    .reverse_output(0);

    let arc_circ = Arc::new(circ);

    let (mut ctx_a, mut ctx_b) = test_st_executor(8);
    let (mut ot_send, mut ot_recv) = ideal_ot();

    let gen = Generator::new(
        GeneratorConfigBuilder::default().build().unwrap(),
        [0u8; 32],
    );
    let ev = Evaluator::default();

    let msg_a: [u8; 30] = test_case.party_a_bits;
    let msg_b: [u8; 30] = test_case.party_b_bits;

    let msg_a_typ = <[u8; 30]>::value_type();
    let msg_b_typ = <[u8; 30]>::value_type();
    let result_typ = <[bool; 1]>::value_type();

    let gen_fut = async {
        let mut memory = ValueMemory::default();

        let msg_a_ref = memory
            .new_input("msg A", msg_a_typ.clone(), Visibility::Private)
            .unwrap();
        let msg_b_ref = memory
            .new_input("msg B", msg_b_typ.clone(), Visibility::Blind)
            .unwrap();
        let ciphertext_ref = memory.new_output("result", result_typ.clone()).unwrap();

        memory.assign(&msg_a_ref, msg_a.into()).unwrap();

        gen.generate_input_encoding(&msg_a_ref, &msg_a_typ);
        gen.generate_input_encoding(&msg_b_ref, &msg_b_typ);

        gen.setup_assigned_values(
            &mut ctx_a,
            &memory.drain_assigned(&[msg_a_ref.clone(), msg_b_ref.clone()]),
            &mut ot_send,
        )
        .await
        .unwrap();

        gen.generate(
            &mut ctx_a,
            arc_circ.clone(),
            &[msg_a_ref.clone(), msg_b_ref.clone()],
            &[ciphertext_ref.clone()],
            false,
        )
        .await
        .unwrap();

        gen.get_encoding(&ciphertext_ref).unwrap()
    };

    let ev_fut = async {
        let mut memory = ValueMemory::default();

        let msg_a_ref = memory
            .new_input("msg A", msg_a_typ.clone(), Visibility::Blind)
            .unwrap();
        let msg_b_ref = memory
            .new_input("msg B", msg_b_typ.clone(), Visibility::Private)
            .unwrap();
        let ciphertext_ref = memory.new_output("result", result_typ.clone()).unwrap();

        memory.assign(&msg_b_ref, msg_b.into()).unwrap();

        ev.setup_assigned_values(
            &mut ctx_b,
            &memory.drain_assigned(&[msg_a_ref.clone(), msg_b_ref.clone()]),
            &mut ot_recv,
        )
        .await
        .unwrap();

        _ = ev
            .evaluate(
                &mut ctx_b,
                arc_circ.clone(),
                &[msg_a_ref.clone(), msg_b_ref.clone()],
                &[ciphertext_ref.clone()],
            )
            .await
            .unwrap();

        ev.get_encoding(&ciphertext_ref).unwrap()
    };

    let (ciphertext_full_encoding, ciphertext_active_encoding) = tokio::join!(gen_fut, ev_fut);

    // Uncomment and modify the verification part
    let decoding = ciphertext_full_encoding.decoding();
    let result: [bool; 1] = ciphertext_active_encoding
        .decode(&decoding)
        .unwrap()
        .try_into()
        .unwrap();

    // The expected output is true
    assert_eq!(result[0], test_case.expected_result);
}

// Assume that the following types and functions are available:
// - JobMatchingTestCase { party_a_bits: [u8; 30], party_b_bits: [u8; 30], expected_result: bool }
// - run_job_matching_test(test_case: JobMatchingTestCase) -> Future<Output = ()>

#[cfg(test)]
mod tests {
    use super::*; // Import your circuit, generator, evaluator, etc.

    // Test Case 1: Successful Match
    #[tokio::test]
    async fn test_job_matching_success() {
        let test_case = JobMatchingTestCase {
            // Party A: "1 0 1000 00000001 0001 0100 00110010"
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0,
                1, 0,
            ],
            // Party B: "00 1000 00000001 0001 0100 00101101"
            party_b_bits: [
                // Bits 0-1: Position & Commitment
                0, 0, // Bits 2-5: Education ("1000")
                1, 0, 0, 0, // Bits 6-13: Experience ("00000001")
                0, 0, 0, 0, 0, 0, 0, 1, // Bits 14-17: Interests ("0001")
                0, 0, 0, 1, // Bits 18-21: Company Stage ("0100")
                0, 1, 0, 0, // Bits 22-29: Salary ("00101101")
                0, 0, 1, 0, 1, 1, 0, 1,
            ],
            expected_result: true,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 2: Salary Mismatch
    #[tokio::test]
    async fn test_job_matching_salary_mismatch() {
        let test_case = JobMatchingTestCase {
            // Party A remains the same as in test case 1.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B with a different salary: Salary changed to "00110111"
            // Breakdown: "00" | "1000" | "00000001" | "0001" | "0100" | "00110111"
            party_b_bits: [
                0, 0, // Position & Commitment
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 0, 1, // Interests ("0001")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 1, 0, 1, 1, 1, // Salary ("00110111")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 3: Education Mismatch
    #[tokio::test]
    async fn test_job_matching_education_mismatch() {
        let test_case = JobMatchingTestCase {
            // Party A remains the same.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B: Education changed to "0100"
            // Breakdown: "00" | "0100" | "00000001" | "0001" | "0100" | "00101101"
            party_b_bits: [
                0, 0, // Position & Commitment
                0, 1, 0, 0, // Education ("0100")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 0, 1, // Interests ("0001")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 0, 1, 1, 0, 1, // Salary ("00101101")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 4: Commitment Mismatch
    #[tokio::test]
    async fn test_job_matching_commitment_mismatch() {
        let test_case = JobMatchingTestCase {
            // Party A remains the same.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B: Commitment bit changed to 1 ("01" as the first two bits)
            // Breakdown: "01" | "1000" | "00000001" | "0001" | "0100" | "00101101"
            party_b_bits: [
                0, 1, // Position & Commitment ("01")
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 0, 1, // Interests ("0001")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 0, 1, 1, 0, 1, // Salary ("00101101")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 5: Both Parties Are Candidates (Party A Position changed to 0)
    #[tokio::test]
    async fn test_job_matching_both_candidates() {
        let test_case = JobMatchingTestCase {
            // Party A: Position changed to 0 ("00" as the first two bits, keeping other fields same)
            // Breakdown: "00" | "1000" | "00000001" | "0001" | "0100" | "00110010"
            party_a_bits: [
                0, 0, // Position & Commitment ("00")
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 0, 1, // Interests ("0001")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 1, 0, 0, 1, 0, // Salary ("00110010")
            ],
            // Party B remains as in test case 1.
            party_b_bits: [
                0, 0, // Position & Commitment
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 0, 1, // Interests ("0001")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 0, 1, 1, 0, 1, // Salary ("00101101")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 6: Interest Mismatch
    #[tokio::test]
    async fn test_job_matching_interest_mismatch() {
        let test_case = JobMatchingTestCase {
            // Party A remains as in test case 1.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B: Interests changed to "0010" (instead of "0001")
            // Breakdown: "00" | "1000" | "00000001" | "0010" | "0100" | "00101101"
            party_b_bits: [
                0, 0, // Position & Commitment
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 1, 0, // Interests ("0010")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 0, 1, 1, 0, 1, // Salary ("00101101")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 7: Company Stage Mismatch
    #[tokio::test]
    async fn test_job_matching_company_stage_mismatch() {
        let test_case = JobMatchingTestCase {
            // Party A remains as in test case 1.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B: Company Stage changed to "0001" (instead of "0100")
            // Breakdown: "00" | "1000" | "00000001" | "0001" | "0001" | "00101101"
            party_b_bits: [
                0, 0, // Position & Commitment
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 0, 1, // Interests ("0001")
                0, 0, 0, 1, // Company Stage ("0001")
                0, 0, 1, 0, 1, 1, 0, 1, // Salary ("00101101")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 8: Experience Mismatch
    #[tokio::test]
    async fn test_job_matching_experience_mismatch() {
        let test_case = JobMatchingTestCase {
            // Party A remains as in test case 1.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B: Experience changed to "00010000" (instead of "00000001")
            // Breakdown: "00" | "1000" | "00010000" | "0001" | "0100" | "00101101"
            party_b_bits: [
                0, 0, // Position & Commitment
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 1, 0, 0, 0, 0, // Experience ("00010000")
                0, 0, 0, 1, // Interests ("0001")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 0, 1, 1, 0, 1, // Salary ("00101101")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 9: Multiple Criteria Fail
    #[tokio::test]
    async fn test_job_matching_multiple_failures() {
        let test_case = JobMatchingTestCase {
            // Party A remains as in test case 1.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B: Multiple changes:
            // Position: 0 -> Commitment: 1, Education: "0100", Experience: "00010000",
            // Interests: "0100", Company Stage: "0010", Salary: "01111100"
            // Breakdown: "01" | "0100" | "00010000" | "0100" | "0010" | "01111100"
            party_b_bits: [
                0, 1, // Position & Commitment ("01")
                0, 1, 0, 0, // Education ("0100")
                0, 0, 0, 1, 0, 0, 0, 0, // Experience ("00010000")
                0, 1, 0, 0, // Interests ("0100")
                0, 0, 1, 0, // Company Stage ("0010")
                0, 1, 1, 1, 1, 1, 0, 0, // Salary ("01111100")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }

    // Test Case 10: Candidate Is a Recruiter
    #[tokio::test]
    async fn test_job_matching_candidate_is_recruiter() {
        let test_case = JobMatchingTestCase {
            // Party A remains as in test case 1.
            party_a_bits: [
                1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0,
                1, 0,
            ],
            // Party B: Position changed to 1 (Recruiter)
            // Breakdown: "10" | "1000" | "00000001" | "0001" | "0100" | "00101101"
            party_b_bits: [
                1, 0, // Position & Commitment ("10")
                1, 0, 0, 0, // Education ("1000")
                0, 0, 0, 0, 0, 0, 0, 1, // Experience ("00000001")
                0, 0, 0, 1, // Interests ("0001")
                0, 1, 0, 0, // Company Stage ("0100")
                0, 0, 1, 0, 1, 1, 0, 1, // Salary ("00101101")
            ],
            expected_result: false,
        };

        run_job_matching_test(test_case).await;
    }
}
