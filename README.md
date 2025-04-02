# Trinity

## Overview

Trinity is a one-round two-party computation (2PC) protocol that combines Laconic OT, garbled circuits, and PLONK to enable secure computation with zero-knowledge verified inputs. It allows mutually distrusting parties to compute securely without revealing their private inputs.

## Features

- Semi-honest garbling using the mpz garbling framework
- Supports Bristol fashion format circuits, which can be compiled using Boolify
- Unified API for both plain and Halo2 modes
- Single-round 2PC protocol with minimal interaction
- Zero-knowledge input verification using PLONK

## Architecture

Trinity is built on the following key components:

- **Garbled Circuits**: Converts circuits into a "garbled" form for 2PC using the mpz framework
- **Laconic OT (LOT)**: Enables efficient oblivious transfer with minimal communication rounds, based on Extractable Witness Encryption for KZG polynomial commitments
- **PLONK Integration**: Provides zero-knowledge proofs for input validation and commitment using Halo2
- **KZG Commitment**: Facilitates polynomial commitments within the protocol

## Usage

Trinity operates in two modes:

### Plain Mode

This mode uses standard KZG commitments without a general purpose proof, suitable for scenarios where input verification is unnecessary.  
The implementation under `/plain_lot` is mirroring the paper implementation: [research-we-kzg](https://github.com/rot256/research-we-kzg).

### Halo2 Mode

This mode integrates PSE Halo2's PLONK implementation to ensure zero-knowledge verified inputs, guaranteeing protocol compliance.  
The default circuit is located in `halo2_lot/src/circuit.rs`. Currently, it performs basic input checks (e.g., verifying if inputs are bits), but more advanced logic, such as signature verification, can be added.

## Protocol Description

1. **Setup Phase**: Generate cryptographic parameters and the circuit representation.
2. **Evaluator Commit**: The evaluator commits to its inputs using either plain or Halo2 KZG. This commitment can be reused with any Boolean circuit adhering to the input data format.
3. **Garbler Phase**: The garbler garbles the circuit, incorporates its inputs, and encrypts the evaluator's gates based on the commitments.
4. **Evaluator Phase**: The evaluator obtains encrypted input labels via Laconic OT and evaluates the circuit to compute the output.

## Building and Testing

```bash
# Build the library
cd trinity
cargo build --release

# Run tests
cargo test
```

## Acknowledgments

We would like to thank all contributors, researchers, and supporters who have helped make Trinity possible. Special thanks to Vivek and the Cursive team for originally imagining the scheme, the research team behind the Laconic OT paper and their implementation, and Nakul for his invaluable help in integrating secure garbling. Additionally, we extend our gratitude to the authors of the mpz garbling framework and the PSE Halo2 team for their foundational work and inspiration.
