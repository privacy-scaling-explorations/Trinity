# Garbled Circuits and Laconic OT

## Introduction to Garbled Circuits

**Garbled circuits** enable secure two-party computation where one party (the garbler) encrypts a circuit such that another party (the evaluator) can evaluate it without learning the garbler’s inputs or the intermediate values.

### Basic Workflow

- **Garbler**:

  - Generates encryption keys for each wire and bit value.
  - Encrypts the truth table of each gate with the corresponding keys ("garbling").
  - Shares encrypted circuit + encrypted labels for evaluator’s inputs.

- **Evaluator**:
  - Obtains one encrypted label per input bit via **Oblivious Transfer (OT)**.
  - Uses these to traverse the circuit gate-by-gate.
  - Retrieves garbler's output via decoding bits.

## Integrating Laconic OT

### How Trinity Uses Laconic OT in Garbled Circuits

Instead of executing one classical OT per bit of evaluator input, Trinity uses Laconic OT to compress all OT interactions into a two-message digest commitment. This minimizes round complexity and bandwidth.

### Integration Flow

1. **Evaluator Side**

   - Converts each bit of input into a `TrinityChoice` (Zero or One).
   - Generates an OT receiver and a commitment using:
     ```rust
     let ot_receiver = trinity.create_ot_receiver(&evaluator_bits)?;
     let receiver_commitment = ot_receiver.trinity_receiver.commitment();
     ```
   - Sends this single commitment to the garbler.

2. **Garbler Side**

   - Initializes an OT sender with the evaluator’s commitment.
   - For each evaluator input bit, computes the two wire labels (one per bit value):
     ```rust
     let key = &input_keys[key_idx];
     let zero_label = key.clone();
     let one_label = Key::from(*key.as_block() ^ delta.as_block());
     ```
   - Sends these via OT:
     ```rust
     ot_sender.trinity_sender.send(rng, i, m0, m1)
     ```
   - The result is a ciphertext (`TrinityMsg`) for each bit.

3. **Evaluator Decryption**
   - Receives the correct label without revealing the input bit:
     ```rust
     let decrypted = ot_receiver.trinity_receiver.recv(i, ciphertext);
     let mac = Mac::from(Block::new(decrypted));
     ```
   - The MAC becomes an authenticated input to the garbled circuit.

### Diagram (Evaluator ↔ Garbler)

```
Evaluator Inputs (bits)
       │
       ▼
[TrinityChoice::Zero, TrinityChoice::One, ...]
       │
       ▼
KZGOTReceiver::commit() ──▶ Commitment ─────────┐
                                              │
                                   ┌──────────┴────────────┐
                                   ▼                       ▼
                Garbler generates wire labels      Garbler runs OT:
                   zero_label, one_label           ot_sender.send(i, m0, m1)
                                   │                       │
                                   └────── Ciphertexts  ◀──┘
                                                           ▼
                                               Evaluator runs OT recv()
                                                    and gets correct MAC
```

## Summary

By directly embedding Laconic OT into the garbling pipeline, Trinity avoids per-bit communication, reducing both communication and computational overhead. Each evaluator input bit is matched with the correct wire label through a single global commitment, preserving circuit privacy and ensuring scalable 2PC execution.
