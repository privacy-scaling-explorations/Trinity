# KZG Witness Encryption

This is the implementation artifacts for the paper:

[Extractable Witness Encryption for KZG Commitments and Efficient Laconic OT](https://eprint.iacr.org/2024/264)

**Abstract:**
We present a concretely efficient and simple extractable witness encryption scheme for KZG polynomial commitments.
It allows to encrypt a message towards a triple $(\mathsf{com}, \alpha, \beta)$, where $\mathsf{com}$ is a KZG commitment for some polynomial $f(X)$.
Anyone with an opening for the commitment attesting $f(\alpha) = \beta$ can decrypt, but without knowledge of a valid opening the message is computationally hidden.

Our construction is simple and highly efficient. The ciphertext is only a single group element. 
Encryption and decryption both require a single pairing evaluation and a constant number of group operations.

## Laconic OT Performance

Using our witness encryption scheme for KZG we construct a simple and highly efficient laconic OT protocol
which significantly outperforms the state of the art in most important metrics.

At 128-bits of security, the digest is a constant 48 bytes and the communication is just 256 bytes.

Below are the running times on an Macbook Pro M3 Max for different operations and different database sizes:

|  Database Size  |  Hash (Time)  |  Send (Time)  |  Recv (Time)  |
|-----------------|---------------|---------------|---------------|
|     $2^{3}$     |   12.39 ms    |    2.59 ms    |   595.52 µs   |
|     $2^{4}$     |   24.58 ms    |    2.62 ms    |   594.31 µs   |
|     $2^{5}$     |   49.27 ms    |    2.63 ms    |   595.35 µs   |
|     $2^{6}$     |   98.93 ms    |    2.64 ms    |   590.88 µs   |
|     $2^{7}$     |   199.65 ms   |    2.64 ms    |   597.03 µs   |
|     $2^{8}$     |   405.10 ms   |    2.64 ms    |   597.60 µs   |
|     $2^{9}$     |   819.49 ms   |    2.64 ms    |   595.67 µs   |
|    $2^{10}$     |    1.65 s     |    2.65 ms    |   596.54 µs   |
|    $2^{11}$     |    2.90 s     |    2.64 ms    |   592.32 µs   |
|    $2^{12}$     |    5.19 s     |    2.65 ms    |   592.85 µs   |
|    $2^{13}$     |    10.08 s    |    2.65 ms    |   597.57 µs   |
|    $2^{14}$     |    20.01 s    |    2.65 ms    |   592.74 µs   |
|    $2^{15}$     |    40.76 s    |    2.65 ms    |   591.76 µs   |
|    $2^{16}$     |    1:22 m     |    2.65 ms    |   592.44 µs   |
|    $2^{17}$     |    3:48 m     |    2.65 ms    |   593.00 µs   |
|    $2^{18}$     |    6:39 m     |    2.64 ms    |   592.98 µs   |

Where:

- Hash: compute the digest of the database (containing the OT choice bits)
- Send: OT send.
- Recv: OT receive.

## Reproduction of The Results

Benchmarks can be reproduced by simply running `cargo bench`.
