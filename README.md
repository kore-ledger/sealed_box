# sealed_box

[![Rust](https://img.shields.io/badge/Rust-v1.73.0-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-green)](https://github.com/kore-ledger/sealed_box/blob/v0.1.0/LICENSE)
![Build & Test](https://github.com/kore-ledger/sealed_box/actions/workflows/rust.yml/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/kore-ledger/sealed_box/badge.svg?branch=main)](https://coveralls.io/github/kore-ledger/sealed_box?branch=main)

`sealed_box` is a Rust a library that includes a set of functions to encrypt and decrypt data using the `sealed box` construction. The `sealed box` construction is a simple and secure way to encrypt small amounts of data using a public key. The `sealed box` construction is described in the [libsodium documentation](https://doc.libsodium.org/public-key_cryptography/sealed_boxes).

It is based on the [crypto_box](https://crates.io/crates/crypto_box) crate, a pure Rust implementation of [NaCl's crypto_box](https://nacl.cr.yp.to/box.html) primitive.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
sealed_box = "0.1.1"
```

## Example

```rust
use sealed_box::{gen_keypair, seal, open};

let receiver_sk = SecretKey::from_slice(b"0123456789abcdef0123456789abcdef")
    .unwrap();
let receiver_pk = PublicKey::from(&fsk);

let message = b"Hello World!";

let cipher = seal_box(message, 
                    receiver_pk.as_bytes(), 
                    Some(b"fedcba9876543210fedcba9876543210")).unwrap();

let message2 = unseal_box(&cipher, &receiver_sk).unwrap();

assert_eq!(message, &message2[..]);
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the license text.
