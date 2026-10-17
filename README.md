kopis-smallcode
===============

This crate is a pure-Rust, no-std implementation of the [Kopis](https://eprint.iacr.org/2026/2268) key encapsulation mechanism (KEM). Kopis is a lattice-based KEM that is designed to be secure against classical and quantum adversaries. Kopis has three security levels: Kopis-512, Kopis-768, and Kopis-1024. If you don't know what to use, just use Kopis-768.

This crate differs from [kopis-rs](https://github.com/rozbb/kopis-rs) in three ways:
1. I, a human, wrote nearly every line of this crate, and the ones I did not (really just the Karatsuba multiplication), I scrutinized carefully
1. The code footprint of this crate is much smaller than `kopis-rs`
1. This crate is significantly slower than `kopis-rs`, and also slower than any ML-KEM crate
1. This crate is not formally verified with Lean, while `kopis-rs` is

Warning
-------

This crate has not been audited in any sense of the word. Use at your own risk.

Example code
------------

The following code can be found in [`examples/simple.rs`](examples/simple.rs).

```rust
use kopis_smallcode::{
    kopis512::{Kopis512Ciphertext, Kopis512PublicKey, Kopis512SecretKey, KOPIS512_CIPHERTEXT_LEN},
    SharedSecret
};

let mut rng = rand::rng();

// Generate a keypair
let sk = Kopis512SecretKey::generate(&mut rng);
let pk = sk.public_key();

// Serialize the secret key, maybe to save on disk
let sk_seed: [u8; 32] = sk.seed();

// Deserialize the secret key
let sk = Kopis512SecretKey::expand_from_seed(&sk_seed);

// Also serialize and deserialize the public key
let mut pk_bytes = [0u8; Kopis512PublicKey::SERIALIZED_LEN];
pk.serialize(&mut pk_bytes);
let slice_containing_pk = pk_bytes.as_slice();
assert_eq!(
    slice_containing_pk.len(),
    Kopis512PublicKey::SERIALIZED_LEN
);
let pk_arr = slice_containing_pk.try_into().unwrap();
// The API only accepts fixed-len slices, so we have to cast it first
let pk = Kopis512PublicKey::from_bytes(pk_arr);

// Encapsulate a shared secret, ss1, to pk
let (ct, ss1): (Kopis512Ciphertext, SharedSecret) = pk.encapsulate(&mut rng);
// Note ct is just a [u8; KOPIS512_CIPHERTEXT_LEN]

// Deserializing is also straightforward
let slice_containing_ct = ct.as_slice();
let receiver_ct: &Kopis512Ciphertext = slice_containing_ct.try_into().unwrap();

// Use the secret key to decapsulate the ciphertext
let ss2 = sk.decapsulate(receiver_ct);

// Check the shared secrets are equal. NOTE is not a constant-time check (ie not secure). We
// only do this for testing purposes.
assert_eq!(ss1.as_bytes(), ss2.as_bytes());

println!("KEM ran successfully");
```

Benchmarks
----------

We have implemented benchmarks for key generation, encapsulation, and decapsulation for all variants. Simply run `cargo bench`.

License
-------

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
