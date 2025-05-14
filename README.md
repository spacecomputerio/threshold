# SpaceComputer | Threshold 

![Build & Test](https://github.com/spacecomputerio/threshold/actions/workflows/main.yml/badge.svg?branch=main)

This crate includes threshold crypto for the SpaceComputer ecosystem.

It uses [github.com/poanetwork/threshold_crypto](https://github.com/poanetwork/threshold_crypto) as a base implementation and adds some additional functionality for managing keys and threshold committees.

## Usage

See the [docs](https://docs.rs/threshold) for more information on how to use this crate.

## Examples 

A basic committee decryption:

```rust
let n = 7;
let t = 5;
let mut committee = Committee::new(n, t);
let decryptor = Decryptor::new(committee.pk_set.clone());

let pk = committee.pk_set.public_key();
let ciphertext = pk.encrypt(b"test-message");
for i in 0..t + 1 {
    let actor = committee.get_actor(i);
    let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
    decryptor.add_share(i, dec_share);
}
let decrypted = decryptor.decrypt(ciphertext).unwrap();
assert_eq!(decrypted, b"test-message")
```

See the tests in the project for more examples.

## License

This project is licensed under the terms of the MIT License. See the [LICENSE](LICENSE) file for details.
