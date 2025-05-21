# SpaceComputer | Threshold 

This crate includes threshold cryptography for the SpaceComputer ecosystem.

It uses [github.com/poanetwork/threshold_crypto](https://github.com/poanetwork/threshold_crypto) as a base implementation and adds some additional functionality for managing keys and threshold committees.

## Usage

A basic committee decryption:

```rust
use threshold::core::{Committee, ShareDecryptor};

let n = 7;
let t = 5;
let mut committee = Committee::new(n, t);
let aggregator = ShareDecryptor::new(committee.pk_set.clone());

let pk = committee.pk_set.public_key();
let ciphertext = pk.encrypt(b"test-message");
for i in 0..t + 1 {
    let actor = committee.get_actor(i);
    let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
    aggregator.add_share(i, dec_share).unwrap();
}

let decrypted = aggregator.decrypt(ciphertext).unwrap();
assert_eq!(decrypted, b"test-message")
```

With `tokio-rt` feature enabled, you can use the async processing for actors:

```rust

use threshold::runner::{ActorEvent, run_actor};

// ...

let (incoming, incoming_rec): (Sender<ActorEvent>, Receiver<ActorEvent>) = tokio::sync::mpsc::channel(8);
let (outgoing, outgoing_rec): (Sender<ActorEvent>, Receiver<ActorEvent>) = tokio::sync::mpsc::channel(8);

tokio::spawn(async move {
    run_actor(actor, pk_set, incoming_rec, outgoing).await;
});
```

