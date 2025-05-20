# SpaceComputer | Threshold CLI

This crate includes a command line interface for generating keys and managing threshold committees.
It is a wrapper around the [threshold](../threshold/README.md) crate and provides a flexible and easy-to-use interface.

## Usage

Build the CLI:

```bash
cargo build --release --bin cli
```

### Generate actor config

Each actor in a threshold committee has a unique configuration file that includes the actor's secret/public keys that will be used to encrypt/decrypt the secret shares when they are distributed

```bash
./target/release/cli actor
```


### Generate committee config

The committee config includes the public keys of all actors in the committee and is used to encrypt/decrypt the secret shares when they are distributed.

```bash
./target/release/cli committee
```

### All

Enables to run an entire flow.

```bash
./target/release/cli all
```