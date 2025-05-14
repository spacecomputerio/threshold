use serde::{Deserialize, Serialize};

use clap::{Parser, Subcommand};
use threshold::core::{Committee, PubKey};

use std::collections::BTreeMap;

#[derive(Parser, Debug, Clone)]
#[command(author, version = "v0.0.1", about = "generator cli for managing actors and commitees", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Generate keypair for an actor
    Actor {
        #[arg(long)]
        id: usize,
    },
    /// Generate a threshold committee
    Committee {
        #[arg(long, default_value = "actors.yaml")]
        actors: String,
        #[arg(short = 't', long, default_value = "3")]
        threshold: usize,
        #[arg(short = 'o', long, default_value = "committee.yaml")]
        output_file: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ActorInfo {
    id: usize,
    pk: String,
    sk: Option<String>,
}

/// A simple command line interface for generating and managing threshold committees and actors.
fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Actor { id } => {
            tracing::debug!("Generating key for actor {}", id);
            let sk = threshold::core::new_private_key();
            let sk_bytes = threshold::serialization::sk_bytes(&sk);
            let actor_info = ActorInfo {
                id,
                pk: hex::encode(sk.public_key().to_bytes()),
                sk: Some(hex::encode(sk_bytes)),
            };
            let actor_raw = serde_yaml::to_string(&actor_info).unwrap();
            println!("{}", actor_raw);
        }
        Commands::Committee {
            actors,
            threshold,
            output_file,
        } => {
            let actors = std::fs::read_to_string(&actors).expect("Failed to read actors file");

            // Parse the actors and threshold from the command line arguments
            let actors: Vec<ActorInfo> =
                serde_yaml::from_str(&actors).expect("Failed to parse actors");

            tracing::debug!(
                "Generating threshold ({}/{}) keyset for actors: {:?}",
                threshold,
                actors.len(),
                actors
            );

            let actor_keys: BTreeMap<usize, PubKey> = actors
                .iter()
                .map(|actor| {
                    let apk: [u8; 48] = hex::decode(actor.pk.clone()).unwrap().try_into().unwrap();
                    let pk = PubKey::new_from_bytes(apk)
                        .expect("Failed to create public key from bytes");
                    (actor.id, pk)
                })
                .collect();

            let committee = Committee::new(actors.len(), threshold);

            let ser = committee.serialize(Some(actor_keys)).unwrap();
            let ser_bytes = serde_json::to_vec(&ser).unwrap();
            let as_yaml: serde_yaml::Value = serde_yaml::from_slice(&ser_bytes).unwrap();
            let ser = serde_yaml::to_string(&as_yaml).unwrap();

            std::fs::write(&output_file, &ser).expect("Failed to write to output file");

            tracing::debug!("Keyset generated and saved to {}", output_file);
        }
    }
}
