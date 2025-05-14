use clap::{Parser, Subcommand};
use threshold::core::{Committee, PubKey};
use threshold::serialization::ActorInfo;

use std::collections::BTreeMap;

#[derive(Parser, Debug, Clone)]
#[command(author, version = "v0.0.1", about = "cli for managing actors and commitees", long_about = None)]
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
        #[arg(short = 'o', long)]
        output_file: Option<String>,
    },
    /// Generate a threshold committee
    Committee {
        #[arg(long, default_value = ".actors.yaml")]
        actors: String,
        #[arg(short = 't', long, default_value = "3")]
        threshold: usize,
        #[arg(short = 'o', long, default_value = "committee.yaml")]
        output_file: String,
    },
    All {
        #[arg(short = 'n', long, default_value = "5")]
        num_actors: usize,
        #[arg(short = 't', long, default_value = "3")]
        threshold: usize,
        #[arg(short = 'o', long, default_value = ".data")]
        output_path: String,
    },
}

/// A simple command line interface for generating and managing threshold committees and actors.
fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();

    run_cmd(args);
}

fn run_cmd(args: Args) {
    match args.command {
        Commands::Actor { id, output_file } => {
            tracing::debug!("Generating key for actor {}", id);
            let sk = threshold::core::new_private_key();
            let actor_info = ActorInfo::new_from_sk(id, sk);
            let actor_raw = serde_yaml::to_string(&actor_info).unwrap();
            if let Some(output_file) = output_file {
                std::fs::write(&output_file, &actor_raw).expect("Failed to write to output file");
                // tracing::debug!("Key generated and saved to {}", output_file);
            } else {
                println!("{}", actor_raw);
            }
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
                "Generating threshold ({}) keyset for {} actors",
                threshold,
                actors.len(),
            );

            let actor_keys: BTreeMap<usize, PubKey> = actors
                .iter()
                .map(|actor| {
                    let apk: [u8; 48] = hex::decode(actor.get_pk()).unwrap().try_into().unwrap();
                    let pk = PubKey::new_from_bytes(apk)
                        .expect("Failed to create public key from bytes");
                    (actor.get_id(), pk)
                })
                .collect();

            let committee = Committee::new(actors.len(), threshold);

            let ser = committee.serialize(Some(actor_keys)).unwrap();
            let ser_bytes = serde_json::to_vec(&ser).unwrap();
            let as_yaml: serde_yaml::Value = serde_yaml::from_slice(&ser_bytes).unwrap();
            let ser = serde_yaml::to_string(&as_yaml).unwrap();

            std::fs::write(&output_file, &ser).expect("Failed to write to output file");

            tracing::debug!("Committee generated and saved to {}", output_file);
        }
        Commands::All {
            num_actors,
            threshold,
            output_path,
        } => {
            // ensure output_path exists
            std::fs::create_dir_all(&output_path).expect("Failed to create output directory");
            for i in 0..num_actors {
                let filename = format!("{}/actor-{}.yaml", &output_path, i);
                run_cmd(Args {
                    command: Commands::Actor {
                        id: i,
                        output_file: Some(filename),
                    },
                });
            }
            let actors: Vec<ActorInfo> = (0..num_actors)
                .map(|i| {
                    let actor_raw =
                        std::fs::read_to_string(format!("{}/actor-{}.yaml", &output_path, i))
                            .expect("Failed to read actor file");
                    serde_yaml::from_str(&actor_raw).expect("Failed to parse actor")
                })
                .collect();
            let actors_yaml_path = format!("{}/.actors.yaml", &output_path);
            std::fs::write(&actors_yaml_path, serde_yaml::to_string(&actors).unwrap())
                .expect("Failed to write actors file");

            let output_file = format!("{}/committee.yaml", output_path);
            run_cmd(Args {
                command: Commands::Committee {
                    actors: actors_yaml_path.clone(),
                    threshold,
                    output_file,
                },
            });
            // cleanup
            std::fs::remove_file(actors_yaml_path).expect("Failed to remove actors file");
        }
    }
}
