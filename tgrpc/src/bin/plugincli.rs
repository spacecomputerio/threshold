use clap::{Parser, Subcommand};
use tgrpc::proto::threshold::CiphertextRequest;
use tgrpc::proto::threshold::threshold_client::ThresholdClient;
use threshold::core::CiphertextMsg;

#[derive(Parser, Debug, Clone)]
#[command(author, version = "v0.0.1", about = "cli for managing actors and commitees", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Encrypt {
        #[arg(short = 'm', long)]
        message: String,
        #[arg(short = 'p', long)]
        pk: String,
    },
    Decrypt {
        #[arg(short = 'c', long)]
        ciphertext: String,
        #[arg(short = 's', long, default_value = "0")]
        seq: usize,
        #[arg(long)]
        grpc_addr: String,
    },
}
/// A simple command line interface for generating and managing threshold committees and actors.
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .without_time()
        .init();

    let args = Args::parse();

    run_cmd(args).await;
}

async fn run_cmd(args: Args) {
    match args.command {
        Commands::Encrypt { message, pk } => {
            tracing::debug!("Encrypting message '{}' with public key '{}'", message, pk);
            let pk = threshold::serialization::pubkey_from_hex(&pk)
                .expect("Failed to parse public key from hex");
            let ciphertext = pk.encrypt(message.as_bytes());
            let ciphertext = CiphertextMsg::new(ciphertext);
            println!(
                "{}",
                String::try_from(ciphertext).expect("Failed to convert ciphertext to string")
            );
        }
        Commands::Decrypt {
            ciphertext,
            seq,
            grpc_addr,
        } => {
            tracing::debug!(
                "Decrypting ciphertext '{}' using gRPC at '{}'",
                ciphertext,
                grpc_addr
            );
            let ciphertext: CiphertextMsg = ciphertext
                .try_into()
                .expect("Failed to convert string to CiphertextMsg");
            let mut client = ThresholdClient::connect(grpc_addr).await.unwrap();
            let res = client
                .add_ciphertext(CiphertextRequest {
                    seq: seq as u32,
                    value: ciphertext
                        .try_into()
                        .expect("Failed to convert CiphertextMsg to string"),
                })
                .await
                .expect("Failed to send ciphertext");

            let res = res.into_inner();
            tracing::debug!("Received response: {:?}", res);
            if let Some(decryption) = res.decryption {
                println!(
                    "Decrypted message: {}",
                    String::from_utf8(decryption).expect("Failed to convert bytes to string")
                );
            } else {
                println!("No decryption available yet.");
            }
        }
    }
}
