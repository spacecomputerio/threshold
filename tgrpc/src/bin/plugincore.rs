use std::sync::Arc;

use clap::Parser;
use tgrpc::proto::threshold::threshold_server::ThresholdServer;
use threshold::{
    core::{Committee, PublicKeySetMsg},
    runner::Runner,
    serialization::ActorInfo,
};

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short = 'p',
        long,
        env = "THRESHOLD_GRPC_PORT",
        default_value = "8000",
        help = "gRPC server port"
    )]
    rpc_port: u16,
    #[clap(
        short = 'a',
        long,
        env = "THRESHOLD_ACTOR_CFG",
        default_value = "actor.yaml",
        help = "Path to actor configuration file"
    )]
    actor_cfg: String,
    #[clap(
        short = 'c',
        long,
        env = "THRESHOLD_COMMITTEE_CFG",
        default_value = "committee.yaml",
        help = "Path to committee configuration file"
    )]
    committee_cfg: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    let args = Args::parse();

    tracing::info!("Starting Threshold gRPC server with args: {:?}", args);

    let actor_cfg = std::path::PathBuf::from(&args.actor_cfg);
    if !actor_cfg.exists() {
        panic!(
            "Actor configuration file does not exist: {}",
            args.actor_cfg
        );
    }
    let actor_info: ActorInfo = serde_yaml::from_str(
        &std::fs::read_to_string(&actor_cfg).expect("Failed to read actor configuration file"),
    )
    .unwrap();
    let actor_sk = actor_info
        .get_sk_raw()
        .expect("Actor configuration file does not contain a valid private key");

    let committee_cfg = std::path::PathBuf::from(&args.committee_cfg);
    if !committee_cfg.exists() {
        panic!(
            "Committee configuration file does not exist: {}",
            args.committee_cfg
        );
    }
    let committee_cfg_raw =
        std::fs::read(&committee_cfg).expect("Failed to read committee configuration file");
    // WORKAROUND: convert to json bytes as deserialize_with_actor is using serde_json
    let committee_cfg_parsed: serde_yaml::Value = serde_yaml::from_slice(&committee_cfg_raw)
        .expect("Failed to parse committee configuration");
    let committee_cfg_parsed = serde_json::to_vec(&committee_cfg_parsed)
        .expect("Failed to convert committee configuration to JSON bytes");
    let (pk_set, actor) = Committee::deserialize_with_actor(committee_cfg_parsed, Some(actor_sk))
        .expect("Failed to deserialize committee configuration");

    tracing::info!("Initialized actor {}", actor.id);

    let runner = Arc::new(Runner::new(actor, PublicKeySetMsg::new(pk_set)));

    let service = tgrpc::service::ThresholdService::new_with_runner(runner);

    let addr = format!("[::1]:{}", args.rpc_port)
        .parse()
        .expect("Failed to parse rpc address");

    tracing::info!("gRPC server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(ThresholdServer::new(service))
        .serve(addr)
        .await
        .expect("Failed to start ThresholdServer");
    Ok(())
}
