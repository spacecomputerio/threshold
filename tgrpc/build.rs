use std::io::Result;

fn main() -> Result<()> {
    // compiling protobuf files
    tonic_build::configure()
        // .build_server(true)
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &["proto/threshold.proto"],
            &["proto"], // specify the root location to search proto dependencies
        )
        .unwrap();
    Ok(())
}
