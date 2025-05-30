// Include the `threshold` module, which is generated from threshold.proto.
pub mod proto {
    pub mod threshold {
        tonic::include_proto!("threshold");
    }
}

pub mod service;
