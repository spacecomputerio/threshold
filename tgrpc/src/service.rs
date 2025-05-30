use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::proto::threshold::threshold_server::Threshold;
use crate::proto::threshold::{
    CiphertextRequest, CiphertextResponse, DecryptionShareRequest, DecryptionShareResponse,
};
use threshold::{
    core::{Actor, CiphertextMsg, DecryptionShareMsg, PublicKeySetMsg},
    runner::Runner,
};

pub struct ThresholdService {
    runner: Arc<Runner>,
}

impl ThresholdService {
    pub fn new(actor: Actor, pk_set_msg: PublicKeySetMsg) -> Self {
        let runner = Arc::new(Runner::new(actor, pk_set_msg));
        Self::new_with_runner(runner)
    }

    pub fn new_with_runner(runner: Arc<Runner>) -> Self {
        ThresholdService { runner }
    }
}

#[tonic::async_trait]
impl Threshold for ThresholdService {
    async fn add_ciphertext(
        &self,
        request: Request<CiphertextRequest>,
    ) -> Result<Response<CiphertextResponse>, Status> {
        let request = request.into_inner();
        let seq = request.seq;
        tracing::debug!("Received add_ciphertext request {}", seq);
        let ciphertext = CiphertextMsg::try_from(request.value)
            .map_err(|e| Status::invalid_argument(format!("Invalid ciphertext: {}", e)))?;
        let runner = self.runner.clone();
        let (dec_share, decryption) = runner
            .handle_ciphertext(seq as usize, ciphertext)
            .map_err(|e| Status::internal(format!("Error handling ciphertext: {}", e)))?;
        tracing::debug!("Decrypted share {}", seq);
        let reply = CiphertextResponse {
            actor_id: self.runner.get_actor().id as u32,
            seq, // Echo back the sequence number
            decryption_share: dec_share.try_into().map_err(|e| {
                Status::internal(format!("Error converting decryption share: {}", e))
            })?,
            decryption,
        };
        Ok(Response::new(reply))
    }

    async fn add_decryption_share(
        &self,
        request: Request<DecryptionShareRequest>,
    ) -> Result<Response<DecryptionShareResponse>, Status> {
        let request = request.into_inner();
        let seq = request.seq;
        let actor_id = request.actor_id as usize;
        tracing::debug!(
            "Received add_decryption_share request {} from actor {}",
            seq,
            actor_id
        );
        let dec_share = DecryptionShareMsg::try_from(request.value)
            .map_err(|e| Status::invalid_argument(format!("Invalid decryption share: {}", e)))?;
        let runner = self.runner.clone();
        let decryption = runner
            .handle_decryption_share(seq as usize, actor_id, dec_share)
            .map_err(|e| Status::internal(format!("Error handling decryption share: {}", e)))?;
        tracing::debug!(
            "Decryption share from actor {} processed for seq {}",
            actor_id,
            seq
        );
        let reply = DecryptionShareResponse { seq, decryption };
        Ok(Response::new(reply))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use threshold::core::Committee;

    #[tokio::test]
    async fn test_threshold_service() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(false)
            .init();

        let n = 4;
        let t = 3;
        let mut committee = Committee::new(n, t);
        let pk_set = committee.pk_set.clone();
        let actor = committee.get_actor(0);

        let service = ThresholdService::new(actor.clone(), PublicKeySetMsg::new(pk_set.clone()));
        let plaintext = b"Hello, world!";
        let encrypted = committee.pk_set.clone().public_key().encrypt(plaintext);

        let request = CiphertextRequest {
            seq: 1,
            value: CiphertextMsg::new(encrypted.clone())
                .try_into()
                .expect("Failed to convert ciphertext"),
        };
        let response = service
            .add_ciphertext(Request::new(request))
            .await
            .expect("Failed to add ciphertext");
        assert_eq!(response.into_inner().seq, 1);

        for i in 1..n {
            let actor = committee.get_actor(i);
            let iservice =
                ThresholdService::new(actor.clone(), PublicKeySetMsg::new(pk_set.clone()));
            let request = CiphertextRequest {
                seq: 1,
                value: CiphertextMsg::new(encrypted.clone())
                    .try_into()
                    .expect("Failed to convert ciphertext"),
            };
            let res = iservice
                .add_ciphertext(Request::new(request))
                .await
                .expect("Failed to add ciphertext");
            let res = res.into_inner();
            assert_eq!(res.actor_id, i as u32);
            assert_eq!(res.seq, 1);
            let dec_share_req = DecryptionShareRequest {
                seq: res.seq,
                actor_id: actor.id as u32,
                value: res.decryption_share,
            };
            let add_share_res = service
                .add_decryption_share(Request::new(dec_share_req))
                .await
                .expect("Failed to add decryption share");
            let add_share_res = add_share_res.into_inner();
            assert_eq!(add_share_res.seq, 1);
            if add_share_res.decryption.is_some() {
                tracing::debug!("Manage to decrypt message");
                assert_eq!(add_share_res.decryption.unwrap(), plaintext.to_vec());
                return; // We expect to get a decryption share from at least one actor
            }
        }
        panic!("No decryption done");
    }
}
