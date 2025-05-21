use std::collections::BTreeMap;

use crate::core::{Actor, CiphertextMsg, Committee, DecryptionShareMsg, Error};

use threshold_crypto::{
    PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeyShare, serde_impl::SerdeSecret,
};

use serde::{Deserialize, Serialize};

/// ActorInfo struct to hold the actor's information
/// including the public key (pk) and secret key (sk) that are used for serialization and deserialization of the actor.
/// The secret key is optional and is only used by the actor itself (to decrypt the private key share).
/// The public key is represented as a hex string.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ActorInfo {
    pk: String,
    sk: Option<String>,
}

impl ActorInfo {
    /// Create a new ActorInfo instance
    pub fn new(pk: String, sk: Option<String>) -> Self {
        ActorInfo { pk, sk }
    }

    /// Create a new ActorInfo instance from a SecretKey
    pub fn new_from_sk(sk: SecretKey) -> Self {
        let pk = pubkey_hex(sk.public_key());
        let sk_bytes = sk_bytes(&sk);
        ActorInfo {
            pk,
            sk: Some(hex::encode(sk_bytes)),
        }
    }

    /// Returns the public key as a hex string
    pub fn get_pk(&self) -> &str {
        &self.pk
    }

    /// Returns the public key
    pub fn get_pk_raw(&self) -> Result<PublicKey, Error> {
        pubkey_from_hex(&self.pk)
    }

    /// Returns the secret key
    pub fn get_sk_raw(&self) -> Result<SecretKey, Error> {
        if let Some(sk_hex) = &self.sk {
            let sk_bytes = hex::decode(sk_hex).map_err(|e| {
                tracing::error!("Failed to decode secret key hex: {}", e);
                Error::InvalidPrivateKey("Invalid hex string".to_string())
            })?;
            sk_from_bytes(&sk_bytes)
        } else {
            Err(Error::KeyNotFound)
        }
    }
}

/// Convert a SecretKey to bytes
pub fn sk_bytes(sk: &SecretKey) -> Vec<u8> {
    serde_json::to_vec(&SerdeSecret(sk.clone())).unwrap()
}

/// Convert bytes to a SecretKey
pub fn sk_from_bytes(bytes: &[u8]) -> Result<SecretKey, Error> {
    let sk: SerdeSecret<SecretKey> = serde_json::from_slice(bytes).map_err(|e| {
        tracing::error!("Failed to deserialize secret key: {}", e);
        Error::InvalidPrivateKey("Failed to deserialize secret key".to_string())
    })?;
    Ok(sk.0)
}

/// Convert a PublicKey to a hex string
pub fn pubkey_hex(pk: PublicKey) -> String {
    let pk_bytes = pk.to_bytes();
    hex::encode(pk_bytes)
}

/// Convert a hex string to a PublicKey
pub fn pubkey_from_hex(tpk: &str) -> Result<PublicKey, Error> {
    // parse the tpk (hex string) to bytes
    let pk_bytes: [u8; 48] = hex::decode(tpk)
        .map_err(|e| {
            tracing::error!("Failed to decode pub key hex: {}", e);
            Error::InvalidPublicKey("Invalid hex string".to_string())
        })?
        .try_into()
        .map_err(|_| {
            tracing::error!("Invalid tpk length: expected 48 bytes");
            Error::InvalidPublicKey("Invalid length: expected 48 bytes".to_string())
        })?;
    PublicKey::from_bytes(pk_bytes).map_err(|e| {
        Error::InvalidPublicKey(format!("Failed to create public key from bytes: {}", e))
    })
}

impl TryFrom<String> for CiphertextMsg {
    type Error = Error;

    fn try_from(data: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(data)
            .map_err(|e| Error::InvalidCiphertext(format!("failed to decode hex: {e}")))?;
        let ciphertext = serde_json::from_slice(bytes.as_slice())
            .map_err(|e| Error::InvalidCiphertext(format!("failed to deserialize hex: {e}")))?;
        Ok(CiphertextMsg::new(ciphertext))
    }
}

impl TryFrom<CiphertextMsg> for String {
    type Error = Error;

    fn try_from(value: CiphertextMsg) -> Result<Self, Self::Error> {
        let parsed = serde_json::to_string(value.get_ciphertext())
            .map_err(|e| Error::InvalidCiphertext(format!("Serialization error: {}", e)))?;
        Ok(hex::encode(parsed))
    }
}

impl TryFrom<DecryptionShareMsg> for String {
    type Error = Error;

    fn try_from(value: DecryptionShareMsg) -> Result<Self, Self::Error> {
        let parsed = serde_json::to_string(value.get_decryption_share())
            .map_err(|e| Error::InvalidCiphertext(format!("Serialization error: {}", e)))?;
        Ok(hex::encode(parsed))
    }
}

impl TryFrom<String> for DecryptionShareMsg {
    type Error = Error;

    fn try_from(data: String) -> Result<Self, Self::Error> {
        let bytes = hex::decode(data)
            .map_err(|e| Error::InvalidCiphertext(format!("failed to decode hex: {e}")))?;
        let decryption_share = serde_json::from_slice(bytes.as_slice())
            .map_err(|e| Error::InvalidCiphertext(format!("failed to deserialize hex: {e}")))?;
        Ok(DecryptionShareMsg::new(decryption_share))
    }
}

impl Committee {
    /// Serialize the committee to a JSON value.
    /// The actor's secret key share is encrypted using the actor's public key.
    pub fn serialize(
        &self,
        actor_pks: Option<BTreeMap<usize, crate::core::PubKey>>,
    ) -> Result<serde_json::Value, Error> {
        let mut serialized_actors = Vec::new();
        for actor in &self.actors {
            let actor_pk = match &actor_pks {
                Some(actor_pks) => {
                    let actor_pk = actor_pks.get(&actor.id).cloned().unwrap();
                    let pk = actor_pk.get_public_key();
                    Some(*pk)
                }
                None => None,
            };
            serialized_actors.push(actor.serialize(actor_pk)?);
        }
        let pk_set_bytes = serde_json::to_vec(&self.pk_set).map_err(|e| {
            tracing::error!("Failed to serialize pk_set: {}", e);
            Error::InternalError(format!("Serialization error: {}", e))
        })?;
        Ok(serde_json::json!({
            "actors": serialized_actors,
            "pk_set": hex::encode(pk_set_bytes),
        }))
    }

    /// Deserialize the committee from a JSON value.
    pub fn deserialize(bytes: Vec<u8>) -> Result<Self, Error> {
        let (pk_set, actors_raw) = Self::deserialize_without_actors(bytes)?;

        let actors = actors_raw
            .iter()
            .map(|actor| {
                let (actor, _) = Actor::deserialize(actor.clone(), None)?;
                Ok(actor)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Committee { actors, pk_set })
    }

    fn deserialize_without_actors(
        bytes: Vec<u8>,
    ) -> Result<(PublicKeySet, Vec<serde_json::Value>), Error> {
        let s: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            Error::InternalError(format!("Deserialization error (committee): {}", e))
        })?;
        let pk_set_bytes = hex::decode(s["pk_set"].as_str().unwrap())
            .map_err(|e| Error::InternalError(format!("Could not find pk_set: {}", e)))?;
        let pk_set = serde_json::from_slice::<PublicKeySet>(&pk_set_bytes).map_err(|e| {
            tracing::error!("Failed to deserialize pk_set: {}", e);
            Error::InternalError(format!("Deserialization error (pk_set): {}", e))
        })?;

        let actors = s["actors"]
            .as_array()
            .ok_or_else(|| {
                tracing::error!("Failed to parse actors from committee");
                Error::InternalError("Failed to parse actors from committee".to_string())
            })?
            .to_vec();

        Ok((pk_set, actors))
    }

    /// Deserialize the committee from a JSON value
    pub fn deserialize_with_actor(
        bytes: Vec<u8>,
        actor_sk: Option<SecretKey>,
    ) -> Result<(PublicKeySet, Actor), Error> {
        let (pk_set, actors_raw) = Self::deserialize_without_actors(bytes)?;
        let actor_pk = actor_sk
            .as_ref()
            .map(|sk| sk.public_key())
            .ok_or_else(|| Error::InternalError("Failed to get actor public key".to_string()))?;

        let actors = actors_raw
            .iter()
            .filter(|actor| {
                let pk_raw = actor["pk"].as_str();
                if pk_raw.is_none() {
                    return false;
                }
                match pubkey_from_hex(pk_raw.unwrap()) {
                    Ok(pk) => pk == actor_pk,
                    Err(_) => false,
                }
            })
            .collect::<Vec<_>>();
        if actors.is_empty() {
            return Err(Error::InternalError(format!(
                "No actor found with pub key {}",
                pubkey_hex(actor_pk)
            )));
        }
        let val = actors[0].clone();
        let (actor, _) = Actor::deserialize(val, actor_sk)?;

        Ok((pk_set, actor))
    }
}

impl Actor {
    /// Serialize the actor to a JSON value
    /// The actor's secret key share is encrypted using the actor's public key
    pub fn serialize(&self, actor_pk: Option<PublicKey>) -> Result<serde_json::Value, Error> {
        let sk_share = match self.sk_share {
            Some(ref sk_share) => sk_share.clone(),
            None => {
                return Err(Error::InternalError(
                    "No secret key share available".to_string(),
                ));
            }
        };
        let ser_sk = SerdeSecret(sk_share);
        let sk_share_bytes = serde_json::to_vec(&ser_sk)
            .map_err(|e| Error::InternalError(format!("Serialization error: {}", e)))?;
        let sk_share: String = match actor_pk {
            Some(actor_pk) => CiphertextMsg::new(actor_pk.encrypt(sk_share_bytes))
                .try_into()
                .map_err(|e| {
                    tracing::error!("Failed to serialize encrypted sk_share: {}", e);
                    Error::InternalError("Failed to serialize encrypted sk_share".to_string())
                })?,
            None => hex::encode(sk_share_bytes),
        };
        match actor_pk {
            Some(actor_pk) => Ok(serde_json::json!({
                "id": self.id,
                "pk_share": hex::encode(self.pk_share.to_bytes()),
                "sk_share": sk_share.as_str(),
                "pk": pubkey_hex(actor_pk),
            })),
            None => Ok(serde_json::json!({
                "id": self.id,
                "pk_share": hex::encode(self.pk_share.to_bytes()),
                "sk_share": sk_share.as_str(),
            })),
        }
    }

    /// Deserialize an actor from a JSON value
    /// The actor's secret key share is decrypted using the actor's secret key
    pub fn deserialize(
        s: serde_json::Value,
        actor_sk: Option<SecretKey>,
    ) -> Result<(Self, Option<PublicKey>), Error> {
        let id = s["id"]
            .as_u64()
            .ok_or_else(|| Error::InternalError("Failed to parse id from actor".to_string()))?
            as usize;
        let pk_share_bytes: [u8; 48] = hex::decode(s["pk_share"].as_str().unwrap())
            .map_err(|e| {
                tracing::error!("Failed to decode pk_share: {}", e);
                Error::InternalError(format!("Deserialization error: {}", e))
            })?
            .try_into()
            .map_err(|_| {
                tracing::error!("Invalid pk_share length: expected 48 bytes");
                Error::InternalError("Invalid length: expected 48 bytes".to_string())
            })?;
        let sk_share = match actor_sk {
            Some(actor_sk) => {
                let sk_share_ciphertext =
                    CiphertextMsg::try_from(s["sk_share"].as_str().unwrap().to_string())?;
                let sk_share_bytes = actor_sk.decrypt(sk_share_ciphertext.get_ciphertext());
                if sk_share_bytes.is_none() {
                    return Err(Error::InternalError(
                        "Failed to decrypt sk_share".to_string(),
                    ));
                }
                let sk_share_bytes = sk_share_bytes.unwrap();
                let sk_share: SerdeSecret<SecretKeyShare> = serde_json::from_slice(&sk_share_bytes)
                    .map_err(|e| {
                        tracing::error!("Failed to deserialize sk_share: {}", e);
                        Error::InternalError(format!("Deserialization error: {}", e))
                    })?;
                Some(sk_share.0)
            }
            None => None,
        };
        let pk_share = PublicKeyShare::from_bytes(pk_share_bytes).map_err(|e| {
            tracing::error!("Failed to create pk_share from bytes: {}", e);
            Error::InternalError(format!("Deserialization error: {}", e))
        })?;
        let pk = match s["pk"].as_str() {
            Some(pk_hex) => Some(pubkey_from_hex(pk_hex)?),
            None => None,
        };
        Ok((
            Actor {
                id,
                sk_share,
                pk_share,
            },
            pk,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_from_str() {
        let tpk = "af9a704172ede842954680f74ba68faeaf66d2538336414f73fb5517ab7c913a66419b9dc179f63a5d68e5a9f2051fc5";
        let pubkey = pubkey_from_hex(tpk);
        assert!(pubkey.is_ok());
    }

    #[test]
    fn test_actor_serialization() {
        let n = 7;
        let t = 5;
        let actor_sk = crate::core::new_private_key();
        let actor_pk = actor_sk.public_key();

        let mut c = Committee::new(n, t);
        let actor = c.get_actor(0);
        let serialized = actor.serialize(Some(actor_pk)).unwrap();
        let (deserialized_actor, pk) = Actor::deserialize(serialized, Some(actor_sk)).unwrap();
        assert_eq!(actor.id, deserialized_actor.id);
        assert_eq!(
            actor.pk_share.to_bytes(),
            deserialized_actor.pk_share.to_bytes()
        );
        assert_eq!(actor.sk_share, deserialized_actor.sk_share);
        assert!(pk.is_some());
        assert_eq!(actor_pk.to_bytes(), pk.unwrap().to_bytes());
    }

    #[test]
    fn test_committee_serialization() {
        let n = 7;
        let t = 5;
        let mut actors_sk = BTreeMap::new();
        let mut actors_pk = BTreeMap::new();
        for i in 0..n {
            let actor_sk = crate::core::new_private_key();
            let actor_pk = actor_sk.public_key();
            actors_sk.insert(i, actor_sk);
            actors_pk.insert(i, crate::core::PubKey::new(actor_pk));
        }

        let mut c = Committee::new(n, t);
        let serialized = c.serialize(Some(actors_pk)).unwrap();
        let serialized_bytes = serde_json::to_vec(&serialized).unwrap();

        let deserialized_committee = Committee::deserialize(serialized_bytes).unwrap();

        let actor_id = 1;
        let sk = actors_sk.get(&actor_id).unwrap();
        // deserialize the committee as an actor
        let deserialized_committee_actor = Committee::deserialize_with_actor(
            serde_json::to_vec(&serialized).unwrap(),
            Some(sk.to_owned()),
        )
        .unwrap();
        assert_eq!(c.pk_set, deserialized_committee_actor.0);
        assert_eq!(
            deserialized_committee.pk_set,
            deserialized_committee_actor.0
        );
        let actor = c.get_actor(actor_id);
        assert_eq!(actor.sk_share, deserialized_committee_actor.1.sk_share);
        assert_eq!(
            actor.pk_share.to_bytes(),
            deserialized_committee_actor.1.pk_share.to_bytes()
        );
        assert_eq!(actor.id, deserialized_committee_actor.1.id);
    }
}
