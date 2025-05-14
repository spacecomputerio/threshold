use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeySet,
    SecretKeyShare, serde_impl::SerdeSecret,
};

use crate::types::{CiphertextMsg, Error};

/// Encrypt a message using the public key.
pub fn encrypt(public_key: &PublicKey, msg: &[u8]) -> CiphertextMsg {
    let ciphertext = public_key.encrypt(msg);
    CiphertextMsg::new(ciphertext)
}

/// Decrypt a message using the secret key.
pub fn decrypt(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Option<Vec<u8>> {
    secret_key.decrypt(ciphertext)
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

/// Generate a new keyset with the given threshold
pub fn new_keyset(threshold: usize) -> SecretKeySet {
    let mut rng = rand::thread_rng();
    SecretKeySet::random(threshold, &mut rng)
}

/// Generate a new private key
pub fn new_private_key() -> SecretKey {
    SecretKey::random()
}

/// The `Committee` struct represents a group of actors (or actors) that can perform decryption
/// using a threshold secret sharing scheme.
/// The committee is created once by generating a keyset and then each actor is assigned a share of the secret key.
#[derive(Debug)]
pub struct Committee {
    actors: Vec<Actor>,
    pk_set: PublicKeySet,
}

impl Committee {
    // Creates a new `Committee`.
    // Accepts the number of actors (`n`) and the `threshold` (for decrypting a message) as parameters.
    pub fn new(n: usize, threshold: usize) -> Self {
        let sk_set = new_keyset(threshold);
        let pk_set = sk_set.public_keys();

        let actors = (0..n)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id);
                let pk_share = pk_set.public_key_share(id);
                Actor::new(id, sk_share, pk_share)
            })
            .collect();

        Committee { actors, pk_set }
    }

    pub fn public_key_set(&self) -> PublicKeySet {
        self.pk_set.clone()
    }

    pub fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors
            .get_mut(id)
            .expect("No `Actor` exists with that ID")
    }

    /// serialize into { "actors": [actor1, actor2, ...], "pk_set": pk_set }
    pub fn serialize(
        &self,
        actor_pks: Option<BTreeMap<usize, PublicKey>>,
    ) -> Result<serde_json::Value, Error> {
        let mut serialized_actors = Vec::new();
        for actor in &self.actors {
            let actor_pk = match &actor_pks {
                Some(actor_pks) => actor_pks.get(&actor.id).cloned(),
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

    pub fn deserialize_actor(
        bytes: Vec<u8>,
        actor_id: usize,
        actor_sk: Option<SecretKey>,
    ) -> Result<(PublicKeySet, Actor), Error> {
        let s: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            Error::InternalError(format!("Deserialization error (committee): {}", e))
        })?;
        let pk_set_bytes = hex::decode(s["pk_set"].as_str().unwrap())
            .map_err(|e| Error::InternalError(format!("Could not find pk_set: {}", e)))?;
        // .try_into()
        // .map_err(|_| {
        //     Error::InvalidPublicKey("Invalid pkset length: expected 48 bytes".to_string())
        // })?;
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
            .iter()
            .filter(|actor| actor["id"].as_u64().unwrap() == actor_id as u64)
            .collect::<Vec<_>>();
        if actors.is_empty() {
            return Err(Error::InternalError(format!(
                "No actor found with id {}",
                actor_id
            )));
        }
        let val = actors[0].clone();
        let actor = Actor::deserialize(val, actor_sk)?;

        Ok((pk_set, actor))
    }
}

/// The `Decryptor` struct is responsible for collecting decryption shares from committee actors
/// and performing the decryption of the ciphertext once a threshold number of shares have been collected.
#[derive(Debug)]
pub struct Decryptor {
    dec_shares: Arc<RwLock<BTreeMap<usize, DecryptionShare>>>,
    pk_set: PublicKeySet,
}

impl Decryptor {
    pub fn new(pk_set: PublicKeySet) -> Self {
        Decryptor {
            dec_shares: Arc::new(RwLock::new(BTreeMap::new())),
            pk_set,
        }
    }

    pub fn add_share(&self, id: usize, dec_share: DecryptionShare) {
        self.dec_shares.write().unwrap().insert(id, dec_share);
    }

    pub fn has_threshold(&self) -> bool {
        self._has_threshold(self.number_of_shares())
    }

    fn number_of_shares(&self) -> usize {
        self.dec_shares.read().unwrap().len()
    }

    fn _has_threshold(&self, n_shares: usize) -> bool {
        n_shares > self.pk_set.threshold()
    }

    pub fn decrypt(&self, ciphertext: Ciphertext) -> Result<Vec<u8>, Error> {
        // lock the decryption shares for adding shares
        let mut shares_lock = self.dec_shares.write().unwrap();
        let n_shares = shares_lock.len();
        if !self._has_threshold(n_shares) {
            return Err(Error::InternalError(format!(
                "Not enough decryption shares ({})",
                n_shares
            )));
        }
        // NOTE: std::mem::take replaces the BTreeMap inside the RwLock with an empty one and returns
        // the original map. This avoids cloning the data and ensures ownership is transferred
        let shares: BTreeMap<usize, DecryptionShare> = std::mem::take(&mut *shares_lock);

        let decrypted = self.pk_set.decrypt(&shares, &ciphertext).map_err(|e| {
            tracing::error!("Failed to decrypt: {}", e);
            Error::InternalError(format!("Decryption error: {}", e))
        })?;

        Ok(decrypted)
    }
}

#[derive(Clone, Debug)]
pub struct Actor {
    pub id: usize,
    pub sk_share: SecretKeyShare,
    pub pk_share: PublicKeyShare,
}

impl Actor {
    pub fn new(id: usize, sk_share: SecretKeyShare, pk_share: PublicKeyShare) -> Self {
        Actor {
            id,
            sk_share,
            pk_share,
        }
    }

    pub fn decrypt_share(&self, ciphertext: Ciphertext) -> Result<DecryptionShare, Error> {
        let dec_share = self.sk_share.decrypt_share_no_verify(&ciphertext);

        if !self
            .pk_share
            .verify_decryption_share(&dec_share, &ciphertext)
        {
            return Err(Error::InternalError(
                "Decryption share verification failed".to_string(),
            ));
        }
        Ok(dec_share)
    }

    pub fn serialize(&self, actor_pk: Option<PublicKey>) -> Result<serde_json::Value, Error> {
        let ser_sk = SerdeSecret(self.sk_share.clone());
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
        Ok(serde_json::json!({
            "id": self.id,
            "pk_share": hex::encode(self.pk_share.to_bytes()),
            "sk_share": sk_share.as_str(),
        }))
    }

    pub fn deserialize(s: serde_json::Value, actor_sk: Option<SecretKey>) -> Result<Self, Error> {
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
        let sk_share_bytes = match actor_sk {
            Some(actor_sk) => {
                let sk_share_ciphertext =
                    CiphertextMsg::try_from(s["sk_share"].as_str().unwrap().to_string())?;
                let sk_share_bytes = actor_sk.decrypt(sk_share_ciphertext.get_ciphertext());
                if sk_share_bytes.is_none() {
                    return Err(Error::InternalError(
                        "Failed to decrypt sk_share".to_string(),
                    ));
                }
                sk_share_bytes.unwrap()
            }
            None => {
                let sk_share_str = s["sk_share"].as_str().unwrap();
                hex::decode(sk_share_str).map_err(|e| {
                    tracing::error!("Failed to decode sk_share: {}", e);
                    Error::InternalError(format!("Deserialization error: {}", e))
                })?
            }
        };
        let sk_share: SerdeSecret<SecretKeyShare> = serde_json::from_slice(&sk_share_bytes)
            .map_err(|e| {
                tracing::error!("Failed to deserialize sk_share: {}", e);
                Error::InternalError(format!("Deserialization error: {}", e))
            })?;
        let pk_share = PublicKeyShare::from_bytes(pk_share_bytes).map_err(|e| {
            tracing::error!("Failed to create pk_share from bytes: {}", e);
            Error::InternalError(format!("Deserialization error: {}", e))
        })?;
        Ok(Actor {
            id,
            sk_share: sk_share.0,
            pk_share,
        })
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
    fn test_new_keyset() {
        let sk_set = new_keyset(3);
        let pk_set = sk_set.public_keys();
        let pk = pk_set.public_key();
        let pk_hex = pubkey_hex(pk.clone());
        let pubkey = pubkey_from_hex(pk_hex.as_str());
        assert!(pubkey.is_ok());
        let pubkey = pubkey.unwrap();
        assert_eq!(pubkey, pk);
    }

    #[test]
    fn test_decryptor() {
        let n = 7;
        let t = 5;

        let mut c = Committee::new(n, t);
        let d = Decryptor::new(c.public_key_set());

        let pk = c.public_key_set().public_key();
        let ciphertext = pk.encrypt(b"test-message");
        for i in 0..t + 1 {
            let actor = c.get_actor(i);
            let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
            d.add_share(i, dec_share);
        }
        let decrypted = d.decrypt(ciphertext).unwrap();
        assert_eq!(decrypted, b"test-message")
    }

    #[test]
    fn test_decryptor_without_threshold() {
        let n = 7;
        let t = 5;

        let mut c = Committee::new(n, t);
        let d = Decryptor::new(c.public_key_set());

        let pk = c.public_key_set().public_key();
        let ciphertext = pk.encrypt(b"test-message");
        for i in 0..t {
            let actor = c.get_actor(i);
            let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
            d.add_share(i, dec_share);
        }
        assert!(!d.has_threshold());
        match d.decrypt(ciphertext.clone()) {
            Err(_) => {}
            Ok(_) => {
                // fail the test
                assert!(
                    false,
                    "should be able to decrypt before threshold of decryption shares"
                )
            }
        }
        // add one more share
        let actor = c.get_actor(t);
        let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
        d.add_share(t, dec_share);
        assert!(d.has_threshold());
        let decrypted = d.decrypt(ciphertext).unwrap();
        assert_eq!(decrypted, b"test-message");
    }

    #[test]
    fn test_actor_serialization() {
        let n = 7;
        let t = 5;
        let actor_sk = new_private_key();
        let actor_pk = actor_sk.public_key();

        let mut c = Committee::new(n, t);
        let actor = c.get_actor(0);
        let serialized = actor.serialize(Some(actor_pk)).unwrap();
        let deserialized_actor = Actor::deserialize(serialized, Some(actor_sk)).unwrap();
        assert_eq!(actor.id, deserialized_actor.id);
        assert_eq!(
            actor.pk_share.to_bytes(),
            deserialized_actor.pk_share.to_bytes()
        );
        assert_eq!(actor.sk_share, deserialized_actor.sk_share);
    }

    #[test]
    fn test_committee_serialization() {
        let n = 7;
        let t = 5;
        let mut actors_sk = BTreeMap::new();
        let mut actors_pk = BTreeMap::new();
        for i in 0..n {
            let actor_sk = new_private_key();
            let actor_pk = actor_sk.public_key();
            actors_sk.insert(i, actor_sk);
            actors_pk.insert(i, actor_pk);
        }

        let mut c = Committee::new(n, t);
        let serialized = c.serialize(Some(actors_pk)).unwrap();
        let actor_id = 1;
        let sk = actors_sk.get(&actor_id).unwrap();
        // deserialize the committee as an actor
        let deserialized_committee_actor = Committee::deserialize_actor(
            serde_json::to_vec(&serialized).unwrap(),
            actor_id,
            Some(sk.to_owned()),
        )
        .unwrap();
        assert_eq!(c.pk_set, deserialized_committee_actor.0);
        let actor = c.get_actor(actor_id);
        assert_eq!(actor.sk_share, deserialized_committee_actor.1.sk_share);
        assert_eq!(
            actor.pk_share.to_bytes(),
            deserialized_committee_actor.1.pk_share.to_bytes()
        );
        assert_eq!(actor.id, deserialized_committee_actor.1.id);
    }
}
