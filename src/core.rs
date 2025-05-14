use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeySet,
    SecretKeyShare,
};

use thiserror::Error as ThisError;

/// Error type for the module, using `thiserror` for easy error handling.
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Invalid cipher text: {0}")]
    InvalidCiphertext(String),
    #[error("Internal error: {0}")]
    InternalError(String),
}
/// Wrapper for the ciphertext message, which is a serialized version of the ciphertext.
#[derive(Clone)]
pub struct CiphertextMsg(Ciphertext);

impl CiphertextMsg {
    pub fn new(ciphertext: Ciphertext) -> Self {
        CiphertextMsg(ciphertext)
    }

    pub fn get_ciphertext(&self) -> &Ciphertext {
        &self.0
    }
}

/// Encrypt a message using the public key.
pub fn encrypt(public_key: &PublicKey, msg: &[u8]) -> CiphertextMsg {
    let ciphertext = public_key.encrypt(msg);
    CiphertextMsg::new(ciphertext)
}

/// Decrypt a message using the secret key.
pub fn decrypt(secret_key: &SecretKey, ciphertext: &Ciphertext) -> Option<Vec<u8>> {
    secret_key.decrypt(ciphertext)
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
    pub actors: Vec<Actor>,
    pub pk_set: PublicKeySet,
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
                Actor::new(id, Some(sk_share), pk_share)
            })
            .collect();

        Committee { actors, pk_set }
    }

    pub fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors
            .get_mut(id)
            .expect("No `Actor` exists with that ID")
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
    pub sk_share: Option<SecretKeyShare>,
    pub pk_share: PublicKeyShare,
}

impl Actor {
    pub fn new(id: usize, sk_share: Option<SecretKeyShare>, pk_share: PublicKeyShare) -> Self {
        Actor {
            id,
            sk_share,
            pk_share,
        }
    }

    pub fn decrypt_share(&self, ciphertext: Ciphertext) -> Result<DecryptionShare, Error> {
        let sk_share = self
            .sk_share
            .as_ref()
            .ok_or_else(|| Error::InternalError("No secret key share available".to_string()))?;
        let dec_share = sk_share.decrypt_share_no_verify(&ciphertext);

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_keyset() {
        let sk_set = new_keyset(3);
        let pk_set = sk_set.public_keys();
        _ = pk_set.public_key();
    }

    #[test]
    fn test_decryptor() {
        let n = 7;
        let t = 5;

        let mut c = Committee::new(n, t);
        let d = Decryptor::new(c.pk_set.clone());

        let pk = c.pk_set.public_key();
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
        let d = Decryptor::new(c.pk_set.clone());

        let pk = c.pk_set.public_key();
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
}
