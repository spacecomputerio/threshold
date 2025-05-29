use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use crate::core::{Actor, CiphertextMsg, DecryptionShareMsg, Decryptors, Error, PublicKeySetMsg};

pub struct Runner {
    actor: Arc<Actor>,
    decryptors: Arc<Decryptors>,
    ciphertexts: Arc<RwLock<BTreeMap<usize, CiphertextMsg>>>,
}

impl Runner {
    pub fn new(actor: Actor, pk_set_msg: PublicKeySetMsg) -> Self {
        let actor = Arc::new(actor);
        let decryptors = Arc::new(Decryptors::new(pk_set_msg.get_public_key_set().clone()));
        let ciphertexts = Arc::new(RwLock::new(BTreeMap::new()));
        Runner {
            actor,
            decryptors,
            ciphertexts,
        }
    }

    /// Get the actor associated with this runner.
    pub fn get_actor(&self) -> Arc<Actor> {
        self.actor.clone()
    }

    /// Prune the ciphertexts and decryptors up to the given sequence number.
    pub fn prune(&self, seq: usize) -> Result<(), Error> {
        let mut ciphertexts = self
            .ciphertexts
            .write()
            .map_err(|_| Error::InternalError("Failed to lock ciphertexts".to_string()))?;
        ciphertexts.retain(|&k, _| k > seq);
        drop(ciphertexts); // Explicitly drop the lock before proceeding

        let decryptors = self.decryptors.clone();
        decryptors.prune(seq)?;

        Ok(())
    }

    pub fn handle_ciphertext(
        &self,
        seq: usize,
        ciphertext: CiphertextMsg,
    ) -> Result<(DecryptionShareMsg, Option<Vec<u8>>), Error> {
        let mut ciphertexts = self
            .ciphertexts
            .write()
            .map_err(|_| Error::InternalError("Failed to lock ciphertexts".to_string()))?;
        ciphertexts.entry(seq).or_insert_with(|| ciphertext.clone());
        drop(ciphertexts); // Explicitly drop the lock before proceeding

        let actor = self.actor.clone();

        let dec_share = actor.decrypt_share(ciphertext.get_ciphertext().clone())?;
        let decryptors = self.decryptors.clone();
        let decryptor = decryptors.get(seq);
        let decryptor = decryptor.unwrap_or(decryptors.new_decryptor(seq));
        let has_quorum = decryptor.add_share(actor.id, dec_share.clone())?;
        let dec_share = DecryptionShareMsg::new(dec_share);
        let decryption = if has_quorum {
            Some(decryptor.decrypt(ciphertext.get_ciphertext().clone())?)
        } else {
            None // Return empty decryption if no quorum
        };
        Ok((dec_share, decryption))
    }

    pub fn handle_decryption_share(
        &self,
        seq: usize,
        actor_id: usize,
        dec_share: DecryptionShareMsg,
    ) -> Result<Option<Vec<u8>>, Error> {
        let decryptors = self.decryptors.clone();
        if !decryptors.has(seq) {
            decryptors.new_decryptor(seq);
        }
        let decryptor = match decryptors.get(seq) {
            Some(d) => d,
            None => return Err(Error::KeyNotFound),
        };

        let has_quorum = decryptor.add_share(actor_id, dec_share.get_decryption_share().clone())?;
        if has_quorum {
            let ciphertext = {
                let ciphertexts = self
                    .ciphertexts
                    .read()
                    .map_err(|_| Error::InternalError("Failed to lock ciphertexts".to_string()))?;
                match ciphertexts.get(&seq) {
                    Some(c) => c.get_ciphertext().clone(),
                    None => {
                        return Ok(None);
                    }
                }
            };
            let decryption = decryptor.decrypt(ciphertext)?;
            Ok(Some(decryption))
        } else {
            Ok(None) // Return empty decryption if no quorum
        }
    }
}
