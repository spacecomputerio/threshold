use std::{collections::BTreeMap, sync::Arc, thread};

use crate::core::{Actor, CiphertextMsg, DecryptionShareMsg, ShareDecryptor};

use tokio::{
    select,
    sync::{RwLock, mpsc::{Receiver, Sender}},
};

#[derive(Clone)]
/// ActorEvent is an enum that represents the events that can occur in the actor loop.
pub enum ActorEvent {
    /// NewCiphertext is sent when a new ciphertext is received from the network.
    /// The ciphertext should be decrypted and the decryption share should be sent to the network.
    NewCiphertext(usize, CiphertextMsg),
    /// NewDecryptionShare is sent when a new decryption share is received from the network
    /// or sent to the network.
    NewDecryptionShare(usize, usize, DecryptionShareMsg),
    /// NewDecryption is sent when a new decryption can be performed, i.e. when a quorum of shares
    /// has been received.
    NewDecryption(usize, Vec<u8>),
}

pub async fn start_actor_loop(
    actor: Actor,
    decryptor: ShareDecryptor,
    mut incoming: Receiver<ActorEvent>,
    outgoing: Sender<ActorEvent>,
) {
    tracing::debug!("Starting actor {}", actor.id);
    let self_actor_id = actor.id;
    let decryptors = Arc::new(RwLock::new(BTreeMap::new()));
    let mut ciphertexts = BTreeMap::new();
    let mut done = BTreeMap::new();
    
    // start a new thread to handle (share) decrypting ciphertexts as it is a blocking operation
    let (share_decrypt_sink, mut share_decrypt_rec) = tokio::sync::mpsc::channel(8);
    let (ciphertext_src, ciphertext_rec) = tokio::sync::mpsc::channel(8);
    thread::spawn(move || {
        share_decryption_loop(
            actor,
            ciphertext_rec,
            share_decrypt_sink,
        );
    });

    // start a new thread to handle decrypting ciphertexts as it is a blocking operation
    let (decrypt_sink, mut decrypt_rec) = tokio::sync::mpsc::channel(8);
    let (full_ciphertext_src, full_ciphertext_rec) = tokio::sync::mpsc::channel(8);
    let decryptors_cloned = decryptors.clone();
    thread::spawn(move || {
        decryption_loop(
            self_actor_id,
            decryptors_cloned,
            full_ciphertext_rec,
            decrypt_sink,
        );
    });

    loop {
        select! {
            Some(event) = incoming.recv() => {
                match event {
                    ActorEvent::NewCiphertext(id, ciphertext) => {
                        tracing::debug!("Actor {} received ciphertext with id {}", self_actor_id, id);
                        if done.contains_key(&id) {
                            tracing::debug!("Actor {} already decrypted message with id {}", self_actor_id, id);
                            continue;
                        }
                        let mut decryptors = decryptors.write().await;
                        if decryptors.contains_key(&id) {
                            tracing::debug!("Actor {} already has decryptor for id {}", self_actor_id, id);
                            continue;
                        }
                        // Store the ciphertext for later use (decryption once we have a quorum)
                        ciphertexts.insert(id, ciphertext.clone());
                        // Create a new decryptor for the ciphertext
                        decryptors.insert(id, Arc::new(decryptor.new_from_pk_set()));
                        ciphertext_src.send((id, ciphertext.clone())).await.unwrap();
                        tracing::debug!("Actor {} sent ciphertext to decryptor for id {}", self_actor_id, id);
                    }
                    ActorEvent::NewDecryptionShare(id, actor_id, share) => {
                        if done.contains_key(&id) {
                            tracing::debug!("Actor {} already decrypted message with id {}", self_actor_id, id);
                            continue;
                        }
                        tracing::debug!("Actor {} received decryption share from {}", self_actor_id, id);
                        let mut decryptors = decryptors.write().await;
                        if let Some(d) = decryptors.get_mut(&id) {
                            if let Err(e) = d.add_share(actor_id, share.get_decryption_share().clone()) {
                                tracing::error!("Actor {} failed to add share: {}", self_actor_id, e);
                            }
                            if d.has_quorum().unwrap_or(false) {
                                tracing::debug!("Actor {} has quorum for decryption {}", self_actor_id, id);
                                let ciphertext = ciphertexts.get(&id).unwrap();
                                full_ciphertext_src.send((id, ciphertext.clone())).await.unwrap();
                            }
                        } else {
                            tracing::warn!("Actor {} received decryption share for unknown id {}", self_actor_id, id);
                        }
                    }
                    ActorEvent::NewDecryption(id, _) => {
                        tracing::debug!("Actor {} received decryption event {}", self_actor_id, id);
                        if done.contains_key(&id) {
                            tracing::debug!("Actor {} already decrypted message with id {}", self_actor_id, id);
                            continue;
                        }
                        done.insert(id, true);
                        let mut decryptors = decryptors.write().await;
                        if let Some(decryptor) = decryptors.get_mut(&id) {
                            if decryptor.get_collector().clear().is_ok() {
                                tracing::debug!("Actor {} cleared collector for id {}", self_actor_id, id);
                            }
                            decryptors.remove(&id);
                        }
                    }
                }
            }
            Some((id, dec_share)) = share_decrypt_rec.recv() => {
                let mut decryptors = decryptors.write().await;
                let decryptor = decryptors.get_mut(&id).unwrap();
                match decryptor.add_share(self_actor_id, dec_share.get_decryption_share().clone()) {
                    Ok(has_quorum) => {
                        tracing::debug!("Actor {} decrypted message with id {}", self_actor_id, id);
                        let event = ActorEvent::NewDecryptionShare(id, self_actor_id , dec_share);
                        if let Err(e) = outgoing.send(event).await {
                            tracing::error!("Actor {} failed to send share decryption: {}", self_actor_id, e);
                        }
                        if has_quorum {
                            tracing::debug!("Actor {} has quorum for decryption {}", self_actor_id, id);
                            let ciphertext = ciphertexts.get(&id).unwrap();
                            full_ciphertext_src.send((id, ciphertext.clone())).await.unwrap();
                        }
                    }
                    Err(e) => {
                        tracing::error!("Actor {} failed to add share: {}", self_actor_id, e);
                    }
                };
            }
            Some((id, plaintext)) = decrypt_rec.recv() => {
                tracing::debug!("Actor {} fully decrypted message with id {}", self_actor_id, id);
                let event = ActorEvent::NewDecryption(id, plaintext);
                if let Err(e) = outgoing.send(event).await {
                    tracing::warn!("Actor {} failed to send decryption: {}", self_actor_id, e);
                } 
                done.insert(id, true);
                let mut decryptors = decryptors.write().await;
                let _ = decryptors.remove(&id);
                let _ = ciphertexts.remove(&id);
            }

        }
    }
}

fn share_decryption_loop(
    actor: Actor,
    mut ciphertext_rec: Receiver<(usize, CiphertextMsg)>,
    decrypt_sink: Sender<(usize, DecryptionShareMsg)>,
) {
    let actor_id = actor.id;
    tracing::debug!("Starting decryption thread for actor {}", actor_id);
    loop {
        tracing::debug!("Actor {} waiting for ciphertext", actor_id);
        let (id, ciphertext) = match ciphertext_rec.blocking_recv() {
            Some((id, ciphertext)) => (id, ciphertext),
            None => {
                tracing::debug!("Actor {} stopping share decryption thread", actor_id);
                return;
            }
        };
        tracing::debug!("Actor {} received ciphertext {}", actor_id, id);
        let dec_share = match actor.decrypt_share(ciphertext.get_ciphertext().clone()) {
            Ok(share) => {
                tracing::debug!("Actor {} decrypted share ({})", actor_id, id);
                share
            }
            Err(e) => {
                tracing::warn!("Actor {} failed to decrypt share ({}): {}", actor_id, id, e);
                continue;
            }
        };
        if let Err(e) = decrypt_sink.blocking_send((id, DecryptionShareMsg::new(dec_share))) {
            tracing::warn!(
                "Actor {} failed to send decryption share on channel: {}",
                actor_id,
                e
            );
        }
    }
}

fn decryption_loop(
    actor_id: usize,
    decryptors: Arc<RwLock<BTreeMap<usize, Arc<ShareDecryptor>>>>,
    mut ciphertext_rec: Receiver<(usize, CiphertextMsg)>,
    decrypt_sink: Sender<(usize, Vec<u8>)>,
) {
    tracing::debug!("Starting decryption thread for actor {}", actor_id);
    loop {
        // tracing::debug!("Actor {} waiting for ciphertext", actor_id);
        let (id, ciphertext) = match ciphertext_rec.blocking_recv() {
            Some((id, ciphertext)) => (id, ciphertext),
            None => {
                tracing::debug!("Actor {} stopping decryption thread", actor_id);
                return;
            }
        };
        tracing::debug!("Actor {} received ciphertext {}", actor_id, id);
        let decryptors = decryptors.blocking_read();
        let decryptor = match decryptors.get(&id) {
            Some(decryptor) => decryptor,
            None => {
                tracing::warn!("Actor {} failed to get decryptor for id {}", actor_id, id);
                continue;
            }
        };
        if !decryptor.has_quorum().unwrap_or(false) {
            tracing::warn!("Actor {} does not have quorum for decryption {}, skipping", actor_id, id);
            continue;
        }
        let plaintext = match decryptor.decrypt(ciphertext.get_ciphertext().clone()) {
            Ok(plaintext) => {
                tracing::debug!("Actor {} decrypted share ({})", actor_id, id);
                plaintext
            }
            Err(e) => {
                tracing::warn!("Actor {} failed to decrypt ({}): {}", actor_id, id, e);
                continue;
            }
        };
        if let Err(e) = decrypt_sink.blocking_send((id, plaintext)) {
            tracing::warn!(
                "Actor {} failed to send decryption share on channel: {}",
                actor_id,
                e
            );
        }
    }

}

#[cfg(test)]
mod tests {
    use std::sync::atomic;

    use super::*;

    use crate::core::{Actor, CiphertextMsg, Committee, ShareDecryptor};

    use threshold_crypto::PublicKeySet;
    
    use tokio::sync::mpsc::{Receiver, Sender, channel};

    #[tokio::test]
    async fn test_actor_loop() {
        // initialize tracing
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .without_time()
            .init();

        let n_msgs = 10;
        // let n_threads = 5;
        let n = 5;
        let t = 3;

        let mut committee = Committee::new(n, t);

        let mut incoming_vec: Vec<Sender<ActorEvent>> = Vec::new();
        let mut outgoing_vec: Vec<Receiver<ActorEvent>> = Vec::new();

        for i in 0..n {
            let actor = committee.get_actor(i);
            let (incoming, outgoing_rec) =
                spawn_actor_loop(actor.clone(), committee.pk_set.clone());
            incoming_vec.push(incoming);
            outgoing_vec.push(outgoing_rec);
        }

        let counter = Arc::new(atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        // listen for outgoing messages from all actors and broadcast them to all other actors
        for i in 0..n {
            let mut outgoing = outgoing_vec.remove(0);
            let incoming_vec = incoming_vec.clone();
            let counter = counter.clone();
            let actor_id = i;
            let handle = tokio::spawn(async move {
                while let Some(event) = outgoing.recv().await {
                    match event {
                        ActorEvent::NewDecryptionShare(id, actor_id, dec_share_msg) => {
                            tracing::debug!(
                                "Actor {} produced decryption share ({})",
                                actor_id,
                                id
                            );
                            let event = ActorEvent::NewDecryptionShare(id, actor_id, dec_share_msg);
                            // broadcast the decryption share to all other actors
                            for i in 0..n {
                                let e = event.clone();
                                if actor_id != i {
                                    incoming_vec[i].send(e).await.unwrap();
                                }
                            }
                        }
                        ActorEvent::NewDecryption(id, plaintext) => {
                            tracing::info!("Actor {} received decryption event {}", actor_id, id);
                            let expected = format!("test-message-{}", id);
                            assert_eq!(plaintext, expected.as_bytes());
                            counter.fetch_add(1, atomic::Ordering::SeqCst);
                        }
                        _ => {}
                    }
                }
            });
            handles.push(handle);
        }

        let pk = committee.pk_set.public_key();

        for im in 0..n_msgs {
            let im = im + 1;
            let plaintext = format!("test-message-{}", im);
            let ciphertext = pk.encrypt(plaintext.as_bytes());
            for i in 0..n {
                let incoming = incoming_vec[i].clone();
                let ciphertext_msg = CiphertextMsg::new(ciphertext.clone());
                tokio::spawn(async move {
                    let _ = incoming
                        .send(ActorEvent::NewCiphertext(im, ciphertext_msg))
                        .await
                        .unwrap();
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // wait for counter to reach t
        loop {
            let count = counter.load(atomic::Ordering::SeqCst);
            if count > t * n_msgs {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    fn spawn_actor_loop(
        actor: Actor,
        pk_set: PublicKeySet,
    ) -> (Sender<ActorEvent>, Receiver<ActorEvent>) {
        let (incoming, incoming_rec): (Sender<ActorEvent>, Receiver<ActorEvent>) = channel(8);
        let (outgoing, outgoing_rec): (Sender<ActorEvent>, Receiver<ActorEvent>) = channel(8);

        tokio::spawn(async move {
            let decryptor = ShareDecryptor::new(pk_set);
            start_actor_loop(actor, decryptor, incoming_rec, outgoing).await;
        });

        (incoming, outgoing_rec)
    }
}
