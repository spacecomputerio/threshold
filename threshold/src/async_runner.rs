use std::{collections::BTreeMap, sync::Arc, thread};

use crate::core::{Actor, CiphertextMsg, DecryptionShareMsg, Decryptors, Error};

use threshold_crypto::PublicKeySet;
use tokio::{
    select,
    sync::{
        broadcast,
        mpsc::{Receiver, Sender},
    },
};

/// ActorEvent is an enum that represents the events that can occur in the actor loop.
#[derive(Clone)]
pub enum ActorEvent {
    /// NewCiphertext is sent when a new ciphertext is received from the network.
    /// The ciphertext should be decrypted and the decryption share should be sent to the network.
    NewCiphertext(usize, String),
    /// NewDecryptionShare is sent when a new decryption share is received from the network
    /// or sent to the network.
    NewDecryptionShare(usize, usize, String),
    /// NewDecryption is sent when a new decryption can be performed, i.e. when a quorum of shares
    /// has been received.
    NewDecryption(usize, Vec<u8>),
}

/// WorkerTransport is a struct that contains the sink and source channels
/// for the worker threads and the main thread.
/// TODO: use an optimized channel for the sink and source channels.
#[derive(Clone)]
struct WorkerTransport<I, O>
where
    I: Send + 'static,
    O: Send + 'static,
{
    /// The sink channel for sending messages from the worker thread to the main thread.
    sink: broadcast::Sender<(usize, O)>,
    /// The source channel for sending messages from the main thread to the worker thread.
    src: broadcast::Sender<(usize, I)>,
}

impl<I, O> WorkerTransport<I, O>
where
    I: Send + Clone + 'static,
    O: Send + Clone + 'static,
{
    /// Creates a new WorkerTransport with the given buffer size.
    pub fn new(buf_size: usize) -> Self {
        let (sink, _) = tokio::sync::broadcast::channel(buf_size);
        let (src, _) = tokio::sync::broadcast::channel(buf_size);
        Self { sink, src }
    }

    /// Sends a message on the sink channel.
    pub fn send_sink(&self, id: usize, msg: O) -> Result<(), Error> {
        if let Err(e) = self.sink.send((id, msg)) {
            return Err(Error::InternalError(format!(
                "Failed to send message on sink channel: {}",
                e
            )));
        }
        Ok(())
    }

    /// Returns a receiver for the sink channel.
    pub fn sink_recv(&self) -> broadcast::Receiver<(usize, O)> {
        self.sink.subscribe()
    }

    /// Sends a message on the source channel.
    pub fn send_src(&self, id: usize, msg: I) -> Result<(), Error> {
        if let Err(e) = self.src.send((id, msg)) {
            return Err(Error::InternalError(format!(
                "Failed to send message on src channel: {}",
                e
            )));
        }
        Ok(())
    }

    /// Returns a receiver for the source channel.
    pub fn src_recv(&self) -> broadcast::Receiver<(usize, I)> {
        self.src.subscribe()
    }
}

/// Starts the actor loop on the current thread.
/// It will spawn new threads to handle decryption and share decryption w/o blocking the main thread.
pub async fn run_actor(
    actor: Actor,
    pk_set: PublicKeySet,
    mut incoming: Receiver<ActorEvent>,
    outgoing: Sender<ActorEvent>,
) {
    tracing::debug!("Starting actor {}", actor.id);
    let self_actor_id = actor.id;
    let decryptors = Arc::new(Decryptors::new(pk_set));
    let mut ciphertexts = BTreeMap::new();
    let mut done = BTreeMap::new();

    // start a new thread to handle (share) decrypting ciphertexts as it is a blocking operation
    let share_decrypt_worker_transport =
        WorkerTransport::<CiphertextMsg, DecryptionShareMsg>::new(8);
    let share_decrypt_worker_transport_cloned = share_decrypt_worker_transport.clone();
    thread::spawn(move || {
        share_decryption_loop(actor, share_decrypt_worker_transport_cloned);
    });

    // start a new thread to handle decrypting ciphertexts as it is a blocking operation
    let decrypt_worker_transport = WorkerTransport::<CiphertextMsg, Vec<u8>>::new(8);
    let decrypt_worker_transport_cloned = decrypt_worker_transport.clone();
    let decryptors_cloned = decryptors.clone();
    thread::spawn(move || {
        decryption_loop(
            self_actor_id,
            decryptors_cloned,
            decrypt_worker_transport_cloned,
        );
    });

    let mut share_decrypt_rec = share_decrypt_worker_transport.sink_recv();
    let mut decrypt_rec = decrypt_worker_transport.sink_recv();
    loop {
        select! {
            Some(event) = incoming.recv() => {
                match event {
                    ActorEvent::NewCiphertext(id, raw_ciphertext) => {
                        let ciphertext = match CiphertextMsg::try_from(raw_ciphertext) {
                            Ok(ciphertext) => ciphertext,
                            Err(e) => {
                                tracing::warn!("Actor {} failed to parse ciphertext: {}", self_actor_id, e);
                                continue;
                            }
                        };
                        tracing::debug!("Actor {} received ciphertext with id {}", self_actor_id, id);
                        if done.contains_key(&id) {
                            tracing::debug!("Actor {} already decrypted message with id {}", self_actor_id, id);
                            continue;
                        }
                        if decryptors.has(id) {
                            tracing::debug!("Actor {} already has decryptor for id {}", self_actor_id, id);
                            continue;
                        }
                        // Store the ciphertext for later use (decryption once we have a quorum)
                        ciphertexts.insert(id, ciphertext.clone());
                        // Create a new decryptor for the ciphertext
                        decryptors.new_decryptor(id);
                        if let Err(e) = share_decrypt_worker_transport.send_src(id, ciphertext.clone()) {
                            tracing::error!("Actor {} failed to send ciphertext on channel: {}", self_actor_id, e);
                        } else {
                            tracing::debug!("Actor {} sent ciphertext to decryptor for id {}", self_actor_id, id);
                        }
                    }
                    ActorEvent::NewDecryptionShare(id, actor_id, raw_share) => {
                        let share = match DecryptionShareMsg::try_from(raw_share) {
                            Ok(share) => share,
                            Err(e) => {
                                tracing::warn!("Actor {} failed to parse decryption share: {}", self_actor_id, e);
                                continue;
                            }
                        };
                        if done.contains_key(&id) {
                            tracing::debug!("Actor {} already decrypted message with id {}", self_actor_id, id);
                            continue;
                        }
                        tracing::debug!("Actor {} received decryption share from {}", self_actor_id, id);
                        if let Some(d) = decryptors.get(id) {
                            if let Err(e) = d.add_share(actor_id, share.get_decryption_share().clone()) {
                                tracing::error!("Actor {} failed to add share: {}", self_actor_id, e);
                            }
                            if d.has_quorum().unwrap_or(false) {
                                tracing::debug!("Actor {} has quorum for decryption {}", self_actor_id, id);
                                let ciphertext = ciphertexts.get(&id).unwrap();
                                if let Err(e) = decrypt_worker_transport.send_src(id, ciphertext.clone()) {
                                    tracing::error!("Actor {} failed to send ciphertext on channel: {}", self_actor_id, e);
                                } else {
                                    tracing::debug!("Actor {} sent ciphertext to decryptor for id {}", self_actor_id, id);
                                }
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
                        if let Some(decryptor) = decryptors.get(id) {
                            if decryptor.get_collector().clear().is_ok() {
                                tracing::debug!("Actor {} cleared collector for id {}", self_actor_id, id);
                            }
                            decryptors.remove(id);
                        }
                    }
                }
            }
            Ok((id, dec_share)) = share_decrypt_rec.recv() => {
                let decryptor = match decryptors.get(id) {
                    Some(decryptor) => decryptor,
                    None => {
                        tracing::warn!("Actor {} failed to get decryptor for id {}", self_actor_id, id);
                        continue;
                    }
                };
                match decryptor.add_share(self_actor_id, dec_share.get_decryption_share().clone()) {
                    Ok(has_quorum) => {
                        tracing::debug!("Actor {} decrypted message with id {}", self_actor_id, id);
                        let raw_dec_share = dec_share.try_into().unwrap();
                        let event = ActorEvent::NewDecryptionShare(id, self_actor_id , raw_dec_share);
                        if let Err(e) = outgoing.send(event).await {
                            tracing::error!("Actor {} failed to send share decryption: {}", self_actor_id, e);
                        }
                        if has_quorum {
                            tracing::debug!("Actor {} has quorum for decryption {}", self_actor_id, id);
                            let ciphertext = ciphertexts.get(&id).unwrap();
                            if let Err(e) = decrypt_worker_transport.send_src(id, ciphertext.clone()) {
                                tracing::error!("Actor {} failed to send ciphertext on channel: {}", self_actor_id, e);
                            } else {
                                tracing::debug!("Actor {} sent ciphertext to decryptor for id {}", self_actor_id, id);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Actor {} failed to add share: {}", self_actor_id, e);
                    }
                };
            }
            Ok((id, plaintext)) = decrypt_rec.recv() => {
                tracing::debug!("Actor {} fully decrypted message with id {}", self_actor_id, id);
                let event = ActorEvent::NewDecryption(id, plaintext);
                if let Err(e) = outgoing.send(event).await {
                    tracing::warn!("Actor {} failed to send decryption: {}", self_actor_id, e);
                }
                done.insert(id, true);
                decryptors.remove(id);
                let _ = ciphertexts.remove(&id);
            }

        }
    }
}

/// Handles share decryption of ciphertexts.
/// NOTE: this function uses blocking operations and should be run in a separate thread.
pub fn share_decryption_loop(
    actor: Actor,
    worker_transport: WorkerTransport<CiphertextMsg, DecryptionShareMsg>,
) {
    let actor_id = actor.id;
    tracing::debug!("Starting share-decryption thread for actor {}", actor_id);
    let mut ciphertext_rec = worker_transport.src_recv();
    loop {
        let (id, ciphertext) = match ciphertext_rec.blocking_recv() {
            Ok((id, ciphertext)) => (id, ciphertext),
            Err(e) => {
                tracing::debug!("Actor {} stopping share-decryption thread: {}", actor_id, e);
                return;
            }
        };
        tracing::debug!(
            "Actor {} received ciphertext ({}) for share decryption",
            actor_id,
            id
        );
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
        if let Err(e) = worker_transport.send_sink(id, DecryptionShareMsg::new(dec_share)) {
            tracing::warn!(
                "Actor {} failed to send decryption share on channel: {}",
                actor_id,
                e
            );
        }
    }
}

/// Handles decryption of ciphertexts after a quorum of shares has been received.
/// NOTE: this function uses blocking operations and should be run in a separate thread.
pub fn decryption_loop(
    actor_id: usize,
    decryptors: Arc<Decryptors>,
    worker_transport: WorkerTransport<CiphertextMsg, Vec<u8>>,
) {
    tracing::debug!("Starting decryption thread for actor {}", actor_id);
    let mut ciphertext_rec = worker_transport.src_recv();

    loop {
        let (id, ciphertext) = match ciphertext_rec.blocking_recv() {
            Ok((id, ciphertext)) => (id, ciphertext),
            Err(e) => {
                tracing::debug!("Actor {} stopping decryption thread: {}", actor_id, e);
                return;
            }
        };
        tracing::debug!("Actor {} received ciphertext {}", actor_id, id);
        let decryptor = match decryptors.get(id) {
            Some(decryptor) => decryptor,
            None => {
                tracing::warn!("Actor {} failed to get decryptor for id {}", actor_id, id);
                continue;
            }
        };
        if !decryptor.has_quorum().unwrap_or(false) {
            tracing::warn!(
                "Actor {} does not have quorum for decryption {}, skipping",
                actor_id,
                id
            );
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
        if let Err(e) = worker_transport.send_sink(id, plaintext) {
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

    use crate::core::{Actor, CiphertextMsg, Committee};

    use threshold_crypto::PublicKeySet;

    use tokio::sync::mpsc::{Receiver, Sender};

    #[tokio::test]
    async fn test_run_actor() {
        // initialize tracing
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_target(false)
            .without_time()
            .init();

        let n_msgs = 10;
        let n = 5;
        let t = 3;

        let mut committee = Committee::new(n, t);

        let mut incoming_vec: Vec<Sender<ActorEvent>> = Vec::new();
        let mut outgoing_vec: Vec<Receiver<ActorEvent>> = Vec::new();

        for i in 0..n {
            let actor = committee.get_actor(i);
            let (incoming, outgoing_rec) = spawn_actor(actor.clone(), committee.pk_set.clone());
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
                let ciphertext_msg = CiphertextMsg::new(ciphertext.clone()).try_into().unwrap();
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

    fn spawn_actor(
        actor: Actor,
        pk_set: PublicKeySet,
    ) -> (Sender<ActorEvent>, Receiver<ActorEvent>) {
        let (incoming, incoming_rec) = tokio::sync::mpsc::channel(8);
        let (outgoing, outgoing_rec) = tokio::sync::mpsc::channel(8);

        tokio::spawn(async move {
            run_actor(actor, pk_set, incoming_rec, outgoing).await;
        });

        (incoming, outgoing_rec)
    }
}
