use crate::error::AvoError;
use crate::network::key_management::KeyManager;
use crate::network::{NetworkConfig, NodeType};
use crate::types::StakeAmount;
use blake3;
use futures::prelude::*;
use libp2p::autonat;
use libp2p::gossipsub::{self, IdentTopic, MessageId, PublishError, TopicHash};
use libp2p::identify;
use libp2p::kad::{self, store::MemoryStore, Behaviour as Kademlia, Event as KademliaEvent};
use libp2p::multiaddr::Protocol;
use libp2p::noise;
use libp2p::ping;
use libp2p::swarm::{Config as SwarmConfig, NetworkBehaviour, SwarmEvent};
use libp2p::{identity, Multiaddr, PeerId, Swarm, Transport};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Configuración extendida para la red libp2p
#[derive(Clone)]
pub struct Libp2pNetworkConfig {
    pub network: NetworkConfig,
    pub key_manager: Arc<KeyManager>,
    pub telemetry_interval: Duration,
    pub stake_weights: HashMap<String, StakeAmount>,
}

impl Libp2pNetworkConfig {
    pub fn new(network: NetworkConfig, key_manager: Arc<KeyManager>) -> Self {
        Self {
            network,
            key_manager,
            telemetry_interval: Duration::from_secs(30),
            stake_weights: HashMap::new(),
        }
    }
}

/// Metadatos de reputación por peer
#[derive(Debug, Clone)]
pub struct PeerMetadata {
    pub stake: StakeAmount,
    pub uptime: Duration,
    pub reputation: f64,
    pub addresses: Vec<Multiaddr>,
    last_seen: Instant,
}

impl Default for PeerMetadata {
    fn default() -> Self {
        Self {
            stake: 0,
            uptime: Duration::from_secs(0),
            reputation: 1.0,
            addresses: Vec::new(),
            last_seen: Instant::now(),
        }
    }
}

impl PeerMetadata {
    pub fn weight(&self) -> f64 {
        let stake_weight = if self.stake == 0 {
            1.0
        } else {
            (self.stake as f64).log10().max(1.0)
        };
        let uptime_weight = (self.uptime.as_secs_f64() / 3600.0).min(10.0) + 1.0;
        self.reputation.max(0.1) * stake_weight * uptime_weight
    }

    pub fn refresh(&mut self) {
        self.last_seen = Instant::now();
    }
}

/// Comandos que puede recibir la red
#[derive(Debug)]
pub enum NetworkCommand {
    Publish {
        topic: IdentTopic,
        data: Vec<u8>,
    },
    Subscribe {
        topic: IdentTopic,
    },
    Dial {
        address: Multiaddr,
    },
    UpdatePeerMetadata {
        peer_id: PeerId,
        metadata: PeerMetadata,
    },
    Shutdown,
}

/// Eventos producidos por la red
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    GossipsubMessage {
        peer_id: Option<PeerId>,
        topic: TopicHash,
        data: Vec<u8>,
    },
    PeerConnected {
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    },
    PeerDisconnected {
        peer_id: PeerId,
    },
    DialFailure {
        peer_id: Option<PeerId>,
        error: String,
    },
    KademliaRoutingUpdated {
        peer_id: PeerId,
        bucket_range: String,
        total_peers: usize,
    },
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "AvoBehaviourEvent")]
struct AvoBehaviour {
    gossipsub: gossipsub::Behaviour,
    kademlia: Kademlia<MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    autonat: autonat::Behaviour,
}

#[derive(Debug)]
enum AvoBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(KademliaEvent),
    Identify(identify::Event),
    Ping(ping::Event),
    Autonat(autonat::Event),
}

impl From<gossipsub::Event> for AvoBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<KademliaEvent> for AvoBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        Self::Kademlia(event)
    }
}

impl From<identify::Event> for AvoBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<ping::Event> for AvoBehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<autonat::Event> for AvoBehaviourEvent {
    fn from(event: autonat::Event) -> Self {
        Self::Autonat(event)
    }
}

/// Handle para interactuar con la red libp2p
#[derive(Clone)]
pub struct Libp2pNetworkController {
    command_tx: mpsc::Sender<NetworkCommand>,
    local_peer_id: PeerId,
}

impl Libp2pNetworkController {
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub async fn publish(&self, topic: &IdentTopic, data: Vec<u8>) -> Result<(), AvoError> {
        self.command_tx
            .send(NetworkCommand::Publish {
                topic: topic.clone(),
                data,
            })
            .await
            .map_err(|e| AvoError::network(format!("Publish command failed: {}", e)))
    }

    pub async fn subscribe(&self, topic: &IdentTopic) -> Result<(), AvoError> {
        self.command_tx
            .send(NetworkCommand::Subscribe {
                topic: topic.clone(),
            })
            .await
            .map_err(|e| AvoError::network(format!("Subscribe command failed: {}", e)))
    }

    pub async fn dial(&self, address: Multiaddr) -> Result<(), AvoError> {
        self.command_tx
            .send(NetworkCommand::Dial { address })
            .await
            .map_err(|e| AvoError::network(format!("Dial command failed: {}", e)))
    }

    pub async fn update_peer_metadata(
        &self,
        peer_id: PeerId,
        metadata: PeerMetadata,
    ) -> Result<(), AvoError> {
        self.command_tx
            .send(NetworkCommand::UpdatePeerMetadata { peer_id, metadata })
            .await
            .map_err(|e| AvoError::network(format!("Metadata update failed: {}", e)))
    }

    pub async fn shutdown(&self) -> Result<(), AvoError> {
        self.command_tx
            .send(NetworkCommand::Shutdown)
            .await
            .map_err(|e| AvoError::network(format!("Shutdown command failed: {}", e)))
    }
}

/// Inicializa y ejecuta el swarm libp2p en un task dedicado
pub fn spawn_libp2p_network(
    config: Libp2pNetworkConfig,
) -> Result<(Libp2pNetworkController, mpsc::Receiver<NetworkEvent>), AvoError> {
    let (command_tx, mut command_rx) = mpsc::channel::<NetworkCommand>(64);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(128);

    let mut secret_bytes = config.key_manager.secret_key();
    let secret = identity::ed25519::SecretKey::try_from_bytes(&mut secret_bytes)
        .map_err(|_| AvoError::crypto("Invalid ed25519 secret key for libp2p"))?;
    let libp2p_keypair = identity::ed25519::Keypair::from(secret);
    let identity = identity::Keypair::from(libp2p_keypair);
    let local_peer_id = PeerId::from(identity.public());

    info!("🌐 Starting libp2p swarm with peer id: {local_peer_id}");

    // Build transport (TCP + Noise + Yamux)
    let transport =
        libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(
                noise::Config::new(&identity)
                    .map_err(|e| AvoError::network(format!("Noise config error: {e}")))?,
            )
            .multiplex(libp2p::yamux::Config::default())
            .boxed();

    let behaviour = build_behaviour(&identity, &config);

    // Prepare swarm
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        SwarmConfig::with_tokio_executor(),
    );

    // Listen on configured address
    let mut listen_multiaddr = Multiaddr::empty();
    match config.network.listen_address.ip() {
        std::net::IpAddr::V4(ip) => listen_multiaddr.push(Protocol::Ip4(ip)),
        std::net::IpAddr::V6(ip) => listen_multiaddr.push(Protocol::Ip6(ip)),
    }
    listen_multiaddr.push(Protocol::Tcp(config.network.listen_address.port()));

    let listen_id = Swarm::listen_on(&mut swarm, listen_multiaddr)
        .map_err(|e| AvoError::network(format!("Failed to start listener: {e}")))?;

    info!("🎧 Listening on {:?}", listen_id);

    let peer_metadata = Arc::new(RwLock::new(HashMap::<PeerId, PeerMetadata>::new()));
    let shard_assignment = config.network.shard_assignment.clone();

    tokio::spawn(async move {
        let telemetry_interval = config.telemetry_interval;
        let mut telemetry_timer = tokio::time::interval(telemetry_interval);
        let mut swarm = swarm;
        let peer_metadata_map = peer_metadata.clone();
        let mut subscribed_topics: HashMap<TopicHash, IdentTopic> = HashMap::new();

        for shard in &shard_assignment {
            let topic = IdentTopic::new(format!("avo/shard/{shard}"));
            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                warn!(
                    "Failed to subscribe to default shard topic {}: {e}",
                    topic.hash()
                );
            } else {
                subscribed_topics.insert(topic.hash(), topic.clone());
            }
        }

        loop {
            tokio::select! {
                biased;
                maybe_command = command_rx.recv() => {
                    match maybe_command {
                        Some(NetworkCommand::Publish { topic, data }) => {
                            if let Err(e) = publish_message(&mut swarm.behaviour_mut().gossipsub, &topic, data) {
                                warn!("Failed to publish gossip message: {e}");
                            }
                        }
                        Some(NetworkCommand::Subscribe { topic }) => {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                                warn!("Failed to subscribe to topic {}: {e}", topic.hash());
                            } else {
                                subscribed_topics.insert(topic.hash(), topic.clone());
                            }
                        }
                        Some(NetworkCommand::Dial { address }) => {
                            if let Err(e) = Swarm::dial(&mut swarm, address.clone()) {
                                warn!("Dial error: {e}");
                                let _ = event_tx.send(NetworkEvent::DialFailure { peer_id: None, error: e.to_string() }).await;
                            }
                        }
                        Some(NetworkCommand::UpdatePeerMetadata { peer_id, metadata }) => {
                            peer_metadata_map.write().await.insert(peer_id, metadata);
                        }
                        Some(NetworkCommand::Shutdown) => {
                            info!("🛑 Shutting down libp2p swarm");
                            break;
                        }
                        None => break,
                    }
                }
                swarm_event = swarm.select_next_some() => {
                    match swarm_event {
                        SwarmEvent::Behaviour(AvoBehaviourEvent::Gossipsub(event)) => {
                            handle_gossipsub_event(event, &event_tx).await;
                        }
                        SwarmEvent::Behaviour(AvoBehaviourEvent::Kademlia(event)) => {
                            handle_kademlia_event(event, &event_tx, &peer_metadata_map, &mut swarm).await;
                        }
                        SwarmEvent::Behaviour(AvoBehaviourEvent::Identify(event)) => {
                            if let identify::Event::Received { peer_id, info, .. } = event {
                                let addresses: Vec<Multiaddr> = info.listen_addrs;
                                let _ = event_tx.send(NetworkEvent::PeerConnected { peer_id, addresses }).await;
                            }
                        }
                        SwarmEvent::Behaviour(AvoBehaviourEvent::Ping(ping::Event { peer, result, .. })) => {
                            match result {
                                Ok(_) => {
                                    let mut guard = peer_metadata_map.write().await;
                                    let entry = guard.entry(peer).or_default();
                                    entry.uptime += telemetry_interval;
                                    entry.refresh();
                                }
                                Err(err) => {
                                    warn!("Ping failure with {peer}: {err:?}");
                                    let _ = event_tx.send(NetworkEvent::PeerDisconnected { peer_id: peer }).await;
                                }
                            }
                        }
                        SwarmEvent::Behaviour(AvoBehaviourEvent::Autonat(_)) => {}
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("📡 Listening on {address}");
                        }
                        SwarmEvent::IncomingConnection { .. } => {}
                        SwarmEvent::IncomingConnectionError { error, .. } => {
                            warn!("Incoming connection error: {error}");
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                            debug!("Connected to {peer_id} via {:?}", endpoint);
                        }
                        SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            let _ = event_tx.send(NetworkEvent::PeerDisconnected { peer_id }).await;
                        }
                        SwarmEvent::Dialing { peer_id, .. } => {
                            if let Some(peer) = peer_id {
                                debug!("Dialing {peer}");
                            }
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            let _ = event_tx.send(NetworkEvent::DialFailure {
                                peer_id,
                                error: error.to_string(),
                            }).await;
                        }
                        _ => {}
                    }
                }
                _ = telemetry_timer.tick() => {
                    trace_metrics(&mut swarm, &peer_metadata_map, &subscribed_topics, &shard_assignment).await;
                }
            }
        }
    });

    let controller = Libp2pNetworkController {
        command_tx,
        local_peer_id,
    };

    Ok((controller, event_rx))
}

fn build_behaviour(identity: &identity::Keypair, config: &Libp2pNetworkConfig) -> AvoBehaviour {
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(|message: &gossipsub::Message| {
            let digest = blake3::hash(&message.data);
            MessageId::from(digest.to_hex().to_string())
        })
        .build()
        .expect("valid gossipsub config");

    let message_authenticity = match config.network.node_type {
        NodeType::Validator | NodeType::BackupValidator => {
            gossipsub::MessageAuthenticity::Signed(identity.clone())
        }
        _ => gossipsub::MessageAuthenticity::Anonymous,
    };

    let gossipsub = gossipsub::Behaviour::new(message_authenticity, gossipsub_config)
        .expect("Gossipsub behaviour");

    let store = MemoryStore::new(PeerId::from(identity.public()));
    let mut kademlia = Kademlia::new(PeerId::from(identity.public()), store);

    for bootstrap in &config.network.bootstrap_nodes {
        let peer_id = peer_id_from_public_key(&bootstrap.public_key);
        let mut addr = Multiaddr::empty();
        match bootstrap.address.ip() {
            std::net::IpAddr::V4(ip) => addr.push(Protocol::Ip4(ip)),
            std::net::IpAddr::V6(ip) => addr.push(Protocol::Ip6(ip)),
        }
        addr.push(Protocol::Tcp(bootstrap.address.port()));
        kademlia.add_address(&peer_id, addr);
    }

    let identify_config = identify::Config::new("avo/1.0.0".into(), identity.public().clone());
    let identify = identify::Behaviour::new(identify_config);
    let ping = ping::Behaviour::new(ping::Config::default());
    let autonat = autonat::Behaviour::new(PeerId::from(identity.public()), Default::default());

    AvoBehaviour {
        gossipsub,
        kademlia,
        identify,
        ping,
        autonat,
    }
}

fn publish_message(
    gossipsub: &mut gossipsub::Behaviour,
    topic: &IdentTopic,
    data: Vec<u8>,
) -> Result<(), PublishError> {
    gossipsub.publish(topic.clone(), data).map(|_| ())
}

async fn handle_gossipsub_event(event: gossipsub::Event, event_tx: &mpsc::Sender<NetworkEvent>) {
    match event {
        gossipsub::Event::Message {
            propagation_source,
            message_id: _,
            message,
        } => {
            let _ = event_tx
                .send(NetworkEvent::GossipsubMessage {
                    peer_id: Some(propagation_source),
                    topic: message.topic,
                    data: message.data,
                })
                .await;
        }
        gossipsub::Event::Subscribed { peer_id, topic } => {
            debug!("Peer {peer_id} subscribed to {topic}");
        }
        gossipsub::Event::Unsubscribed { peer_id, topic } => {
            debug!("Peer {peer_id} unsubscribed from {topic}");
        }
        _ => {}
    }
}

async fn handle_kademlia_event(
    event: KademliaEvent,
    event_tx: &mpsc::Sender<NetworkEvent>,
    metadata: &Arc<RwLock<HashMap<PeerId, PeerMetadata>>>,
    swarm: &mut Swarm<AvoBehaviour>,
) {
    match event {
        KademliaEvent::RoutingUpdated {
            peer,
            is_new_peer,
            addresses,
            bucket_range,
            old_peer,
            ..
        } => {
            let address_list: Vec<Multiaddr> = addresses.iter().cloned().collect();

            {
                let mut guard = metadata.write().await;
                let entry = guard.entry(peer).or_default();
                entry.addresses = address_list.clone();
                entry.refresh();
            }

            let new_weight = metadata
                .read()
                .await
                .get(&peer)
                .cloned()
                .unwrap_or_default()
                .weight();

            if let Some(old_peer_id) = old_peer {
                let old_weight = metadata
                    .read()
                    .await
                    .get(&old_peer_id)
                    .cloned()
                    .unwrap_or_default()
                    .weight();

                if new_weight + 0.1 < old_weight {
                    debug!(
                        "Dropping peer {peer} (weight {:.2}) in favor of {old_peer_id} (weight {:.2})",
                        new_weight,
                        old_weight
                    );

                    let old_addresses = metadata
                        .read()
                        .await
                        .get(&old_peer_id)
                        .map(|meta| meta.addresses.clone());

                    {
                        let behaviour = swarm.behaviour_mut();
                        behaviour.kademlia.remove_peer(&peer);

                        if let Some(addrs) = old_addresses {
                            for addr in addrs {
                                behaviour.kademlia.add_address(&old_peer_id, addr);
                            }
                        }
                    }

                    return;
                }
            }

            let total_peers: usize = swarm.connected_peers().count();

            debug!(
                "Routing table updated with {peer} (new: {is_new_peer}) weight={new_weight:.2} total_peers={total_peers}"
            );

            let bucket_desc = format!("{:?}", bucket_range);

            if let Err(e) = event_tx
                .send(NetworkEvent::KademliaRoutingUpdated {
                    peer_id: peer,
                    bucket_range: bucket_desc,
                    total_peers,
                })
                .await
            {
                warn!("Failed to push routing event: {e}");
            }
        }
        _ => {}
    }
}

fn peer_id_from_public_key(public_key: &[u8]) -> PeerId {
    if let Ok(pk) = identity::ed25519::PublicKey::try_from_bytes(public_key) {
        PeerId::from(identity::PublicKey::from(pk))
    } else {
        let mut bytes = *blake3::hash(public_key).as_bytes();
        let secret = identity::ed25519::SecretKey::try_from_bytes(&mut bytes)
            .unwrap_or_else(|_| identity::ed25519::SecretKey::generate());
        let derived = identity::ed25519::Keypair::from(secret);
        PeerId::from(identity::PublicKey::from(derived.public()))
    }
}

async fn trace_metrics(
    swarm: &mut Swarm<AvoBehaviour>,
    metadata: &Arc<RwLock<HashMap<PeerId, PeerMetadata>>>,
    topics: &HashMap<TopicHash, IdentTopic>,
    shard_assignment: &[u32],
) {
    let peer_count = swarm.connected_peers().count();
    let topic_count = topics.len();

    let total_weight: f64 = metadata
        .read()
        .await
        .values()
        .map(|meta| meta.weight())
        .sum();

    info!("📊 libp2p peers={peer_count} topics={topic_count} total_weight={total_weight:.2} shards={:?}", shard_assignment);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::multi_node_config::NetworkConfig;

    #[tokio::test]
    async fn build_controller_and_shutdown() {
        let key_manager = Arc::new(KeyManager::generate().expect("key manager"));
        let mut network_config = NetworkConfig::default();
        network_config.listen_address = "127.0.0.1:0".parse().unwrap();

        let cfg = Libp2pNetworkConfig::new(network_config, key_manager);
        let (controller, mut events) = spawn_libp2p_network(cfg).expect("network spawn");

        // Esperar a que emerja algún evento o un timeout corto
        let timeout = tokio::time::sleep(Duration::from_millis(200));
        tokio::pin!(timeout);

        tokio::select! {
            _ = timeout.as_mut() => {}
            _ = events.recv() => {}
        }

        controller.shutdown().await.expect("shutdown command");
    }
}
