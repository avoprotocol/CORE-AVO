use crate::error::{AvoError, AvoResult};
use crate::network::network_metrics::{AggregatedNetworkMetrics, NetworkMetricsCollector};
use crate::network::p2p::{ConnectionStatus, NetworkStats, P2PManager};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Umbrales para detección de particiones en la red
#[derive(Debug, Clone)]
pub struct PartitionThresholds {
    pub min_connected_peers: usize,
    pub max_average_latency_ms: f64,
    pub max_packet_loss_ratio: f64,
    pub min_bandwidth_mbps: f64,
    pub history_capacity: usize,
}

impl Default for PartitionThresholds {
    fn default() -> Self {
        Self {
            min_connected_peers: 4,
            max_average_latency_ms: 1_500.0,
            max_packet_loss_ratio: 0.2,
            min_bandwidth_mbps: 5.0,
            history_capacity: 128,
        }
    }
}

/// Eventos generados por el monitor de particiones
#[derive(Debug, Clone)]
pub enum PartitionEvent {
    Healthy,
    Detected {
        reason: String,
        metrics: AggregatedNetworkMetrics,
        stats: NetworkStats,
    },
    HealingAttempt {
        attempted: usize,
        succeeded: usize,
    },
    Healed {
        reconnected: usize,
    },
}

/// Monitor responsable de detectar y autocurar particiones de red
#[derive(Debug)]
pub struct PartitionMonitor {
    metrics: Arc<NetworkMetricsCollector>,
    thresholds: PartitionThresholds,
    history: Arc<RwLock<VecDeque<(SystemTime, PartitionEvent)>>>,
}

impl PartitionMonitor {
    pub fn new(metrics: Arc<NetworkMetricsCollector>, thresholds: PartitionThresholds) -> Self {
        Self {
            metrics,
            thresholds: thresholds.clone(),
            history: Arc::new(RwLock::new(VecDeque::with_capacity(
                thresholds.history_capacity,
            ))),
        }
    }

    /// Evalúa el estado de la red y, si es necesario, intenta curar particiones
    pub async fn evaluate_and_heal(
        &self,
        p2p: Option<Arc<P2PManager>>,
    ) -> AvoResult<Option<PartitionEvent>> {
        let network_metrics = self.metrics.get_network_metrics().await;
        let stats = if let Some(manager) = p2p.as_ref() {
            manager.get_stats().await
        } else {
            NetworkStats::default()
        };

        if let Some(event) = self.evaluate_metrics(&network_metrics, &stats) {
            self.push_history(event.clone()).await;
            match event {
                PartitionEvent::Detected { .. } => {
                    if let Some(manager) = p2p {
                        let (attempted, succeeded) = self.attempt_healing(manager.clone()).await?;
                        let healing_event = PartitionEvent::HealingAttempt {
                            attempted,
                            succeeded,
                        };
                        self.push_history(healing_event.clone()).await;
                        if succeeded > 0 {
                            let healed = PartitionEvent::Healed {
                                reconnected: succeeded,
                            };
                            self.push_history(healed.clone()).await;
                            return Ok(Some(healed));
                        }
                        return Ok(Some(healing_event));
                    }
                }
                PartitionEvent::Healthy => {
                    debug!("Network healthy, no partition detected");
                }
                _ => {}
            }
            return Ok(Some(event));
        }

        self.push_history(PartitionEvent::Healthy).await;
        Ok(Some(PartitionEvent::Healthy))
    }

    /// Analiza métricas y determina si existe partición
    pub fn evaluate_metrics(
        &self,
        metrics: &AggregatedNetworkMetrics,
        stats: &NetworkStats,
    ) -> Option<PartitionEvent> {
        if stats.peers_connected < self.thresholds.min_connected_peers {
            return Some(PartitionEvent::Detected {
                reason: format!(
                    "Peers conectados insuficientes ({} < {})",
                    stats.peers_connected, self.thresholds.min_connected_peers
                ),
                metrics: metrics.clone(),
                stats: stats.clone(),
            });
        }

        if metrics.average_latency_ms > self.thresholds.max_average_latency_ms {
            return Some(PartitionEvent::Detected {
                reason: format!(
                    "Latencia promedio alta: {:.2} ms",
                    metrics.average_latency_ms
                ),
                metrics: metrics.clone(),
                stats: stats.clone(),
            });
        }

        if metrics.packet_loss_ratio > self.thresholds.max_packet_loss_ratio {
            return Some(PartitionEvent::Detected {
                reason: format!("Packet loss elevado: {:.3}", metrics.packet_loss_ratio),
                metrics: metrics.clone(),
                stats: stats.clone(),
            });
        }

        if metrics.bandwidth_mbps_total < self.thresholds.min_bandwidth_mbps {
            return Some(PartitionEvent::Detected {
                reason: format!(
                    "Bandwidth total bajo: {:.2} Mbps",
                    metrics.bandwidth_mbps_total
                ),
                metrics: metrics.clone(),
                stats: stats.clone(),
            });
        }

        None
    }

    async fn attempt_healing(&self, manager: Arc<P2PManager>) -> AvoResult<(usize, usize)> {
        let peers = manager.get_peers().await;
        let disconnected: Vec<_> = peers
            .into_iter()
            .filter(|peer| peer.status != ConnectionStatus::Connected)
            .collect();

        if disconnected.is_empty() {
            return Ok((0, 0));
        }

        info!(
            "🔍 Partition detected - attempting to reconnect {} peers",
            disconnected.len()
        );

        let mut successes = 0;
        for peer in &disconnected {
            match manager.reconnect_peer(peer).await {
                Ok(_) => successes += 1,
                Err(err) => warn!("Failed to reconnect peer {}: {}", peer.id, err),
            }
        }

        Ok((disconnected.len(), successes))
    }

    async fn push_history(&self, event: PartitionEvent) {
        let mut history = self.history.write().await;
        if history.len() == self.thresholds.history_capacity {
            history.pop_front();
        }
        history.push_back((SystemTime::now(), event));
    }

    pub async fn recent_events(&self) -> Vec<(SystemTime, PartitionEvent)> {
        self.history.read().await.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_metrics(
        peers: usize,
        latency: f64,
        bandwidth: f64,
    ) -> (AggregatedNetworkMetrics, NetworkStats) {
        let metrics = AggregatedNetworkMetrics {
            bandwidth_mbps_out: bandwidth / 2.0,
            bandwidth_mbps_in: bandwidth / 2.0,
            bandwidth_mbps_total: bandwidth,
            average_latency_ms: latency,
            peak_latency_ms: latency,
            packet_loss_ratio: 0.0,
            connection_count: peers,
            bytes_per_second_out: 0.0,
            bytes_per_second_in: 0.0,
            measurement_period_secs: 10,
        };
        let stats = NetworkStats {
            peers_connected: peers,
            ..Default::default()
        };
        (metrics, stats)
    }

    #[tokio::test]
    async fn detects_partition_by_peer_count() {
        let metrics_collector = Arc::new(NetworkMetricsCollector::new(Default::default()));
        let monitor = PartitionMonitor::new(metrics_collector, PartitionThresholds::default());
        let (metrics, stats) = build_metrics(1, 10.0, 50.0);
        let result = monitor.evaluate_metrics(&metrics, &stats);
        assert!(matches!(result, Some(PartitionEvent::Detected { .. })));
    }

    #[tokio::test]
    async fn healthy_network_returns_none() {
        let metrics_collector = Arc::new(NetworkMetricsCollector::new(Default::default()));
        let monitor = PartitionMonitor::new(metrics_collector, PartitionThresholds::default());
        let (metrics, stats) = build_metrics(5, 10.0, 50.0);
        let result = monitor.evaluate_metrics(&metrics, &stats);
        assert!(result.is_none());
    }
}
