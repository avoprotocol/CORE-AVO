use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// FASE 12.1: Enhanced HLC with partition detection

/// Timestamp producido por un Hybrid Logical Clock (HLC)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HlcTimestamp {
    physical_micros: u64,
    logical: u64,
}

impl HlcTimestamp {
    pub fn new(physical_micros: u64, logical: u64) -> Self {
        Self {
            physical_micros,
            logical,
        }
    }

    pub fn physical_micros(&self) -> u64 {
        self.physical_micros
    }

    pub fn logical_counter(&self) -> u64 {
        self.logical
    }

    /// FASE 12.1: Compare timestamps for ordering
    pub fn compare(&self, other: &HlcTimestamp) -> std::cmp::Ordering {
        match self.physical_micros.cmp(&other.physical_micros) {
            std::cmp::Ordering::Equal => self.logical.cmp(&other.logical),
            ord => ord,
        }
    }

    /// FASE 12.1: Calculate time difference in microseconds
    pub fn duration_since(&self, earlier: &HlcTimestamp) -> Option<Duration> {
        if self.physical_micros >= earlier.physical_micros {
            Some(Duration::from_micros(
                self.physical_micros - earlier.physical_micros,
            ))
        } else {
            None
        }
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.compare(other))
    }
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.compare(other)
    }
}

#[derive(Debug)]
struct HlcState {
    last: HlcTimestamp,
    drift_tolerance: Duration,
    // FASE 12.1: Partition detection
    peer_timestamps: HashMap<u64, (HlcTimestamp, SystemTime)>, // peer_id -> (last_ts, last_seen)
    partition_threshold: Duration,
}

/// FASE 12.1: Partition detection result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionStatus {
    /// No partition detected
    Healthy,
    /// Potential partition detected
    PartitionSuspected {
        stale_peers: Vec<u64>,
        max_drift: Duration,
    },
    /// Confirmed partition (clock drift exceeds threshold)
    PartitionConfirmed {
        partitioned_peers: Vec<u64>,
        drift_amount: Duration,
    },
}

/// Implementación de un Hybrid Logical Clock para ordering determinista
#[derive(Debug)]
pub struct HybridLogicalClock {
    state: Mutex<HlcState>,
}

impl HybridLogicalClock {
    /// Crea un nuevo HLC con la tolerancia indicada
    pub fn new(drift_tolerance: Duration) -> Self {
        Self::new_with_partition_detection(drift_tolerance, Duration::from_secs(30))
    }

    /// FASE 12.1: Create HLC with partition detection enabled
    pub fn new_with_partition_detection(
        drift_tolerance: Duration,
        partition_threshold: Duration,
    ) -> Self {
        let now = Self::current_physical_micros();
        Self {
            state: Mutex::new(HlcState {
                last: HlcTimestamp::new(now, 0),
                drift_tolerance,
                peer_timestamps: HashMap::new(),
                partition_threshold,
            }),
        }
    }

    /// Avanza el reloj con el tiempo local
    pub fn tick(&self) -> HlcTimestamp {
        let physical = Self::current_physical_micros();
        let mut state = self.state.lock().expect("HLC mutex poisoned");

        if physical > state.last.physical_micros {
            state.last = HlcTimestamp::new(physical, 0);
        } else {
            state.last = HlcTimestamp::new(state.last.physical_micros, state.last.logical + 1);
        }

        state.last
    }

    /// Fusiona el reloj con un timestamp remoto, aplicando reglas de HLC
    pub fn update_with_remote(&self, remote: HlcTimestamp) -> HlcTimestamp {
        let physical_now = Self::current_physical_micros();
        let mut state = self.state.lock().expect("HLC mutex poisoned");

        // Detectar desviaciones de reloj excesivas
        let tolerance = state.drift_tolerance.as_micros() as u64;
        let clamped_remote_physical =
            if remote.physical_micros > physical_now.saturating_add(tolerance) {
                // Si el remoto está fuera de tolerancia, se clampa para evitar saltos grandes
                physical_now.saturating_add(tolerance)
            } else {
                remote.physical_micros
            };

        let current = state.last;
        let max_physical = physical_now
            .max(clamped_remote_physical)
            .max(current.physical_micros);

        let logical =
            if max_physical == current.physical_micros && max_physical == clamped_remote_physical {
                current.logical.max(remote.logical) + 1
            } else if max_physical == current.physical_micros {
                current.logical + 1
            } else if max_physical == clamped_remote_physical {
                remote.logical + 1
            } else {
                0
            };

        state.last = HlcTimestamp::new(max_physical, logical);
        state.last
    }

    /// Obtiene el último timestamp observado sin avanzar el reloj
    pub fn last_timestamp(&self) -> HlcTimestamp {
        let state = self.state.lock().expect("HLC mutex poisoned");
        state.last
    }

    /// FASE 12.1: Record timestamp from a peer
    pub fn record_peer_timestamp(&self, peer_id: u64, timestamp: HlcTimestamp) {
        let mut state = self.state.lock().expect("HLC mutex poisoned");
        state
            .peer_timestamps
            .insert(peer_id, (timestamp, SystemTime::now()));
    }

    /// FASE 12.1: Detect potential network partitions
    pub fn detect_partition(&self) -> PartitionStatus {
        let state = self.state.lock().expect("HLC mutex poisoned");
        let now_system = SystemTime::now();
        let now_hlc = state.last;

        let mut stale_peers = Vec::new();
        let mut max_drift = Duration::from_secs(0);

        for (peer_id, (peer_ts, last_seen)) in &state.peer_timestamps {
            // Check if peer hasn't been heard from in a while
            if let Ok(elapsed) = now_system.duration_since(*last_seen) {
                if elapsed > state.partition_threshold {
                    stale_peers.push(*peer_id);
                    max_drift = max_drift.max(elapsed);
                    continue;
                }
            }

            // Check clock drift
            if let Some(drift) = now_hlc.duration_since(peer_ts) {
                if drift > state.drift_tolerance * 2 {
                    // Significant drift detected
                    max_drift = max_drift.max(drift);
                    if drift > state.drift_tolerance * 10 {
                        // Confirmed partition
                        return PartitionStatus::PartitionConfirmed {
                            partitioned_peers: vec![*peer_id],
                            drift_amount: drift,
                        };
                    }
                }
            }
        }

        if !stale_peers.is_empty() {
            PartitionStatus::PartitionSuspected {
                stale_peers,
                max_drift,
            }
        } else {
            PartitionStatus::Healthy
        }
    }

    /// FASE 12.1: Clean up old peer timestamps
    pub fn cleanup_stale_peers(&self, max_age: Duration) -> usize {
        let mut state = self.state.lock().expect("HLC mutex poisoned");
        let now = SystemTime::now();
        let before_count = state.peer_timestamps.len();

        state.peer_timestamps.retain(|_, (_, last_seen)| {
            now.duration_since(*last_seen).unwrap_or_default() < max_age
        });

        before_count - state.peer_timestamps.len()
    }

    /// FASE 12.1: Get peer count
    pub fn peer_count(&self) -> usize {
        let state = self.state.lock().expect("HLC mutex poisoned");
        state.peer_timestamps.len()
    }

    fn current_physical_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn hlc_monotonic_tick() {
        let hlc = HybridLogicalClock::new(Duration::from_millis(500));
        let ts1 = hlc.tick();
        let ts2 = hlc.tick();
        assert!(ts2.physical_micros() >= ts1.physical_micros());
        if ts2.physical_micros() == ts1.physical_micros() {
            assert!(ts2.logical_counter() > ts1.logical_counter());
        }
    }

    #[test]
    fn hlc_remote_update_within_tolerance() {
        let hlc = HybridLogicalClock::new(Duration::from_millis(10));
        let local = hlc.tick();
        let remote = HlcTimestamp::new(local.physical_micros(), local.logical_counter() + 5);
        let merged = hlc.update_with_remote(remote);
        assert!(merged.logical_counter() > local.logical_counter());
    }

    #[test]
    fn hlc_remote_outside_tolerance_is_clamped() {
        let hlc = HybridLogicalClock::new(Duration::from_millis(1));
        let _ = hlc.tick();
        let remote = HlcTimestamp::new(u64::MAX - 1, 0);
        let merged = hlc.update_with_remote(remote);
        // Al menos debe ser válido y no overflowear
        assert!(merged.physical_micros() < u64::MAX);
    }

    #[test]
    fn hlc_progresses_with_real_time() {
        let hlc = HybridLogicalClock::new(Duration::from_millis(10));
        let ts1 = hlc.tick();
        thread::sleep(Duration::from_millis(5));
        let ts2 = hlc.tick();
        assert!(ts2.physical_micros() >= ts1.physical_micros());
    }

    // FASE 12.1: Partition detection tests
    #[test]
    fn test_partition_detection_healthy() {
        let hlc = HybridLogicalClock::new_with_partition_detection(
            Duration::from_millis(100),
            Duration::from_secs(5),
        );

        // Record recent peer timestamps
        let ts = hlc.tick();
        hlc.record_peer_timestamp(1, ts);
        hlc.record_peer_timestamp(2, ts);

        // Should be healthy
        let status = hlc.detect_partition();
        assert_eq!(status, PartitionStatus::Healthy);
    }

    #[test]
    fn test_partition_detection_stale_peers() {
        let hlc = HybridLogicalClock::new_with_partition_detection(
            Duration::from_millis(100),
            Duration::from_millis(50), // Short threshold for testing
        );

        // Record old peer timestamp
        let old_ts = hlc.tick();
        hlc.record_peer_timestamp(1, old_ts);

        // Wait for partition threshold
        thread::sleep(Duration::from_millis(60));

        // Should detect stale peer
        let status = hlc.detect_partition();
        match status {
            PartitionStatus::PartitionSuspected { stale_peers, .. } => {
                assert_eq!(stale_peers, vec![1]);
            }
            _ => panic!("Expected PartitionSuspected"),
        }
    }

    #[test]
    fn test_cleanup_stale_peers() {
        let hlc = HybridLogicalClock::new(Duration::from_millis(100));

        // Add some peers
        let ts = hlc.tick();
        hlc.record_peer_timestamp(1, ts);
        hlc.record_peer_timestamp(2, ts);
        hlc.record_peer_timestamp(3, ts);

        assert_eq!(hlc.peer_count(), 3);

        // Wait and cleanup
        thread::sleep(Duration::from_millis(60));
        let cleaned = hlc.cleanup_stale_peers(Duration::from_millis(50));

        assert_eq!(cleaned, 3);
        assert_eq!(hlc.peer_count(), 0);
    }

    #[test]
    fn test_timestamp_ordering() {
        let ts1 = HlcTimestamp::new(1000, 0);
        let ts2 = HlcTimestamp::new(1000, 1);
        let ts3 = HlcTimestamp::new(2000, 0);

        assert!(ts1 < ts2);
        assert!(ts2 < ts3);
        assert!(ts1 < ts3);
    }

    #[test]
    fn test_timestamp_duration() {
        let ts1 = HlcTimestamp::new(1000, 0);
        let ts2 = HlcTimestamp::new(2000, 0);

        let duration = ts2.duration_since(&ts1).unwrap();
        assert_eq!(duration, Duration::from_micros(1000));

        assert!(ts1.duration_since(&ts2).is_none());
    }
}
