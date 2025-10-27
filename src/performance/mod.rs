use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use crate::types::Epoch;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub block_number: u64,
    pub epoch: Epoch,
    pub tx_count: usize,
    pub total_gas_used: u64,
    pub vm_execution_ms: u128,
    pub total_processing_ms: u128,
    pub timestamp_micros: u64,
}

impl PerformanceSnapshot {
    pub fn transactions_per_second(&self) -> f64 {
        if self.total_processing_ms == 0 {
            return 0.0;
        }
        let seconds = self.total_processing_ms as f64 / 1_000.0;
        if seconds <= f64::EPSILON {
            return 0.0;
        }
        self.tx_count as f64 / seconds
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PerformanceAggregate {
    pub samples: usize,
    pub avg_tps: f64,
    pub avg_vm_execution_ms: f64,
    pub avg_block_time_ms: f64,
    pub avg_gas_per_block: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub generated_at_micros: u64,
    pub samples_available: usize,
    pub aggregate: PerformanceAggregate,
    pub latest: Option<PerformanceSnapshot>,
    pub recent: Vec<PerformanceSnapshot>,
}

impl PerformanceReport {
    pub fn has_samples(&self) -> bool {
        self.samples_available > 0
    }
}

pub struct PerformanceTracker {
    history: RwLock<VecDeque<PerformanceSnapshot>>,
    max_samples: usize,
}

impl PerformanceTracker {
    pub fn new(max_samples: usize) -> Self {
        Self {
            history: RwLock::new(VecDeque::with_capacity(max_samples)),
            max_samples,
        }
    }

    pub async fn record(&self, snapshot: PerformanceSnapshot) {
        let mut history = self.history.write().await;
        if history.len() == self.max_samples {
            history.pop_front();
        }
        history.push_back(snapshot);
    }

    pub async fn recent(&self, limit: usize) -> Vec<PerformanceSnapshot> {
        let history = self.history.read().await;
        history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
    }

    pub async fn aggregate(&self) -> PerformanceAggregate {
        self.report(self.max_samples).await.aggregate
    }

    pub async fn report(&self, limit: usize) -> PerformanceReport {
        let limit = limit.max(1);
        let history = self.history.read().await;
        let samples_available = history.len();
        let aggregate = compute_aggregate(&history);
        let recent = history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let latest = recent.first().cloned();
        let generated_at_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros().min(u64::MAX as u128) as u64)
            .unwrap_or(0);

        PerformanceReport {
            generated_at_micros,
            samples_available,
            aggregate,
            latest,
            recent,
        }
    }
}

pub struct BenchmarkRunner {
    tracker: Arc<PerformanceTracker>,
    warmup_duration: Duration,
    measurement_duration: Duration,
}

impl BenchmarkRunner {
    pub fn new(
        tracker: Arc<PerformanceTracker>,
        warmup_duration: Duration,
        measurement_duration: Duration,
    ) -> Self {
        Self {
            tracker,
            warmup_duration,
            measurement_duration,
        }
    }

    /// Obtiene un resumen de métricas acumuladas hasta el momento.
    pub async fn summary(&self) -> PerformanceAggregate {
        self.tracker.aggregate().await
    }

    /// Devuelve los últimos `limit` snapshots para análisis fino.
    pub async fn recent_snapshots(&self, limit: usize) -> Vec<PerformanceSnapshot> {
        self.tracker.recent(limit).await
    }

    /// En futuras iteraciones ejecutará escenarios sintéticos; por ahora devuelve la configuración.
    pub fn window(&self) -> (Duration, Duration) {
        (self.warmup_duration, self.measurement_duration)
    }
}

fn compute_aggregate(history: &VecDeque<PerformanceSnapshot>) -> PerformanceAggregate {
    if history.is_empty() {
        return PerformanceAggregate::default();
    }

    let mut aggregate = PerformanceAggregate {
        samples: history.len(),
        ..Default::default()
    };

    let mut total_tps = 0.0;
    let mut total_vm_ms = 0.0;
    let mut total_block_ms = 0.0;
    let mut total_gas = 0.0;

    for snapshot in history.iter() {
        total_tps += snapshot.transactions_per_second();
        total_vm_ms += snapshot.vm_execution_ms as f64;
        total_block_ms += snapshot.total_processing_ms as f64;
        total_gas += snapshot.total_gas_used as f64;
    }

    let samples = history.len() as f64;
    aggregate.avg_tps = total_tps / samples;
    aggregate.avg_vm_execution_ms = total_vm_ms / samples;
    aggregate.avg_block_time_ms = total_block_ms / samples;
    aggregate.avg_gas_per_block = total_gas / samples;

    aggregate
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(
        block_number: u64,
        tx_count: usize,
        total_gas: u64,
        vm_ms: u128,
        block_ms: u128,
    ) -> PerformanceSnapshot {
        PerformanceSnapshot {
            block_number,
            epoch: block_number,
            tx_count,
            total_gas_used: total_gas,
            vm_execution_ms: vm_ms,
            total_processing_ms: block_ms,
            timestamp_micros: block_number * 1_000_000,
        }
    }

    #[tokio::test]
    async fn computes_transactions_per_second() {
        let snapshot = make_snapshot(1, 20, 10_000, 400, 1_000);
        assert!((snapshot.transactions_per_second() - 20.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn tracker_produces_reports() {
        let tracker = PerformanceTracker::new(10);

        tracker
            .record(make_snapshot(1, 10, 5_000, 300, 1_000))
            .await;
        tracker.record(make_snapshot(2, 20, 8_000, 500, 900)).await;

        let report = tracker.report(5).await;
        assert!(report.has_samples());
        assert_eq!(report.samples_available, 2);
        assert_eq!(report.recent.len(), 2);
        assert!(report.latest.is_some());
        let aggregate = report.aggregate;
        assert_eq!(aggregate.samples, 2);
        assert!(aggregate.avg_tps > 0.0);
    }
}
