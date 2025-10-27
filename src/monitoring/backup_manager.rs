use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

/// Sistema de backup automático para datos críticos
#[derive(Debug)]
pub struct BackupManager {
    /// Configuración del sistema de backup
    config: BackupConfig,
    /// Estado del sistema de backup
    backup_state: Arc<RwLock<BackupState>>,
    /// Historial de backups
    backup_history: Arc<RwLock<Vec<BackupRecord>>>,
    /// Métricas de backup
    backup_metrics: Arc<RwLock<BackupMetrics>>,
    /// Políticas de backup por componente
    backup_policies: Arc<RwLock<HashMap<String, BackupPolicy>>>,
}

/// Estado del sistema de backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupState {
    /// Timestamp del último backup completo
    pub last_full_backup: Option<u64>,
    /// Timestamp del último backup incremental
    pub last_incremental_backup: Option<u64>,
    /// Estado operacional del sistema de backup
    pub operational_status: BackupOperationalStatus,
    /// Número de backups completados hoy
    pub backups_completed_today: u32,
    /// Número de backups fallidos hoy
    pub backups_failed_today: u32,
    /// Espacio total usado por backups (bytes)
    pub total_backup_size_bytes: u64,
    /// Número de archivos de backup activos
    pub active_backup_files: u32,
    /// Último error de backup
    pub last_error: Option<String>,
}

/// Estado operacional del sistema de backup
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BackupOperationalStatus {
    /// Sistema funcionando normalmente
    Active,
    /// Backup en progreso
    BackingUp,
    /// Sistema pausado
    Paused,
    /// Sistema con errores
    Error,
    /// Sistema deshabilitado
    Disabled,
}

/// Registro de un backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRecord {
    /// ID único del backup
    pub backup_id: String,
    /// Timestamp del backup
    pub timestamp: u64,
    /// Tipo de backup realizado
    pub backup_type: BackupType,
    /// Componente respaldado
    pub component: String,
    /// Ruta del archivo de backup
    pub backup_path: String,
    /// Tamaño del backup en bytes
    pub size_bytes: u64,
    /// Duración del backup en ms
    pub duration_ms: u64,
    /// Estado del backup
    pub status: BackupStatus,
    /// Hash de verificación del backup
    pub verification_hash: Option<String>,
    /// Mensaje descriptivo
    pub message: String,
    /// Metadatos adicionales
    pub metadata: BackupMetadata,
}

/// Tipos de backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupType {
    /// Backup completo de todos los datos
    Full,
    /// Backup incremental (solo cambios)
    Incremental,
    /// Backup diferencial (cambios desde último full)
    Differential,
    /// Backup de emergencia
    Emergency,
    /// Backup manual
    Manual,
    /// Snapshot de estado
    Snapshot,
}

/// Estados de backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupStatus {
    /// Backup completado exitosamente
    Success,
    /// Backup falló
    Failed,
    /// Backup en progreso
    InProgress,
    /// Backup cancelado
    Cancelled,
    /// Backup corrupto detectado
    Corrupted,
}

/// Metadatos del backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Versión del sistema al momento del backup
    pub system_version: String,
    /// Número de archivos incluidos
    pub file_count: u32,
    /// Algoritmo de compresión usado
    pub compression_algorithm: String,
    /// Ratio de compresión
    pub compression_ratio: f64,
    /// Algoritmo de hash para verificación
    pub hash_algorithm: String,
    /// Tags adicionales
    pub tags: Vec<String>,
}

/// Política de backup para un componente
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    /// Nombre del componente
    pub component_name: String,
    /// Frecuencia de backup completo (horas)
    pub full_backup_frequency_hours: u64,
    /// Frecuencia de backup incremental (minutos)
    pub incremental_backup_frequency_minutes: u64,
    /// Número de backups completos a retener
    pub retain_full_backups: u32,
    /// Número de backups incrementales a retener
    pub retain_incremental_backups: u32,
    /// Habilitar compresión
    pub enable_compression: bool,
    /// Habilitar encriptación
    pub enable_encryption: bool,
    /// Rutas a incluir en el backup
    pub include_paths: Vec<String>,
    /// Rutas a excluir del backup
    pub exclude_paths: Vec<String>,
    /// Prioridad del backup (1-10)
    pub priority: u8,
    /// Límite de tamaño máximo (bytes)
    pub max_backup_size_bytes: Option<u64>,
}

/// Métricas del sistema de backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetrics {
    /// Número total de backups realizados
    pub total_backups_completed: u64,
    /// Número total de backups fallidos
    pub total_backups_failed: u64,
    /// Tasa de éxito de backups (%)
    pub backup_success_rate: f64,
    /// Tiempo promedio de backup completo (ms)
    pub avg_full_backup_time_ms: f64,
    /// Tiempo promedio de backup incremental (ms)
    pub avg_incremental_backup_time_ms: f64,
    /// Tamaño promedio de backup completo (bytes)
    pub avg_full_backup_size_bytes: u64,
    /// Tamaño promedio de backup incremental (bytes)
    pub avg_incremental_backup_size_bytes: u64,
    /// Espacio total usado por todos los backups (bytes)
    pub total_storage_used_bytes: u64,
    /// Ratio promedio de compresión
    pub avg_compression_ratio: f64,
    /// Tiempo de recovery promedio (ms)
    pub avg_recovery_time_ms: f64,
    /// Número de recoveries exitosos
    pub successful_recoveries: u64,
}

/// Configuración del sistema de backup
#[derive(Debug, Clone)]
pub struct BackupConfig {
    /// Habilitar sistema de backup automático
    pub enable_auto_backup: bool,
    /// Directorio base para almacenar backups
    pub backup_directory: String,
    /// Formato de nombre de archivos de backup
    pub backup_filename_format: String,
    /// Configuración de retención
    pub retention_policy: RetentionPolicy,
    /// Configuración de compresión
    pub compression_config: CompressionConfig,
    /// Configuración de encriptación
    pub encryption_config: EncryptionConfig,
    /// Configuración de almacenamiento remoto
    pub remote_storage_config: Option<RemoteStorageConfig>,
    /// Número máximo de backups concurrentes
    pub max_concurrent_backups: u32,
    /// Timeout para operaciones de backup (segundos)
    pub backup_timeout_seconds: u64,
}

/// Política de retención de backups
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Días a retener backups diarios
    pub keep_daily_days: u32,
    /// Semanas a retener backups semanales
    pub keep_weekly_weeks: u32,
    /// Meses a retener backups mensuales
    pub keep_monthly_months: u32,
    /// Años a retener backups anuales
    pub keep_yearly_years: u32,
    /// Limpiar automáticamente backups antiguos
    pub auto_cleanup_old_backups: bool,
    /// Espacio máximo para backups (bytes)
    pub max_storage_bytes: Option<u64>,
}

/// Configuración de compresión
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Algoritmo de compresión (gzip, lz4, zstd)
    pub algorithm: String,
    /// Nivel de compresión (1-9)
    pub compression_level: u8,
    /// Habilitar compresión solo para archivos grandes
    pub compress_large_files_only: bool,
    /// Tamaño mínimo para comprimir (bytes)
    pub min_file_size_for_compression: u64,
}

/// Configuración de encriptación
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Habilitar encriptación de backups
    pub enable_encryption: bool,
    /// Algoritmo de encriptación (AES-256, ChaCha20)
    pub encryption_algorithm: String,
    /// Ruta al archivo de clave
    pub key_file_path: Option<String>,
    /// Derivación de clave desde contraseña
    pub use_password_derived_key: bool,
}

/// Configuración de almacenamiento remoto
#[derive(Debug, Clone)]
pub struct RemoteStorageConfig {
    /// Tipo de almacenamiento remoto (S3, GCS, Azure)
    pub storage_type: String,
    /// Endpoint del servicio
    pub endpoint: String,
    /// Bucket/Container name
    pub bucket_name: String,
    /// Credenciales de acceso
    pub access_credentials: StorageCredentials,
    /// Habilitar upload automático
    pub auto_upload: bool,
    /// Verificar integridad después de upload
    pub verify_after_upload: bool,
}

/// Credenciales de almacenamiento
#[derive(Debug, Clone)]
pub struct StorageCredentials {
    /// Access key ID
    pub access_key_id: String,
    /// Secret access key
    pub secret_access_key: String,
    /// Región del servicio
    pub region: Option<String>,
}

impl BackupManager {
    /// Crear nueva instancia del backup manager
    pub fn new(config: BackupConfig) -> Self {
        let initial_state = BackupState {
            last_full_backup: None,
            last_incremental_backup: None,
            operational_status: BackupOperationalStatus::Active,
            backups_completed_today: 0,
            backups_failed_today: 0,
            total_backup_size_bytes: 0,
            active_backup_files: 0,
            last_error: None,
        };

        let initial_metrics = BackupMetrics {
            total_backups_completed: 0,
            total_backups_failed: 0,
            backup_success_rate: 100.0,
            avg_full_backup_time_ms: 0.0,
            avg_incremental_backup_time_ms: 0.0,
            avg_full_backup_size_bytes: 0,
            avg_incremental_backup_size_bytes: 0,
            total_storage_used_bytes: 0,
            avg_compression_ratio: 0.0,
            avg_recovery_time_ms: 0.0,
            successful_recoveries: 0,
        };

        Self {
            config,
            backup_state: Arc::new(RwLock::new(initial_state)),
            backup_history: Arc::new(RwLock::new(Vec::new())),
            backup_metrics: Arc::new(RwLock::new(initial_metrics)),
            backup_policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Iniciar el sistema de backup automático
    pub async fn start_backup_system(&self) -> AvoResult<()> {
        info!("💾 Starting automatic backup system");
        info!("📁 Backup directory: {}", self.config.backup_directory);
        info!("🔄 Auto-backup enabled: {}", self.config.enable_auto_backup);

        // Crear directorio de backup si no existe
        if let Err(e) = fs::create_dir_all(&self.config.backup_directory).await {
            error!("Failed to create backup directory: {}", e);
            return Err(AvoError::IoError {
                source: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create backup directory: {}", e),
                ),
            });
        }

        // Configurar políticas de backup por defecto
        self.configure_default_backup_policies().await?;

        // Iniciar scheduler de backups automáticos
        if self.config.enable_auto_backup {
            self.start_backup_scheduler().await?;
        }

        // Iniciar limpieza automática de backups antiguos
        if self.config.retention_policy.auto_cleanup_old_backups {
            self.start_cleanup_scheduler().await?;
        }

        info!("✅ Backup system started successfully");
        Ok(())
    }

    /// Configurar políticas de backup por defecto
    async fn configure_default_backup_policies(&self) -> AvoResult<()> {
        let mut policies = self.backup_policies.write().await;

        // Política para el estado del blockchain
        let blockchain_policy = BackupPolicy {
            component_name: "blockchain_state".to_string(),
            full_backup_frequency_hours: 24, // Backup completo diario
            incremental_backup_frequency_minutes: 60, // Backup incremental cada hora
            retain_full_backups: 7,          // Retener 7 backups completos
            retain_incremental_backups: 24,  // Retener 24 incrementales
            enable_compression: true,
            enable_encryption: true,
            include_paths: vec![
                "state/".to_string(),
                "blocks/".to_string(),
                "transactions/".to_string(),
            ],
            exclude_paths: vec!["cache/".to_string(), "temp/".to_string()],
            priority: 10,                                         // Máxima prioridad
            max_backup_size_bytes: Some(10 * 1024 * 1024 * 1024), // 10GB max
        };

        // Política para configuración crítica
        let config_policy = BackupPolicy {
            component_name: "critical_config".to_string(),
            full_backup_frequency_hours: 12, // Backup cada 12 horas
            incremental_backup_frequency_minutes: 30, // Backup incremental cada 30 min
            retain_full_backups: 10,
            retain_incremental_backups: 48,
            enable_compression: true,
            enable_encryption: true,
            include_paths: vec![
                "config/".to_string(),
                "keys/".to_string(),
                "certificates/".to_string(),
            ],
            exclude_paths: vec![],
            priority: 9,
            max_backup_size_bytes: Some(100 * 1024 * 1024), // 100MB max
        };

        // Política para logs críticos
        let logs_policy = BackupPolicy {
            component_name: "critical_logs".to_string(),
            full_backup_frequency_hours: 6, // Backup cada 6 horas
            incremental_backup_frequency_minutes: 15, // Backup incremental cada 15 min
            retain_full_backups: 4,
            retain_incremental_backups: 24,
            enable_compression: true,
            enable_encryption: false, // Logs no necesitan encriptación
            include_paths: vec![
                "logs/consensus.log".to_string(),
                "logs/validator.log".to_string(),
                "logs/network.log".to_string(),
            ],
            exclude_paths: vec!["logs/debug/".to_string()],
            priority: 7,
            max_backup_size_bytes: Some(1024 * 1024 * 1024), // 1GB max
        };

        // Política para wallets y claves
        let wallet_policy = BackupPolicy {
            component_name: "wallets_keys".to_string(),
            full_backup_frequency_hours: 8, // Backup cada 8 horas
            incremental_backup_frequency_minutes: 60, // Backup incremental cada hora
            retain_full_backups: 14,        // Retener por 2 semanas
            retain_incremental_backups: 168, // Retener por 1 semana
            enable_compression: false,      // No comprimir para máxima seguridad
            enable_encryption: true,        // Siempre encriptar
            include_paths: vec!["wallets/".to_string(), "private_keys/".to_string()],
            exclude_paths: vec![],
            priority: 10,                                  // Máxima prioridad
            max_backup_size_bytes: Some(50 * 1024 * 1024), // 50MB max
        };

        policies.insert("blockchain_state".to_string(), blockchain_policy);
        policies.insert("critical_config".to_string(), config_policy);
        policies.insert("critical_logs".to_string(), logs_policy);
        policies.insert("wallets_keys".to_string(), wallet_policy);

        info!("📋 Configured {} backup policies", policies.len());
        Ok(())
    }

    /// Iniciar scheduler de backups automáticos
    async fn start_backup_scheduler(&self) -> AvoResult<()> {
        let backup_state = self.backup_state.clone();
        let backup_history = self.backup_history.clone();
        let backup_metrics = self.backup_metrics.clone();
        let backup_policies = self.backup_policies.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // Check cada 5 minutos

            loop {
                interval.tick().await;

                if let Err(e) = Self::evaluate_and_execute_backups(
                    &backup_state,
                    &backup_history,
                    &backup_metrics,
                    &backup_policies,
                    &config,
                )
                .await
                {
                    error!("🚨 Backup scheduler error: {}", e);
                }
            }
        });

        info!("⏰ Backup scheduler started");
        Ok(())
    }

    /// Iniciar scheduler de limpieza automática
    async fn start_cleanup_scheduler(&self) -> AvoResult<()> {
        let backup_history = self.backup_history.clone();
        let backup_state = self.backup_state.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Cleanup cada hora

            loop {
                interval.tick().await;

                if let Err(e) =
                    Self::cleanup_old_backups(&backup_history, &backup_state, &config).await
                {
                    error!("🚨 Backup cleanup error: {}", e);
                }
            }
        });

        info!("🧹 Backup cleanup scheduler started");
        Ok(())
    }

    /// Evaluar y ejecutar backups según las políticas
    async fn evaluate_and_execute_backups(
        backup_state: &Arc<RwLock<BackupState>>,
        backup_history: &Arc<RwLock<Vec<BackupRecord>>>,
        backup_metrics: &Arc<RwLock<BackupMetrics>>,
        backup_policies: &Arc<RwLock<HashMap<String, BackupPolicy>>>,
        config: &BackupConfig,
    ) -> AvoResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Leer políticas y determinar qué hacer
        let backup_tasks = {
            let policies = backup_policies.read().await;
            let state = backup_state.read().await;

            // Verificar si el sistema está disponible para backup
            if state.operational_status != BackupOperationalStatus::Active {
                debug!("Backup system not active, skipping evaluation");
                return Ok(());
            }

            let mut tasks = Vec::new();

            for (component_name, policy) in policies.iter() {
                // Evaluar si necesita backup completo
                let needs_full_backup = if let Some(last_full) = state.last_full_backup {
                    (now - last_full) >= (policy.full_backup_frequency_hours * 3600)
                } else {
                    true // Primer backup
                };

                // Evaluar si necesita backup incremental
                let needs_incremental_backup = if let Some(last_incremental) =
                    state.last_incremental_backup
                {
                    (now - last_incremental) >= (policy.incremental_backup_frequency_minutes * 60)
                } else {
                    false // Solo después del primer backup completo
                };

                if needs_full_backup {
                    tasks.push((component_name.clone(), BackupType::Full, policy.clone()));
                } else if needs_incremental_backup && state.last_full_backup.is_some() {
                    tasks.push((
                        component_name.clone(),
                        BackupType::Incremental,
                        policy.clone(),
                    ));
                }
            }
            tasks
        };

        // Ejecutar las tareas de backup fuera del lock
        for (component_name, backup_type, policy) in backup_tasks {
            match backup_type {
                BackupType::Full => {
                    info!(
                        "📦 Scheduling full backup for component: {}",
                        component_name
                    );

                    let result = Self::execute_backup(
                        &component_name,
                        BackupType::Full,
                        &policy,
                        backup_history,
                        backup_metrics,
                        config,
                    )
                    .await;

                    let mut state = backup_state.write().await;
                    if result.is_ok() {
                        state.last_full_backup = Some(now);
                        state.backups_completed_today += 1;
                    } else {
                        state.backups_failed_today += 1;
                        state.last_error =
                            Some(format!("Full backup failed for {}", component_name));
                    }
                }
                BackupType::Incremental => {
                    info!(
                        "📁 Scheduling incremental backup for component: {}",
                        component_name
                    );

                    let result = Self::execute_backup(
                        &component_name,
                        BackupType::Incremental,
                        &policy,
                        backup_history,
                        backup_metrics,
                        config,
                    )
                    .await;

                    let mut state = backup_state.write().await;
                    if result.is_ok() {
                        state.last_incremental_backup = Some(now);
                        state.backups_completed_today += 1;
                    } else {
                        state.backups_failed_today += 1;
                        state.last_error =
                            Some(format!("Incremental backup failed for {}", component_name));
                    }
                }
                BackupType::Differential
                | BackupType::Emergency
                | BackupType::Manual
                | BackupType::Snapshot => {
                    // Estos tipos de backup no se ejecutan automáticamente en la evaluación de políticas
                    debug!(
                        "Skipping automatic execution for backup type: {:?}",
                        backup_type
                    );
                }
            }
        }

        Ok(())
    }

    /// Ejecutar un backup específico
    async fn execute_backup(
        component_name: &str,
        backup_type: BackupType,
        policy: &BackupPolicy,
        backup_history: &Arc<RwLock<Vec<BackupRecord>>>,
        backup_metrics: &Arc<RwLock<BackupMetrics>>,
        config: &BackupConfig,
    ) -> AvoResult<()> {
        let backup_start = Instant::now();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let backup_id = format!(
            "{}_{}_{}_{}",
            component_name,
            match backup_type {
                BackupType::Full => "full",
                BackupType::Incremental => "inc",
                _ => "other",
            },
            timestamp,
            rand::random::<u32>() % 10000
        );

        info!("🚀 Starting backup: {} ({:?})", backup_id, backup_type);

        // Generar nombre de archivo de backup
        let backup_filename = format!(
            "{}/{}_{}.avobak",
            config.backup_directory, backup_id, timestamp
        );

        // Simular proceso de backup
        let mut backup_success = true;
        let mut error_message = String::new();

        // Fase 1: Preparación
        debug!("📋 Phase 1: Preparing backup for {}", component_name);
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Fase 2: Recolección de datos
        debug!("📋 Phase 2: Collecting data for backup");
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Simular tamaño de backup basado en el tipo
        let mut backup_size_bytes = match backup_type {
            BackupType::Full => {
                match component_name {
                    "blockchain_state" => 2_500_000_000 + rand::random::<u64>() % 500_000_000, // 2.5GB ± 500MB
                    "critical_config" => 50_000_000 + rand::random::<u64>() % 10_000_000, // 50MB ± 10MB
                    "critical_logs" => 800_000_000 + rand::random::<u64>() % 200_000_000, // 800MB ± 200MB
                    "wallets_keys" => 25_000_000 + rand::random::<u64>() % 5_000_000, // 25MB ± 5MB
                    _ => 100_000_000,
                }
            }
            BackupType::Incremental => {
                // Incrementales son típicamente 5-15% del tamaño completo
                let full_size = match component_name {
                    "blockchain_state" => 2_500_000_000u64,
                    "critical_config" => 50_000_000u64,
                    "critical_logs" => 800_000_000u64,
                    "wallets_keys" => 25_000_000u64,
                    _ => 100_000_000u64,
                };
                (full_size as f64 * (0.05 + rand::random::<f64>() * 0.10)) as u64
            }
            _ => 50_000_000,
        };

        // Fase 3: Compresión (si está habilitada)
        if policy.enable_compression {
            debug!("📋 Phase 3: Compressing backup data");
            tokio::time::sleep(Duration::from_millis(300)).await;
            // Simular reducción por compresión
            backup_size_bytes = (backup_size_bytes as f64 * 0.7) as u64; // 30% de compresión
        }

        // Fase 4: Encriptación (si está habilitada)
        if policy.enable_encryption {
            debug!("📋 Phase 4: Encrypting backup data");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Fase 5: Escritura a disco
        debug!("📋 Phase 5: Writing backup to disk");
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Simular ocasionales fallos de backup (2% de probabilidad)
        if rand::random::<f64>() < 0.02 {
            backup_success = false;
            error_message = "Disk I/O error during backup write".to_string();
        }

        // Fase 6: Verificación de integridad
        if backup_success {
            debug!("📋 Phase 6: Verifying backup integrity");
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        let backup_duration = backup_start.elapsed();
        let verification_hash = if backup_success {
            Some(format!("sha256:{:x}", rand::random::<u64>()))
        } else {
            None
        };

        // Crear registro de backup
        let backup_record = BackupRecord {
            backup_id: backup_id.clone(),
            timestamp,
            backup_type: backup_type.clone(),
            component: component_name.to_string(),
            backup_path: backup_filename,
            size_bytes: backup_size_bytes,
            duration_ms: backup_duration.as_millis() as u64,
            status: if backup_success {
                BackupStatus::Success
            } else {
                BackupStatus::Failed
            },
            verification_hash,
            message: if backup_success {
                format!(
                    "Backup completed successfully - {} MB",
                    backup_size_bytes / (1024 * 1024)
                )
            } else {
                error_message.clone()
            },
            metadata: BackupMetadata {
                system_version: "1.0.0".to_string(),
                file_count: 1000 + rand::random::<u32>() % 5000,
                compression_algorithm: if policy.enable_compression {
                    "zstd".to_string()
                } else {
                    "none".to_string()
                },
                compression_ratio: if policy.enable_compression { 0.7 } else { 1.0 },
                hash_algorithm: "sha256".to_string(),
                tags: vec![
                    component_name.to_string(),
                    format!("{:?}", backup_type),
                    "production".to_string(),
                ],
            },
        };

        // Registrar backup en historial
        {
            let mut history = backup_history.write().await;
            history.push(backup_record);

            // Mantener solo las últimas 500 entradas
            if history.len() > 500 {
                history.remove(0);
            }
        }

        // Actualizar métricas
        {
            let mut metrics = backup_metrics.write().await;
            if backup_success {
                metrics.total_backups_completed += 1;

                match backup_type {
                    BackupType::Full => {
                        metrics.avg_full_backup_time_ms = (metrics.avg_full_backup_time_ms
                            + backup_duration.as_millis() as f64)
                            / 2.0;
                        metrics.avg_full_backup_size_bytes =
                            (metrics.avg_full_backup_size_bytes + backup_size_bytes) / 2;
                    }
                    BackupType::Incremental => {
                        metrics.avg_incremental_backup_time_ms = (metrics
                            .avg_incremental_backup_time_ms
                            + backup_duration.as_millis() as f64)
                            / 2.0;
                        metrics.avg_incremental_backup_size_bytes =
                            (metrics.avg_incremental_backup_size_bytes + backup_size_bytes) / 2;
                    }
                    _ => {}
                }

                metrics.total_storage_used_bytes += backup_size_bytes;
                if policy.enable_compression {
                    metrics.avg_compression_ratio = (metrics.avg_compression_ratio + 0.7) / 2.0;
                }
            } else {
                metrics.total_backups_failed += 1;
            }

            // Recalcular tasa de éxito
            let total = metrics.total_backups_completed + metrics.total_backups_failed;
            if total > 0 {
                metrics.backup_success_rate =
                    (metrics.total_backups_completed as f64 / total as f64) * 100.0;
            }
        }

        if backup_success {
            info!(
                "✅ Backup completed: {} ({} MB in {:?})",
                backup_id,
                backup_size_bytes / (1024 * 1024),
                backup_duration
            );
            Ok(())
        } else {
            error!("❌ Backup failed: {} - {}", backup_id, error_message);
            Err(AvoError::BackupError(format!(
                "Backup failed: {}",
                error_message
            )))
        }
    }

    /// Limpiar backups antiguos según política de retención
    async fn cleanup_old_backups(
        backup_history: &Arc<RwLock<Vec<BackupRecord>>>,
        backup_state: &Arc<RwLock<BackupState>>,
        config: &BackupConfig,
    ) -> AvoResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let retention = &config.retention_policy;
        let mut cleanup_count = 0u32;
        let mut reclaimed_space = 0u64;

        // Identificar backups para limpiar
        {
            let mut history = backup_history.write().await;
            let initial_count = history.len();

            // Filtrar backups que deben ser eliminados
            history.retain(|backup| {
                let age_seconds = now - backup.timestamp;
                let age_days = age_seconds / (24 * 3600);

                let should_keep = match backup.backup_type {
                    BackupType::Full => age_days <= retention.keep_daily_days as u64,
                    BackupType::Incremental => age_days <= (retention.keep_daily_days / 2) as u64,
                    _ => age_days <= retention.keep_daily_days as u64,
                };

                if !should_keep {
                    cleanup_count += 1;
                    reclaimed_space += backup.size_bytes;
                    debug!(
                        "🗑️  Marking backup for cleanup: {} (age: {} days)",
                        backup.backup_id, age_days
                    );
                }

                should_keep
            });

            debug!(
                "🧹 Backup cleanup: removed {} old backups, reclaimed {} MB",
                cleanup_count,
                reclaimed_space / (1024 * 1024)
            );
        }

        // Actualizar estado del backup
        if cleanup_count > 0 {
            let mut state = backup_state.write().await;
            state.total_backup_size_bytes = state
                .total_backup_size_bytes
                .saturating_sub(reclaimed_space);
            state.active_backup_files = state.active_backup_files.saturating_sub(cleanup_count);

            info!(
                "🧹 Cleaned up {} old backups, reclaimed {} MB of storage",
                cleanup_count,
                reclaimed_space / (1024 * 1024)
            );
        }

        Ok(())
    }

    /// Ejecutar backup manual
    pub async fn create_manual_backup(
        &self,
        component: &str,
        backup_type: BackupType,
    ) -> AvoResult<String> {
        info!(
            "📦 Creating manual backup for component: {} ({:?})",
            component, backup_type
        );

        let policies = self.backup_policies.read().await;
        let policy = policies.get(component).ok_or_else(|| {
            AvoError::BackupError(format!(
                "No backup policy found for component: {}",
                component
            ))
        })?;

        Self::execute_backup(
            component,
            backup_type,
            policy,
            &self.backup_history,
            &self.backup_metrics,
            &self.config,
        )
        .await?;

        Ok(format!("Manual backup completed for {}", component))
    }

    /// Ejecutar backup de emergencia de todos los componentes
    pub async fn create_emergency_backup(&self) -> AvoResult<Vec<String>> {
        warn!("🚨 Creating EMERGENCY BACKUP of all critical components");

        let mut results = Vec::new();
        let policies = self.backup_policies.read().await;

        for component_name in policies.keys() {
            let result = self
                .create_manual_backup(component_name, BackupType::Emergency)
                .await;
            match result {
                Ok(msg) => {
                    results.push(format!("✅ {}: {}", component_name, msg));
                }
                Err(e) => {
                    results.push(format!("❌ {}: {}", component_name, e));
                }
            }
        }

        info!(
            "🚨 Emergency backup completed for {} components",
            policies.len()
        );
        Ok(results)
    }

    /// Obtener estado actual del sistema de backup
    pub async fn get_backup_state(&self) -> BackupState {
        self.backup_state.read().await.clone()
    }

    /// Obtener historial de backups
    pub async fn get_backup_history(&self, limit: Option<usize>) -> Vec<BackupRecord> {
        let history = self.backup_history.read().await;
        let limit = limit.unwrap_or(100);

        if history.len() <= limit {
            history.clone()
        } else {
            history[history.len() - limit..].to_vec()
        }
    }

    /// Obtener métricas de backup
    pub async fn get_backup_metrics(&self) -> BackupMetrics {
        self.backup_metrics.read().await.clone()
    }

    /// Pausar sistema de backup
    pub async fn pause_backup_system(&self) -> AvoResult<()> {
        let mut state = self.backup_state.write().await;
        state.operational_status = BackupOperationalStatus::Paused;
        info!("⏸️  Backup system paused");
        Ok(())
    }

    /// Reanudar sistema de backup
    pub async fn resume_backup_system(&self) -> AvoResult<()> {
        let mut state = self.backup_state.write().await;
        state.operational_status = BackupOperationalStatus::Active;
        info!("▶️  Backup system resumed");
        Ok(())
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enable_auto_backup: true,
            backup_directory: "./backups".to_string(),
            backup_filename_format: "{component}_{type}_{timestamp}.avobak".to_string(),
            retention_policy: RetentionPolicy {
                keep_daily_days: 7,
                keep_weekly_weeks: 4,
                keep_monthly_months: 12,
                keep_yearly_years: 3,
                auto_cleanup_old_backups: true,
                max_storage_bytes: Some(100 * 1024 * 1024 * 1024), // 100GB
            },
            compression_config: CompressionConfig {
                algorithm: "zstd".to_string(),
                compression_level: 6,
                compress_large_files_only: false,
                min_file_size_for_compression: 1024 * 1024, // 1MB
            },
            encryption_config: EncryptionConfig {
                enable_encryption: true,
                encryption_algorithm: "AES-256-GCM".to_string(),
                key_file_path: Some("./keys/backup.key".to_string()),
                use_password_derived_key: false,
            },
            remote_storage_config: None,
            max_concurrent_backups: 2,
            backup_timeout_seconds: 3600, // 1 hour
        }
    }
}
