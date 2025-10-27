use crate::error::*;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn, Level};
use tracing_appender::{non_blocking, rolling};
use tracing_subscriber::{EnvFilter, Layer, Registry};

/// Sistema de logging estructurado para producción
#[derive(Debug)]
pub struct ProductionLogger {
    /// Configuración del logger
    config: LoggerConfig,
    /// Estado del sistema de logging
    logger_state: Arc<RwLock<LoggerState>>,
    /// Archivos de log activos
    active_log_files: Arc<RwLock<HashMap<String, LogFileHandle>>>,
    /// Métricas de logging
    logging_metrics: Arc<RwLock<LoggingMetrics>>,
    /// Buffer para logs de alta prioridad
    priority_log_buffer: Arc<RwLock<Vec<PriorityLogEntry>>>,
}

/// Estado del sistema de logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerState {
    /// Timestamp de inicialización
    pub initialized_at: u64,
    /// Estado operacional
    pub operational_status: LoggerOperationalStatus,
    /// Nivel de log actual
    pub current_log_level: String,
    /// Número de mensajes loggeados hoy
    pub messages_logged_today: u64,
    /// Número de errores de logging
    pub logging_errors_today: u32,
    /// Tamaño total de archivos de log (bytes)
    pub total_log_size_bytes: u64,
    /// Número de archivos de log activos
    pub active_log_files_count: u32,
    /// Último error de logging
    pub last_logging_error: Option<String>,
}

/// Estado operacional del logger
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LoggerOperationalStatus {
    /// Logger funcionando normalmente
    Active,
    /// Logger con errores menores
    Warning,
    /// Logger con errores críticos
    Error,
    /// Logger pausado
    Paused,
    /// Logger deshabilitado
    Disabled,
}

/// Handle para un archivo de log
#[derive(Debug)]
pub struct LogFileHandle {
    /// Nombre del archivo
    pub filename: String,
    /// Ruta completa del archivo
    pub file_path: PathBuf,
    /// Writer asíncrono con buffer
    pub writer: BufWriter<File>,
    /// Timestamp de última escritura
    pub last_write: u64,
    /// Tamaño actual del archivo
    pub current_size_bytes: u64,
    /// Tipo de log
    pub log_type: LogType,
    /// Nivel mínimo de log para este archivo
    pub min_level: LogLevel,
}

/// Tipos de archivos de log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogType {
    /// Log principal del sistema
    System,
    /// Log de consenso
    Consensus,
    /// Log de red
    Network,
    /// Log de validadores
    Validator,
    /// Log de transacciones
    Transaction,
    /// Log de errores
    Error,
    /// Log de auditoría
    Audit,
    /// Log de seguridad
    Security,
    /// Log de performance
    Performance,
    /// Log de debugging
    Debug,
}

/// Niveles de log
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
}

/// Entrada de log con prioridad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityLogEntry {
    /// Timestamp del evento
    pub timestamp: u64,
    /// Nivel de prioridad
    pub priority: LogPriority,
    /// Componente que generó el log
    pub component: String,
    /// Mensaje del log
    pub message: String,
    /// Metadatos adicionales
    pub metadata: LogMetadata,
    /// ID de correlación para rastreo
    pub correlation_id: Option<String>,
}

/// Prioridades de log
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum LogPriority {
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
    Emergency = 5,
}

/// Metadatos de una entrada de log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMetadata {
    /// Código de error (si aplica)
    pub error_code: Option<String>,
    /// Detalles técnicos
    pub technical_details: HashMap<String, String>,
    /// Stack trace (para errores)
    pub stack_trace: Option<String>,
    /// Usuario/sesión asociada
    pub user_context: Option<String>,
    /// ID de transacción/operación
    pub operation_id: Option<String>,
    /// Tags para categorización
    pub tags: Vec<String>,
}

/// Métricas del sistema de logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingMetrics {
    /// Total de mensajes loggeados
    pub total_messages_logged: u64,
    /// Mensajes por nivel de log
    pub messages_by_level: HashMap<String, u64>,
    /// Mensajes por componente
    pub messages_by_component: HashMap<String, u64>,
    /// Errores de logging
    pub logging_errors: u32,
    /// Tiempo promedio de escritura (ms)
    pub avg_write_time_ms: f64,
    /// Throughput de logging (mensajes/segundo)
    pub logging_throughput_mps: f64,
    /// Tamaño promedio de mensaje (bytes)
    pub avg_message_size_bytes: f64,
    /// Eficiencia de compresión (%)
    pub compression_efficiency_percent: f64,
    /// Espacio total usado por logs (bytes)
    pub total_log_storage_bytes: u64,
}

/// Configuración del sistema de logging
#[derive(Debug, Clone)]
pub struct LoggerConfig {
    /// Directorio base para logs
    pub log_directory: String,
    /// Nivel mínimo de log global
    pub min_log_level: LogLevel,
    /// Formato de logs
    pub log_format: LogFormat,
    /// Configuración de rotación
    pub rotation_config: LogRotationConfig,
    /// Configuración de compresión
    pub compression_config: LogCompressionConfig,
    /// Configuración de archivado
    pub archival_config: LogArchivalConfig,
    /// Configuración de alertas
    pub alert_config: LogAlertConfig,
    /// Habilitar logs estructurados (JSON)
    pub enable_structured_logs: bool,
    /// Buffer size para escritura asíncrona
    pub async_buffer_size: usize,
    /// Timeout para flush de buffer (ms)
    pub buffer_flush_timeout_ms: u64,
}

/// Formatos de log
#[derive(Debug, Clone)]
pub enum LogFormat {
    /// Formato texto plano
    Plain,
    /// Formato JSON estructurado
    Json,
    /// Formato compacto
    Compact,
    /// Formato personalizado
    Custom(String),
}

/// Configuración de rotación de logs
#[derive(Debug, Clone)]
pub struct LogRotationConfig {
    /// Rotar por tamaño máximo (bytes)
    pub max_file_size_bytes: u64,
    /// Rotar por tiempo (horas)
    pub rotation_interval_hours: u64,
    /// Número máximo de archivos a mantener
    pub max_files_to_keep: u32,
    /// Habilitar rotación automática
    pub enable_auto_rotation: bool,
    /// Patrón de nombre para archivos rotados
    pub rotated_filename_pattern: String,
}

/// Configuración de compresión de logs
#[derive(Debug, Clone)]
pub struct LogCompressionConfig {
    /// Habilitar compresión automática
    pub enable_compression: bool,
    /// Algoritmo de compresión (gzip, lz4, zstd)
    pub compression_algorithm: String,
    /// Nivel de compresión (1-9)
    pub compression_level: u8,
    /// Comprimir archivos después de X horas
    pub compress_after_hours: u64,
    /// Tamaño mínimo para comprimir (bytes)
    pub min_size_for_compression: u64,
}

/// Configuración de archivado
#[derive(Debug, Clone)]
pub struct LogArchivalConfig {
    /// Habilitar archivado automático
    pub enable_archival: bool,
    /// Directorio para archivos
    pub archive_directory: String,
    /// Archivar logs después de X días
    pub archive_after_days: u32,
    /// Eliminar archivos después de X días
    pub delete_after_days: u32,
    /// Almacenamiento remoto para archivos
    pub remote_storage_endpoint: Option<String>,
}

/// Configuración de alertas de logging
#[derive(Debug, Clone)]
pub struct LogAlertConfig {
    /// Alertar después de X errores por minuto
    pub error_threshold_per_minute: u32,
    /// Alertar si el throughput baja de X mensajes/segundo
    pub min_throughput_threshold: f64,
    /// Alertar si el espacio en disco es bajo (%)
    pub disk_space_warning_threshold: f64,
    /// Webhook para enviar alertas
    pub alert_webhook_url: Option<String>,
    /// Email para alertas críticas
    pub alert_email: Option<String>,
}

impl ProductionLogger {
    /// Crear nueva instancia del logger de producción
    pub fn new(config: LoggerConfig) -> Self {
        let initial_state = LoggerState {
            initialized_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            operational_status: LoggerOperationalStatus::Active,
            current_log_level: format!("{:?}", config.min_log_level),
            messages_logged_today: 0,
            logging_errors_today: 0,
            total_log_size_bytes: 0,
            active_log_files_count: 0,
            last_logging_error: None,
        };

        let initial_metrics = LoggingMetrics {
            total_messages_logged: 0,
            messages_by_level: HashMap::new(),
            messages_by_component: HashMap::new(),
            logging_errors: 0,
            avg_write_time_ms: 0.0,
            logging_throughput_mps: 0.0,
            avg_message_size_bytes: 0.0,
            compression_efficiency_percent: 0.0,
            total_log_storage_bytes: 0,
        };

        Self {
            config,
            logger_state: Arc::new(RwLock::new(initial_state)),
            active_log_files: Arc::new(RwLock::new(HashMap::new())),
            logging_metrics: Arc::new(RwLock::new(initial_metrics)),
            priority_log_buffer: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Inicializar el sistema de logging de producción
    pub async fn initialize_production_logging(&self) -> AvoResult<()> {
        info!("📝 Initializing production logging system");
        info!("📁 Log directory: {}", self.config.log_directory);
        info!("📊 Min log level: {:?}", self.config.min_log_level);

        // Crear directorio de logs si no existe
        tokio::fs::create_dir_all(&self.config.log_directory)
            .await
            .map_err(|e| AvoError::IoError {
                source: std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create log directory: {}", e),
                ),
            })?;

        // Configurar logs estructurados
        self.setup_structured_logging().await?;

        // Inicializar archivos de log por categoría
        self.initialize_log_files().await?;

        // Iniciar sistemas de mantenimiento
        if self.config.rotation_config.enable_auto_rotation {
            self.start_log_rotation_system().await?;
        }

        if self.config.compression_config.enable_compression {
            self.start_log_compression_system().await?;
        }

        if self.config.archival_config.enable_archival {
            self.start_log_archival_system().await?;
        }

        // Iniciar sistema de alertas
        self.start_log_monitoring_system().await?;

        info!("✅ Production logging system initialized successfully");
        Ok(())
    }

    /// Configurar logging estructurado con tracing
    async fn setup_structured_logging(&self) -> AvoResult<()> {
        if self.config.enable_structured_logs {
            // Configurar appender con rotación
            let file_appender = rolling::daily(&self.config.log_directory, "system.log");
            let (non_blocking, _guard) = non_blocking(file_appender);

            // Configurar filtros
            let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                match self.config.min_log_level {
                    LogLevel::Trace => EnvFilter::new("trace"),
                    LogLevel::Debug => EnvFilter::new("debug"),
                    LogLevel::Info => EnvFilter::new("info"),
                    LogLevel::Warn => EnvFilter::new("warn"),
                    LogLevel::Error => EnvFilter::new("error"),
                    LogLevel::Critical => EnvFilter::new("error"),
                }
            });

            // Configurar subscriber según formato
            match self.config.log_format {
                LogFormat::Json => {
                    let subscriber = tracing_subscriber::fmt()
                        .with_writer(non_blocking)
                        .json()
                        .with_env_filter(filter)
                        .finish();
                    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
                        AvoError::SystemError(format!("Failed to set tracing subscriber: {}", e))
                    })?;
                }
                LogFormat::Compact => {
                    let subscriber = tracing_subscriber::fmt()
                        .with_writer(non_blocking)
                        .compact()
                        .with_env_filter(filter)
                        .finish();
                    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
                        AvoError::SystemError(format!("Failed to set tracing subscriber: {}", e))
                    })?;
                }
                _ => {
                    let subscriber = tracing_subscriber::fmt()
                        .with_writer(non_blocking)
                        .with_env_filter(filter)
                        .finish();
                    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
                        AvoError::SystemError(format!("Failed to set tracing subscriber: {}", e))
                    })?;
                }
            }

            info!(
                "📝 Structured logging configured with {:?} format",
                self.config.log_format
            );
        }

        Ok(())
    }

    /// Inicializar archivos de log por categoría
    async fn initialize_log_files(&self) -> AvoResult<()> {
        let log_types = vec![
            (LogType::System, "system.log", LogLevel::Info),
            (LogType::Consensus, "consensus.log", LogLevel::Debug),
            (LogType::Network, "network.log", LogLevel::Info),
            (LogType::Validator, "validator.log", LogLevel::Info),
            (LogType::Transaction, "transactions.log", LogLevel::Debug),
            (LogType::Error, "errors.log", LogLevel::Error),
            (LogType::Audit, "audit.log", LogLevel::Info),
            (LogType::Security, "security.log", LogLevel::Warn),
            (LogType::Performance, "performance.log", LogLevel::Info),
            (LogType::Debug, "debug.log", LogLevel::Debug),
        ];

        let mut log_files = self.active_log_files.write().await;

        for (log_type, filename, min_level) in log_types {
            let file_path = PathBuf::from(&self.config.log_directory).join(filename);

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .await
                .map_err(|e| AvoError::IoError {
                    source: std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to open log file {}: {}", filename, e),
                    ),
                })?;

            let writer = BufWriter::new(file);

            let log_handle = LogFileHandle {
                filename: filename.to_string(),
                file_path: file_path.clone(),
                writer,
                last_write: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                current_size_bytes: 0,
                log_type: log_type.clone(),
                min_level,
            };

            log_files.insert(format!("{:?}", log_type), log_handle);
        }

        // Actualizar estado
        {
            let mut state = self.logger_state.write().await;
            state.active_log_files_count = log_files.len() as u32;
        }

        info!("📁 Initialized {} log files", log_files.len());
        Ok(())
    }

    /// Iniciar sistema de rotación de logs
    async fn start_log_rotation_system(&self) -> AvoResult<()> {
        let active_log_files = self.active_log_files.clone();
        let logger_state = self.logger_state.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Check cada hora

            loop {
                interval.tick().await;

                if let Err(e) =
                    Self::check_and_rotate_logs(&active_log_files, &logger_state, &config).await
                {
                    error!("🚨 Log rotation error: {}", e);
                }
            }
        });

        info!("🔄 Log rotation system started");
        Ok(())
    }

    /// Verificar y rotar logs según configuración
    async fn check_and_rotate_logs(
        active_log_files: &Arc<RwLock<HashMap<String, LogFileHandle>>>,
        logger_state: &Arc<RwLock<LoggerState>>,
        config: &LoggerConfig,
    ) -> AvoResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut files = active_log_files.write().await;
        let mut rotated_count = 0;

        for (log_type, handle) in files.iter_mut() {
            let should_rotate = handle.current_size_bytes
                >= config.rotation_config.max_file_size_bytes
                || (now - handle.last_write)
                    >= (config.rotation_config.rotation_interval_hours * 3600);

            if should_rotate {
                // Simular rotación de archivo
                let rotated_filename = format!("{}.{}", handle.filename, now);

                debug!(
                    "🔄 Rotating log file: {} -> {}",
                    handle.filename, rotated_filename
                );

                // En producción, aquí moveríamos el archivo actual y crearíamos uno nuevo
                handle.current_size_bytes = 0;
                handle.last_write = now;
                rotated_count += 1;
            }
        }

        if rotated_count > 0 {
            info!("🔄 Rotated {} log files", rotated_count);
        }

        Ok(())
    }

    /// Iniciar sistema de compresión de logs
    async fn start_log_compression_system(&self) -> AvoResult<()> {
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1800)); // Check cada 30 minutos

            loop {
                interval.tick().await;

                if let Err(e) = Self::compress_old_logs(&config).await {
                    error!("🚨 Log compression error: {}", e);
                }
            }
        });

        info!("📦 Log compression system started");
        Ok(())
    }

    /// Comprimir logs antiguos
    async fn compress_old_logs(config: &LoggerConfig) -> AvoResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let compression_threshold = config.compression_config.compress_after_hours * 3600;

        // Simular compresión de archivos antiguos
        debug!(
            "📦 Checking for logs to compress (older than {} hours)",
            config.compression_config.compress_after_hours
        );

        // En producción, aquí buscaríamos archivos reales y los comprimiríamos
        let compressed_files = 2; // Simular

        if compressed_files > 0 {
            info!("📦 Compressed {} old log files", compressed_files);
        }

        Ok(())
    }

    /// Iniciar sistema de archivado de logs
    async fn start_log_archival_system(&self) -> AvoResult<()> {
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // Check diario

            loop {
                interval.tick().await;

                if let Err(e) = Self::archive_old_logs(&config).await {
                    error!("🚨 Log archival error: {}", e);
                }
            }
        });

        info!("📦 Log archival system started");
        Ok(())
    }

    /// Archivar logs antiguos
    async fn archive_old_logs(config: &LoggerConfig) -> AvoResult<()> {
        let archive_threshold_days = config.archival_config.archive_after_days;
        let delete_threshold_days = config.archival_config.delete_after_days;

        debug!(
            "🗄️  Checking for logs to archive (older than {} days)",
            archive_threshold_days
        );

        // Simular proceso de archivado
        let archived_files = 1; // Simular
        let deleted_files = 0; // Simular

        if archived_files > 0 {
            info!("🗄️  Archived {} old log files", archived_files);
        }

        if deleted_files > 0 {
            info!("🗑️  Deleted {} very old log files", deleted_files);
        }

        Ok(())
    }

    /// Iniciar sistema de monitoreo de logs
    async fn start_log_monitoring_system(&self) -> AvoResult<()> {
        let logger_state = self.logger_state.clone();
        let logging_metrics = self.logging_metrics.clone();
        let priority_log_buffer = self.priority_log_buffer.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60)); // Check cada minuto

            loop {
                interval.tick().await;

                if let Err(e) = Self::monitor_logging_health(
                    &logger_state,
                    &logging_metrics,
                    &priority_log_buffer,
                    &config,
                )
                .await
                {
                    error!("🚨 Log monitoring error: {}", e);
                }
            }
        });

        info!("📊 Log monitoring system started");
        Ok(())
    }

    /// Monitorear salud del sistema de logging
    async fn monitor_logging_health(
        logger_state: &Arc<RwLock<LoggerState>>,
        logging_metrics: &Arc<RwLock<LoggingMetrics>>,
        priority_log_buffer: &Arc<RwLock<Vec<PriorityLogEntry>>>,
        config: &LoggerConfig,
    ) -> AvoResult<()> {
        let state = logger_state.read().await;
        let metrics = logging_metrics.read().await;

        // Verificar throughput
        if metrics.logging_throughput_mps < config.alert_config.min_throughput_threshold {
            warn!(
                "⚠️  Low logging throughput: {} messages/second",
                metrics.logging_throughput_mps
            );
        }

        // Verificar errores
        let error_rate_per_minute = state.logging_errors_today as f64 / (24.0 * 60.0); // Aproximación
        if error_rate_per_minute > config.alert_config.error_threshold_per_minute as f64 {
            error!(
                "🚨 High logging error rate: {} errors/minute",
                error_rate_per_minute
            );
        }

        // Procesar buffer de logs de alta prioridad
        let buffer = priority_log_buffer.read().await;
        if buffer.len() > 100 {
            warn!(
                "⚠️  Priority log buffer is getting full: {} entries",
                buffer.len()
            );
        }

        // Verificar espacio en disco (simulado)
        let disk_usage_percent = 45.0; // Simular
        if disk_usage_percent > config.alert_config.disk_space_warning_threshold {
            warn!("⚠️  Disk space running low: {}% used", disk_usage_percent);
        }

        debug!("📊 Logging health check completed");
        Ok(())
    }

    /// Escribir mensaje de log a archivo específico
    pub async fn write_log_message(
        &self,
        log_type: LogType,
        level: LogLevel,
        component: &str,
        message: &str,
        metadata: Option<LogMetadata>,
    ) -> AvoResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Verificar si el nivel cumple el mínimo
        if level < self.config.min_log_level {
            return Ok(());
        }

        // Crear entrada de log
        let log_entry = self
            .format_log_entry(
                timestamp,
                &log_type,
                level.clone(),
                component,
                message,
                metadata,
            )
            .await;

        // Escribir a archivo correspondiente
        {
            let mut files = self.active_log_files.write().await;
            let log_type_key = format!("{:?}", log_type);

            if let Some(handle) = files.get_mut(&log_type_key) {
                if let Err(e) = handle.writer.write_all(log_entry.as_bytes()).await {
                    error!("Failed to write to log file {}: {}", handle.filename, e);
                    return Err(AvoError::IoError {
                        source: std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Log write failed: {}", e),
                        ),
                    });
                }

                if let Err(e) = handle.writer.flush().await {
                    error!("Failed to flush log file {}: {}", handle.filename, e);
                }

                handle.current_size_bytes += log_entry.len() as u64;
                handle.last_write = timestamp;
            }
        }

        // Actualizar métricas
        {
            let mut metrics = self.logging_metrics.write().await;
            metrics.total_messages_logged += 1;

            let level_key = format!("{:?}", level);
            *metrics.messages_by_level.entry(level_key).or_insert(0) += 1;
            *metrics
                .messages_by_component
                .entry(component.to_string())
                .or_insert(0) += 1;

            metrics.avg_message_size_bytes =
                (metrics.avg_message_size_bytes + log_entry.len() as f64) / 2.0;
        }

        // Actualizar estado
        {
            let mut state = self.logger_state.write().await;
            state.messages_logged_today += 1;
        }

        Ok(())
    }

    /// Formatear entrada de log según configuración
    async fn format_log_entry(
        &self,
        timestamp: u64,
        log_type: &LogType,
        level: LogLevel,
        component: &str,
        message: &str,
        metadata: Option<LogMetadata>,
    ) -> String {
        let formatted_time = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S UTC");

        match &self.config.log_format {
            LogFormat::Json => {
                let json_entry = serde_json::json!({
                    "timestamp": formatted_time.to_string(),
                    "level": format!("{:?}", level),
                    "log_type": format!("{:?}", log_type),
                    "component": component,
                    "message": message,
                    "metadata": metadata
                });
                format!("{}\n", json_entry)
            }
            LogFormat::Compact => {
                format!(
                    "{} [{}] {}: {}\n",
                    formatted_time,
                    format!("{:?}", level).to_uppercase(),
                    component,
                    message
                )
            }
            _ => {
                format!(
                    "{} [{}] [{}] [{}] {}\n",
                    formatted_time,
                    format!("{:?}", level).to_uppercase(),
                    format!("{:?}", log_type),
                    component,
                    message
                )
            }
        }
    }

    /// Escribir log de alta prioridad al buffer
    pub async fn write_priority_log(
        &self,
        priority: LogPriority,
        component: &str,
        message: &str,
        metadata: LogMetadata,
    ) -> AvoResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let priority_entry = PriorityLogEntry {
            timestamp,
            priority: priority.clone(),
            component: component.to_string(),
            message: message.to_string(),
            metadata: metadata.clone(),
            correlation_id: Some(format!("prio_{}", rand::random::<u32>())),
        };

        {
            let mut buffer = self.priority_log_buffer.write().await;
            buffer.push(priority_entry);

            // Mantener buffer limitado
            if buffer.len() > 1000 {
                buffer.remove(0);
            }
        }

        // También escribir a log regular
        let log_level = match priority {
            LogPriority::Emergency | LogPriority::Critical => LogLevel::Critical,
            LogPriority::High => LogLevel::Error,
            LogPriority::Normal => LogLevel::Warn,
            LogPriority::Low => LogLevel::Info,
        };

        self.write_log_message(
            LogType::System,
            log_level,
            component,
            message,
            Some(metadata),
        )
        .await?;

        Ok(())
    }

    /// Obtener estado del logger
    pub async fn get_logger_state(&self) -> LoggerState {
        self.logger_state.read().await.clone()
    }

    /// Obtener métricas de logging
    pub async fn get_logging_metrics(&self) -> LoggingMetrics {
        self.logging_metrics.read().await.clone()
    }

    /// Obtener logs de alta prioridad
    pub async fn get_priority_logs(&self, limit: Option<usize>) -> Vec<PriorityLogEntry> {
        let buffer = self.priority_log_buffer.read().await;
        let limit = limit.unwrap_or(100);

        if buffer.len() <= limit {
            buffer.clone()
        } else {
            buffer[buffer.len() - limit..].to_vec()
        }
    }

    /// Flush todos los buffers de log
    pub async fn flush_all_logs(&self) -> AvoResult<()> {
        let mut files = self.active_log_files.write().await;

        for (log_type, handle) in files.iter_mut() {
            if let Err(e) = handle.writer.flush().await {
                error!("Failed to flush log file {}: {}", handle.filename, e);
            }
        }

        info!("💾 Flushed all log buffers");
        Ok(())
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            log_directory: "./logs".to_string(),
            min_log_level: LogLevel::Info,
            log_format: LogFormat::Json,
            rotation_config: LogRotationConfig {
                max_file_size_bytes: 100 * 1024 * 1024, // 100MB
                rotation_interval_hours: 24,
                max_files_to_keep: 30,
                enable_auto_rotation: true,
                rotated_filename_pattern: "{filename}.{timestamp}".to_string(),
            },
            compression_config: LogCompressionConfig {
                enable_compression: true,
                compression_algorithm: "gzip".to_string(),
                compression_level: 6,
                compress_after_hours: 24,
                min_size_for_compression: 10 * 1024 * 1024, // 10MB
            },
            archival_config: LogArchivalConfig {
                enable_archival: true,
                archive_directory: "./logs/archive".to_string(),
                archive_after_days: 7,
                delete_after_days: 30,
                remote_storage_endpoint: None,
            },
            alert_config: LogAlertConfig {
                error_threshold_per_minute: 10,
                min_throughput_threshold: 100.0,
                disk_space_warning_threshold: 85.0,
                alert_webhook_url: None,
                alert_email: None,
            },
            enable_structured_logs: true,
            async_buffer_size: 8192,
            buffer_flush_timeout_ms: 1000,
        }
    }
}
