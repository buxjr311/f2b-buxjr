use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)] // Error variants needed for comprehensive error handling
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    
    #[error("Service unavailable: {0}")]
    Service(#[from] ServiceError),
    
    #[error("Permission denied: {0}")]
    Permission(String),
    
    #[error("File system error: {0}")]
    FileSystem(#[from] std::io::Error),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("fail2ban client error: {0}")]
    Fail2banClient(String),
    
    #[error("Terminal error: {0}")]
    Terminal(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Error, Debug)]
#[allow(dead_code)] // Configuration error variants for Epic 1 & 5
pub enum ConfigError {
    #[error("Invalid configuration file: {0}")]
    InvalidFile(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Invalid value for {field}: {value}")]
    InvalidValue { field: String, value: String },
    
    #[error("Configuration validation failed: {0}")]
    ValidationFailed(String),
    
    #[error("Backup operation failed: {0}")]
    BackupFailed(String),
    
    #[error("Restore operation failed: {0}")]
    RestoreFailed(String),
}

#[derive(Error, Debug)]
#[allow(dead_code)] // Service error variants for Epic 4
pub enum ServiceError {
    #[error("fail2ban service not found")]
    NotFound,
    
    #[error("Service is not running")]
    NotRunning,
    
    #[error("Service operation failed: {0}")]
    OperationFailed(String),
    
    #[error("Service status unknown")]
    StatusUnknown,
    
    #[error("Service communication error: {0}")]
    CommunicationError(String),
    
    #[error("Timeout waiting for service response")]
    Timeout,
}

// Error utility methods removed as they were unused

pub type Result<T> = std::result::Result<T, AppError>;