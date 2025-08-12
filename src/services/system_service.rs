use std::process::Command;
use crate::utils::errors::{AppError, ServiceError, Result};
use crate::app::ServiceStatus;

pub struct SystemService {
    service_name: String,
}

impl SystemService {
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }
    
    pub fn get_status(&self) -> Result<ServiceStatus> {
        let output = Command::new("systemctl")
            .args(["is-active", &self.service_name])
            .output()
            .map_err(|e| AppError::Service(ServiceError::CommunicationError(
                format!("Failed to check service status: {}", e)
            )))?;
        
        let binding = String::from_utf8_lossy(&output.stdout);
        let status_str = binding.trim();
        
        match status_str {
            "active" => Ok(ServiceStatus::Running),
            "inactive" => Ok(ServiceStatus::Stopped),
            "failed" => Ok(ServiceStatus::Failed),
            _ => Ok(ServiceStatus::Unknown),
        }
    }
    
    pub fn start(&self) -> Result<()> {
        let output = Command::new("sudo")
            .args(["systemctl", "start", &self.service_name])
            .output()
            .map_err(|e| {
                AppError::Service(ServiceError::OperationFailed(
                    format!("Failed to start service: {}", e)
                ))
            })?;
        
        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Start failed: {}", error_msg)
            )))
        }
    }
    
    pub fn stop(&self) -> Result<()> {
        let output = Command::new("sudo")
            .args(["systemctl", "stop", &self.service_name])
            .output()
            .map_err(|e| {
                AppError::Service(ServiceError::OperationFailed(
                    format!("Failed to stop service: {}", e)
                ))
            })?;
        
        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Stop failed: {}", error_msg)
            )))
        }
    }
    
    pub fn restart(&self) -> Result<()> {
        let output = Command::new("sudo")
            .args(["systemctl", "restart", &self.service_name])
            .output()
            .map_err(|e| {
                AppError::Service(ServiceError::OperationFailed(
                    format!("Failed to restart service: {}", e)
                ))
            })?;
        
        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Restart failed: {}", error_msg)
            )))
        }
    }
    
    pub fn reload(&self) -> Result<()> {
        let output = Command::new("sudo")
            .args(["systemctl", "reload", &self.service_name])
            .output()
            .map_err(|e| {
                AppError::Service(ServiceError::OperationFailed(
                    format!("Failed to reload service: {}", e)
                ))
            })?;
        
        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Reload failed: {}", error_msg)
            )))
        }
    }
    
    // Removed unused get_uptime method
}