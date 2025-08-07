use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::SystemTime;
// Removed unused notify imports after FileWatcher removal
use crate::utils::errors::{AppError, Result};
use crate::app::LogEntry;
use chrono::{DateTime, Utc, NaiveDateTime};

pub struct LogMonitor {
    file_path: String,
    last_position: u64,
    last_modified: SystemTime,
}

impl LogMonitor {
    pub fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
            last_position: 0,
            last_modified: SystemTime::UNIX_EPOCH,
        }
    }
    
    pub fn get_fail2ban_log_path() -> String {
        // Common fail2ban log locations
        let possible_paths = vec![
            "/var/log/fail2ban.log",
            "/var/log/fail2ban/fail2ban.log",
            "/usr/local/var/log/fail2ban.log",
        ];
        
        for path in possible_paths {
            if Path::new(path).exists() {
                return path.to_string();
            }
        }
        
        // Default to most common location
        "/var/log/fail2ban.log".to_string()
    }
    
    pub fn tail_new_lines(&mut self) -> Result<Vec<LogEntry>> {
        let path = Path::new(&self.file_path);
        
        if !path.exists() {
            return Err(AppError::FileSystem(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Log file not found: {}", self.file_path)
            )));
        }
        
        let metadata = path.metadata()
            .map_err(|e| AppError::FileSystem(e))?;
        
        let modified = metadata.modified()
            .map_err(|e| AppError::FileSystem(e))?;
        
        // Check if file has been modified since last check
        if modified <= self.last_modified {
            return Ok(Vec::new());
        }
        
        let mut file = File::open(path)
            .map_err(|e| AppError::FileSystem(e))?;
        
        // Seek to last known position
        file.seek(SeekFrom::Start(self.last_position))
            .map_err(|e| AppError::FileSystem(e))?;
        
        let reader = BufReader::new(file);
        let mut new_entries = Vec::new();
        let mut current_position = self.last_position;
        
        for line in reader.lines() {
            match line {
                Ok(line_content) => {
                    current_position += line_content.len() as u64 + 1; // +1 for newline
                    
                    if let Some(entry) = self.parse_log_line(&line_content) {
                        new_entries.push(entry);
                    }
                },
                Err(e) => {
                    log::warn!("Failed to read log line: {}", e);
                    break;
                }
            }
        }
        
        // Sort new entries by timestamp in descending order (newest first)
        new_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Update tracking info
        self.last_position = current_position;
        self.last_modified = modified;
        
        Ok(new_entries)
    }
    
    pub fn get_recent_lines(&mut self, max_lines: usize) -> Result<Vec<LogEntry>> {
        let path = Path::new(&self.file_path);
        
        if !path.exists() {
            return Ok(Vec::new());
        }
        
        let file = File::open(path)
            .map_err(|e| AppError::FileSystem(e))?;
        
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        
        // Read all lines and keep only the last max_lines
        let lines: Vec<String> = reader.lines()
            .filter_map(|line| line.ok())
            .collect();
        
        let start_index = if lines.len() > max_lines {
            lines.len() - max_lines
        } else {
            0
        };
        
        for line in &lines[start_index..] {
            if let Some(entry) = self.parse_log_line(line) {
                entries.push(entry);
            }
        }
        
        // Sort entries by timestamp in descending order (newest first)
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        // Update position to end of file
        if let Ok(metadata) = path.metadata() {
            self.last_position = metadata.len();
            if let Ok(modified) = metadata.modified() {
                self.last_modified = modified;
            }
        }
        
        Ok(entries)
    }
    
    fn parse_log_line(&self, line: &str) -> Option<LogEntry> {
        // Parse fail2ban log format: TIMESTAMP LEVEL MESSAGE
        // Example: 2025-07-19 16:16:35,393 fail2ban.actions [12345]: NOTICE [sshd] Ban 192.168.1.100
        
        if line.trim().is_empty() {
            return None;
        }
        
        // Try to extract timestamp (first 23 characters: "YYYY-MM-DD HH:MM:SS,mmm")
        if line.len() < 23 {
            return Some(LogEntry {
                timestamp: Utc::now(),
                level: "INFO".to_string(),
                message: line.to_string(),
                jail: None,
            });
        }
        
        let timestamp_str = &line[..23];
        let rest = if line.len() > 24 { &line[24..] } else { "" };
        
        // Parse timestamp
        let timestamp = self.parse_timestamp(timestamp_str)
            .unwrap_or_else(|| Utc::now());
        
        // Extract level and message
        let (level, message, jail) = self.parse_message_parts(rest);
        
        Some(LogEntry {
            timestamp,
            level,
            message: message.to_string(),
            jail,
        })
    }
    
    fn parse_timestamp(&self, timestamp_str: &str) -> Option<DateTime<Utc>> {
        // Parse format: "2025-07-19 16:16:35,393"
        let without_millis = timestamp_str.split(',').next()?;
        
        NaiveDateTime::parse_from_str(without_millis, "%Y-%m-%d %H:%M:%S")
            .ok()?
            .and_utc()
            .into()
    }
    
    fn parse_message_parts(&self, message_part: &str) -> (String, String, Option<String>) {
        // Extract level from patterns like "fail2ban.actions [12345]: NOTICE [sshd] Ban 192.168.1.100"
        
        let level = if message_part.contains("ERROR") {
            "ERROR"
        } else if message_part.contains("WARNING") || message_part.contains("WARN") {
            "WARN"
        } else if message_part.contains("NOTICE") {
            "NOTICE"
        } else if message_part.contains("INFO") {
            "INFO"
        } else if message_part.contains("DEBUG") {
            "DEBUG"
        } else {
            "INFO"
        };
        
        // Extract jail name from patterns like "[sshd]" or "[nginx-http]"
        let jail = if let Some(start) = message_part.find('[') {
            if let Some(end) = message_part[start..].find(']') {
                let jail_part = &message_part[start + 1..start + end];
                // Filter out non-jail brackets like process IDs
                if !jail_part.chars().all(|c| c.is_ascii_digit()) && jail_part.len() > 1 {
                    Some(jail_part.to_string())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        
        (level.to_string(), message_part.to_string(), jail)
    }
}

// Removed unused FileWatcher struct and methods