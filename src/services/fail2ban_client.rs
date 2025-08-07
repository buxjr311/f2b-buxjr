use std::process::Command;
use crate::utils::errors::{AppError, ServiceError, Result};
use crate::app::{JailState, BannedIP, JailConfig};
use chrono::{Utc, TimeZone};

pub struct Fail2banClient;

impl Fail2banClient {
    pub fn new() -> Self {
        Self
    }
    
    #[allow(dead_code)] // Service health checking for Epic 4
    pub fn is_available() -> bool {
        Command::new("fail2ban-client")
            .arg("--help")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
    
    #[allow(dead_code)] // Service health checking for Epic 4
    pub fn ping() -> Result<bool> {
        let output = Command::new("fail2ban-client")
            .arg("ping")
            .output()
            .map_err(|e| AppError::Service(ServiceError::CommunicationError(
                format!("Failed to ping fail2ban: {}", e)
            )))?;
        
        let response = String::from_utf8_lossy(&output.stdout);
        Ok(response.trim() == "pong")
    }
    
    pub fn get_jails(&self) -> Result<Vec<String>> {
        let output = Command::new("fail2ban-client")
            .args(["status"])
            .output()
            .map_err(|e| AppError::Service(ServiceError::CommunicationError(
                format!("Failed to get jail list: {}", e)
            )))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Service(ServiceError::OperationFailed(
                format!("Failed to get jails: {}", error_msg)
            )));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut jails = Vec::new();
        
        for line in stdout.lines() {
            if line.contains("Jail list:") {
                if let Some(jail_list) = line.split("Jail list:").nth(1) {
                    jails = jail_list
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                break;
            }
        }
        
        Ok(jails)
    }
    
    pub fn get_jail_status(&self, jail_name: &str) -> Result<JailState> {
        let output = Command::new("fail2ban-client")
            .args(["status", jail_name])
            .output()
            .map_err(|e| AppError::Service(ServiceError::CommunicationError(
                format!("Failed to get jail status for {}: {}", jail_name, e)
            )))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Service(ServiceError::OperationFailed(
                format!("Failed to get jail status: {}", error_msg)
            )));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut banned_count = 0;
        let mut filter = "unknown".to_string();
        let mut action = "unknown".to_string();
        
        for line in stdout.lines() {
            if line.contains("Currently banned:") {
                if let Some(count_str) = line.split(':').nth(1) {
                    banned_count = count_str.trim().parse().unwrap_or(0);
                }
            } else if line.contains("Filter") {
                if let Some(filter_str) = line.split(':').nth(1) {
                    filter = filter_str.trim().to_string();
                }
            } else if line.contains("Actions") {
                if let Some(action_str) = line.split(':').nth(1) {
                    action = action_str.trim().to_string();
                }
            }
        }
        
        Ok(JailState {
            name: jail_name.to_string(),
            enabled: true, // If we can get status, it's enabled
            banned_count,
            filter,
            action,
        })
    }
    
    pub fn get_banned_ips(&self, jail_name: &str) -> Result<Vec<BannedIP>> {
        log::debug!("Getting banned IPs with times for jail: {}", jail_name);
        
        // Use the more accurate command that includes ban times
        let output = Command::new("fail2ban-client")
            .args(["get", jail_name, "banip", "--with-time"])
            .output()
            .map_err(|e| AppError::Service(ServiceError::CommunicationError(
                format!("Failed to get banned IPs with times for {}: {}", jail_name, e)
            )))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            log::debug!("fail2ban-client get banip --with-time failed for {}: {}", jail_name, error_msg);
            
            // Fallback to old method if --with-time is not available
            return self.get_banned_ips_fallback(jail_name);
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        log::debug!("fail2ban-client banip --with-time output for {}: {}", jail_name, stdout);
        
        let mut banned_ips = Vec::new();
        
        // Get jail's bantime duration to calculate correct unban times
        let jail_bantime_duration = self.get_jail_bantime_duration(jail_name);
        
        // Parse the output format: "IP_ADDRESS BAN_TIME UNBAN_TIME"
        // Example: "192.168.1.100 2024-07-26 15:30:25 2024-07-26 16:30:25"
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                // Format: IP YYYY-MM-DD HH:MM:SS YYYY-MM-DD HH:MM:SS
                let ip = parts[0].to_string();
                let ban_date = parts[1];
                let ban_time = parts[2];
                let unban_date = parts[3];
                let unban_time = parts[4];
                
                // Parse ban timestamp
                let ban_datetime_str = format!("{} {}", ban_date, ban_time);
                let ban_datetime = chrono::NaiveDateTime::parse_from_str(&ban_datetime_str, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .and_then(|naive_dt| chrono::Local.from_local_datetime(&naive_dt).single())
                    .map(|local_dt| local_dt.with_timezone(&chrono::Utc));
                
                if let Some(ban_time) = ban_datetime {
                    // Calculate proper unban time: ban_time + jail's bantime duration
                    let calculated_unban_time = if let Some(duration) = jail_bantime_duration {
                        Some(ban_time + duration)
                    } else {
                        // Parse the provided unban timestamp as fallback
                        let unban_datetime_str = format!("{} {}", unban_date, unban_time);
                        chrono::NaiveDateTime::parse_from_str(&unban_datetime_str, "%Y-%m-%d %H:%M:%S")
                            .ok()
                            .and_then(|naive_dt| chrono::Local.from_local_datetime(&naive_dt).single())
                            .map(|local_dt| local_dt.with_timezone(&chrono::Utc))
                    };
                    
                    banned_ips.push(BannedIP {
                        ip,
                        jail: jail_name.to_string(),
                        ban_time,
                        unban_time: calculated_unban_time,
                        reason: "Active ban".to_string(),
                    });
                    log::debug!("Parsed banned IP: {} banned at {} unbans at {:?}", 
                               parts[0], ban_datetime_str, calculated_unban_time);
                } else {
                    log::warn!("Failed to parse ban time for IP {}: '{}'", parts[0], ban_datetime_str);
                }
            } else {
                log::debug!("Unexpected ban info format: '{}'", line);
            }
        }
        
        log::debug!("Total banned IPs parsed for {}: {}", jail_name, banned_ips.len());
        Ok(banned_ips)
    }
    
    // Fallback method using the old approach
    fn get_banned_ips_fallback(&self, jail_name: &str) -> Result<Vec<BannedIP>> {
        log::debug!("Using fallback method for getting banned IPs for jail: {}", jail_name);
        
        // Get the list of currently banned IPs without times
        let output = Command::new("fail2ban-client")
            .args(["status", jail_name])
            .output()
            .map_err(|e| AppError::Service(ServiceError::CommunicationError(
                format!("Failed to get banned IPs for {}: {}", jail_name, e)
            )))?;
        
        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            return Err(AppError::Service(ServiceError::OperationFailed(
                format!("Failed to get banned IPs: {}", error_msg)
            )));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_banned_ips = Vec::new();
        
        // Parse currently banned IPs from fail2ban-client output
        for line in stdout.lines() {
            if line.contains("Banned IP list:") {
                if let Some(ip_list) = line.split("Banned IP list:").nth(1) {
                    for ip in ip_list.split_whitespace() {
                        if !ip.is_empty() {
                            current_banned_ips.push(ip.to_string());
                        }
                    }
                }
                break;
            }
        }
        
        // Get jail's bantime duration for proper calculations
        let jail_bantime_duration = self.get_jail_bantime_duration(jail_name);
        
        // For fallback, try to get ban details from log files
        let mut banned_ips = Vec::new();
        
        for ip in current_banned_ips {
            if let Some(ban_details) = self.get_ban_details_from_log(&ip, jail_name) {
                banned_ips.push(ban_details);
            } else {
                // Last resort fallback with better estimated ban time
                let estimated_ban_time = Utc::now() - chrono::Duration::minutes(30); // More reasonable fallback
                let unban_time = if let Some(duration) = jail_bantime_duration {
                    Some(estimated_ban_time + duration)
                } else {
                    self.calculate_unban_time(jail_name, estimated_ban_time)
                };
                
                banned_ips.push(BannedIP {
                    ip: ip.clone(),
                    jail: jail_name.to_string(),
                    ban_time: estimated_ban_time,
                    unban_time,
                    reason: "Estimated (exact time unavailable)".to_string(),
                });
            }
        }
        
        Ok(banned_ips)
    }
    
    fn get_ban_details_from_log(&self, ip: &str, jail_name: &str) -> Option<BannedIP> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        
        // Try to read from fail2ban log file
        let log_paths = [
            "/var/log/fail2ban.log",
            "/var/log/fail2ban/fail2ban.log",
        ];
        
        for log_path in &log_paths {
            if let Ok(file) = File::open(log_path) {
                let reader = BufReader::new(file);
                
                // Read lines in reverse order to find the most recent ban
                let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
                
                for line in lines.iter().rev() {
                    // Look for ban entries like: "2024-07-25 14:30:05,123 fail2ban.actions[1234]: NOTICE [sshd] Ban 192.168.1.100"
                    if line.contains(&format!("[{}]", jail_name)) && 
                       line.contains(&format!("Ban {}", ip)) {
                        
                        // Parse the timestamp from the log line
                        if let Some(timestamp_str) = line.split(',').next() {
                            // Parse as naive datetime first, then assume local time
                            if let Ok(naive_dt) = chrono::NaiveDateTime::parse_from_str(
                                timestamp_str, "%Y-%m-%d %H:%M:%S"
                            ) {
                                // Convert local time to UTC
                                let ban_time = chrono::Local.from_local_datetime(&naive_dt)
                                    .single()
                                    .map(|dt| dt.with_timezone(&chrono::Utc));
                                
                                if let Some(ban_time) = ban_time {
                                    // Calculate unban time using jail's bantime duration
                                    let unban_time = if let Some(duration) = self.get_jail_bantime_duration(jail_name) {
                                        Some(ban_time + duration)
                                    } else {
                                        self.calculate_unban_time(jail_name, ban_time)
                                    };
                                    
                                    return Some(BannedIP {
                                        ip: ip.to_string(),
                                        jail: jail_name.to_string(),
                                        ban_time,
                                        unban_time,
                                        reason: "Log analysis".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }
    
    fn calculate_unban_time(&self, jail_name: &str, ban_time: chrono::DateTime<Utc>) -> Option<chrono::DateTime<Utc>> {
        // Try to get bantime from jail configuration
        if let Ok(all_jails) = self.get_all_available_jails() {
            if let Some(jail_config) = all_jails.iter().find(|j| j.name == jail_name) {
                log::debug!("Found jail config for {}: bantime = '{}'", jail_name, jail_config.ban_time);
                // Parse bantime (could be like "1h", "3600", "1d", etc.)
                if let Some(duration) = self.parse_bantime(&jail_config.ban_time) {
                    log::debug!("Parsed bantime for {}: {} hours", jail_name, duration.num_hours());
                    return Some(ban_time + duration);
                } else {
                    log::warn!("Failed to parse bantime '{}' for jail {}", jail_config.ban_time, jail_name);
                }
            } else {
                log::warn!("No jail config found for {}", jail_name);
            }
        } else {
            log::warn!("Failed to get all jail configs");
        }
        
        // Default fallback: assume 24 hour ban
        log::debug!("Using 24h fallback for jail {}", jail_name);
        Some(ban_time + chrono::Duration::hours(24))
    }
    
    /// Get jail's bantime duration in chrono::Duration format
    fn get_jail_bantime_duration(&self, jail_name: &str) -> Option<chrono::Duration> {
        // First try to get bantime directly from fail2ban-client
        if let Ok(bantime_seconds) = self.get_bantime(jail_name) {
            log::debug!("Got bantime for {} from fail2ban-client: {} seconds", jail_name, bantime_seconds);
            return Some(chrono::Duration::seconds(bantime_seconds as i64));
        }
        
        // Fallback: try to get from jail configuration files
        if let Ok(all_jails) = self.get_all_available_jails() {
            if let Some(jail_config) = all_jails.iter().find(|j| j.name == jail_name) {
                log::debug!("Found jail config for {}: bantime = '{}'", jail_name, jail_config.ban_time);
                return self.parse_bantime(&jail_config.ban_time);
            }
        }
        
        log::warn!("Could not determine bantime for jail {}, using default 1 hour", jail_name);
        Some(chrono::Duration::hours(1))
    }

    fn parse_bantime(&self, bantime_str: &str) -> Option<chrono::Duration> {
        let bantime = bantime_str.trim();
        log::debug!("Parsing bantime string: '{}'", bantime);
        
        // Handle different bantime formats
        if bantime.ends_with('h') {
            if let Ok(hours) = bantime[..bantime.len()-1].parse::<i64>() {
                log::debug!("Parsed as hours: {}", hours);
                return Some(chrono::Duration::hours(hours));
            }
        } else if bantime.ends_with('d') {
            if let Ok(days) = bantime[..bantime.len()-1].parse::<i64>() {
                log::debug!("Parsed as days: {}", days);
                return Some(chrono::Duration::days(days));
            }
        } else if bantime.ends_with('m') {
            if let Ok(minutes) = bantime[..bantime.len()-1].parse::<i64>() {
                log::debug!("Parsed as minutes: {}", minutes);
                return Some(chrono::Duration::minutes(minutes));
            }
        } else {
            // Assume it's seconds
            if let Ok(seconds) = bantime.parse::<i64>() {
                let hours = seconds / 3600;
                log::debug!("Parsed as seconds: {} (= {} hours)", seconds, hours);
                return Some(chrono::Duration::seconds(seconds));
            }
        }
        
        log::warn!("Failed to parse bantime: '{}'", bantime);
        None
    }
    
    pub fn ban_ip(&self, jail_name: &str, ip: &str) -> Result<()> {
        let output = Command::new("fail2ban-client")
            .args(["set", jail_name, "banip", ip])
            .output()
            .map_err(|e| AppError::Service(ServiceError::OperationFailed(
                format!("Failed to ban IP {}: {}", ip, e)
            )))?;
        
        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Ban failed: {}", error_msg)
            )))
        }
    }


    /// Get current bantime for a jail in seconds
    fn get_bantime(&self, jail_name: &str) -> Result<u64> {
        let output = Command::new("fail2ban-client")
            .args(["get", jail_name, "bantime"])
            .output()
            .map_err(|e| AppError::Service(ServiceError::OperationFailed(
                format!("Failed to get bantime for {}: {}", jail_name, e)
            )))?;
        
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let bantime_str = stdout.trim();
            bantime_str.parse::<u64>()
                .map_err(|e| AppError::Service(ServiceError::OperationFailed(
                    format!("Failed to parse bantime '{}': {}", bantime_str, e)
                )))
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Failed to get bantime: {}", error_msg)
            )))
        }
    }

    // Removed unused set_bantime and parse_duration helper methods
    
    pub fn unban_ip(&self, jail_name: &str, ip: &str) -> Result<()> {
        let output = Command::new("fail2ban-client")
            .args(["set", jail_name, "unbanip", ip])
            .output()
            .map_err(|e| AppError::Service(ServiceError::OperationFailed(
                format!("Failed to unban IP {}: {}", ip, e)
            )))?;
        
        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Unban failed: {}", error_msg)
            )))
        }
    }
    
    // Removed unused reload_jail and get_version methods
    
    /// Get all available jails from configuration files (both enabled and disabled)
    pub fn get_all_available_jails(&self) -> Result<Vec<JailConfig>> {
        let jail_config_path = "/etc/fail2ban/jail.local";
        
        let content = match std::fs::read_to_string(jail_config_path) {
            Ok(content) => {
                log::info!("Successfully read jail.local file ({} bytes)", content.len());
                content
            },
            Err(e) => {
                log::warn!("Failed to read jail.local: {}, trying jail.conf", e);
                // jail.local doesn't exist, try to read from jail.conf
                let jail_conf_path = "/etc/fail2ban/jail.conf";
                match std::fs::read_to_string(jail_conf_path) {
                    Ok(conf_content) => {
                        log::info!("Successfully read jail.conf file ({} bytes)", conf_content.len());
                        conf_content
                    },
                    Err(e) => {
                        log::error!("Failed to read both jail.local and jail.conf: {}", e);
                        return Err(AppError::Service(ServiceError::CommunicationError(
                            format!("Failed to read jail configuration files: {}", e)
                        )));
                    }
                }
            }
        };
        
        self.parse_jail_configs(&content)
    }
    
    /// Parse jail configurations from file content
    fn parse_jail_configs(&self, content: &str) -> Result<Vec<JailConfig>> {
        let mut jails = Vec::new();
        let mut current_jail: Option<JailConfig> = None;
        let mut section_count = 0;
        
        log::info!("Starting to parse jail configurations...");
        
        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            
            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            
            // Section headers
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                // Save previous jail if it exists
                if let Some(jail) = current_jail.take() {
                    log::debug!("Saving jail: {} (enabled: {}, filter: {}, port: {})", 
                        jail.name, jail.enabled, jail.filter, jail.port);
                    jails.push(jail);
                }
                
                let section_name = trimmed[1..trimmed.len()-1].to_string();
                section_count += 1;
                
                log::debug!("Found section at line {}: [{}]", line_num + 1, section_name);
                
                // Create jail config for ANY section that's not DEFAULT or INCLUDES
                let is_jail_section = section_name != "DEFAULT" && 
                                    section_name != "INCLUDES" && 
                                    section_name != "Definition";
                
                if is_jail_section {
                    log::debug!("Creating jail config for: {}", section_name);
                    current_jail = Some(JailConfig {
                        name: section_name.clone(),
                        enabled: false, // Default to disabled unless explicitly enabled
                        filter: String::new(),
                        port: String::new(),
                        protocol: String::new(),
                        log_path: String::new(),
                        max_retry: 5,
                        find_time: "10m".to_string(),
                        ban_time: "1h".to_string(),
                        action: String::new(),
                    });
                } else {
                    log::debug!("Skipping non-jail section: {}", section_name);
                }
            } else if let Some(ref mut jail) = current_jail {
                // Parse key-value pairs within jail sections
                if let Some((key, value)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    
                    log::debug!("Setting {}.{} = {}", jail.name, key, value);
                    
                    match key {
                        "enabled" => {
                            jail.enabled = value.to_lowercase() == "true";
                        },
                        "filter" => {
                            jail.filter = value.to_string();
                        },
                        "port" => {
                            jail.port = value.to_string();
                        },
                        "protocol" => {
                            jail.protocol = value.to_string();
                        },
                        "logpath" => {
                            jail.log_path = value.to_string();
                        },
                        "maxretry" => {
                            if let Ok(retry_count) = value.parse::<i32>() {
                                jail.max_retry = retry_count;
                            }
                        },
                        "findtime" => {
                            jail.find_time = value.to_string();
                        },
                        "bantime" => {
                            jail.ban_time = value.to_string();
                        },
                        "action" => {
                            jail.action = value.to_string();
                        },
                        _ => {} // Ignore other parameters for now
                    }
                }
            }
        }
        
        // Don't forget the last jail
        if let Some(jail) = current_jail {
            log::debug!("Saving final jail: {} (enabled: {}, filter: {}, port: {})", 
                jail.name, jail.enabled, jail.filter, jail.port);
            jails.push(jail);
        }
        
        // Log the number of jails found for debugging
        log::info!("Parsed {} jail configurations from config file (found {} total sections)", jails.len(), section_count);
        for jail in &jails {
            log::info!("Found jail: {} (enabled: {}, port: {}, filter: {})", 
                jail.name, jail.enabled, jail.port, jail.filter);
        }
        
        Ok(jails)
    }
    
    /// Enable or disable a jail by updating its configuration
    pub fn set_jail_enabled(&self, jail_name: &str, enabled: bool) -> Result<()> {
        let jail_config_path = "/etc/fail2ban/jail.local";
        
        // Read existing configuration or create jail.local from jail.conf
        let content = match std::fs::read_to_string(jail_config_path) {
            Ok(content) => content,
            Err(_) => {
                // jail.local doesn't exist, copy from jail.conf
                let jail_conf_path = "/etc/fail2ban/jail.conf";
                match std::fs::read_to_string(jail_conf_path) {
                    Ok(conf_content) => {
                        // Copy jail.conf to jail.local
                        std::fs::write(jail_config_path, &conf_content)?;
                        conf_content
                    },
                    Err(e) => {
                        return Err(AppError::Service(ServiceError::CommunicationError(
                            format!("Failed to read jail configuration: {}", e)
                        )));
                    }
                }
            }
        };
        
        // Update the jail configuration
        let updated_content = self.update_jail_enabled_in_config(&content, jail_name, enabled)?;
        
        // Write the updated content back to jail.local
        std::fs::write(jail_config_path, updated_content)?;
        
        // Reload fail2ban configuration to apply changes
        self.reload_config()
    }
    
    /// Update jail enabled status in configuration content
    fn update_jail_enabled_in_config(&self, content: &str, jail_name: &str, enabled: bool) -> Result<String> {
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        let mut in_target_jail = false;
        let mut found_enabled_line = false;
        let mut i = 0;
        
        while i < lines.len() {
            let trimmed = lines[i].trim();
            
            // Check if we're entering the target jail section
            if trimmed == format!("[{}]", jail_name) {
                in_target_jail = true;
                i += 1;
                continue;
            }
            
            // Check if we're leaving the current jail section
            if in_target_jail && trimmed.starts_with('[') && trimmed.ends_with(']') {
                // If we didn't find an enabled line, add it right after the jail section header
                if !found_enabled_line {
                    // Find the jail section header and add enabled line right after it
                    for j in 0..i {
                        let header_line = lines[j].trim();
                        if header_line == format!("[{}]", jail_name) {
                            lines.insert(j + 1, format!("enabled = {}", enabled));
                            found_enabled_line = true;
                            break;
                        }
                    }
                }
                break;
            }
            
            // If we're in the target jail and find an enabled line, update it
            if in_target_jail && trimmed.starts_with("enabled") {
                if let Some(_) = trimmed.split_once('=') {
                    lines[i] = format!("enabled = {}", enabled);
                    found_enabled_line = true;
                }
            }
            
            i += 1;
        }
        
        // If we reached the end without finding an enabled line, add it right after the jail section header
        if in_target_jail && !found_enabled_line {
            // Find the jail section header and add enabled line right after it
            for i in 0..lines.len() {
                let trimmed = lines[i].trim();
                if trimmed == format!("[{}]", jail_name) {
                    // Insert enabled line right after the jail header
                    lines.insert(i + 1, format!("enabled = {}", enabled));
                    break;
                }
            }
        }
        
        Ok(lines.join("\n"))
    }
    
    /// Get currently whitelisted IPs from fail2ban configuration
    pub fn get_whitelist_ips(&self) -> Result<Vec<String>> {
        // Read from the jail.local file or create one if it doesn't exist
        let jail_config_path = "/etc/fail2ban/jail.local";
        
        let content = match std::fs::read_to_string(jail_config_path) {
            Ok(content) => content,
            Err(_) => {
                // jail.local doesn't exist, try to read from jail.conf
                let jail_conf_path = "/etc/fail2ban/jail.conf";
                match std::fs::read_to_string(jail_conf_path) {
                    Ok(conf_content) => conf_content,
                    Err(_) => {
                        // Neither file exists, return default whitelist
                        return Ok(vec!["127.0.0.1".to_string(), "::1".to_string()]);
                    }
                }
            }
        };
        
        // Parse ignoreip parameter from the [DEFAULT] section
        let mut whitelist_ips = Vec::new();
        let mut in_default_section = false;
        
        for line in content.lines() {
            let trimmed = line.trim();
            
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_default_section = trimmed == "[DEFAULT]";
                continue;
            }
            
            if in_default_section && (trimmed.starts_with("ignoreip") || trimmed.starts_with("#ignoreip")) {
                // Parse ignoreip = ip1 ip2 ip3 (handle both commented and uncommented)
                let line_to_parse = if trimmed.starts_with("#") {
                    trimmed.trim_start_matches('#').trim()
                } else {
                    trimmed
                };
                
                if let Some(ips_part) = line_to_parse.split('=').nth(1) {
                    let ips: Vec<String> = ips_part
                        .split_whitespace()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    whitelist_ips.extend(ips);
                }
                break; // Found ignoreip line
            }
        }
        
        Ok(whitelist_ips)
    }
    
    /// Save whitelist IPs to fail2ban configuration
    pub fn save_whitelist_ips(&self, whitelist_ips: &[String]) -> Result<()> {
        let jail_config_path = "/etc/fail2ban/jail.local";
        
        // Read existing configuration or create jail.local from jail.conf
        let config_content = match std::fs::read_to_string(jail_config_path) {
            Ok(content) => content,
            Err(_) => {
                // jail.local doesn't exist, copy from jail.conf
                let jail_conf_path = "/etc/fail2ban/jail.conf";
                match std::fs::read_to_string(jail_conf_path) {
                    Ok(conf_content) => {
                        // Copy jail.conf to jail.local
                        std::fs::write(jail_config_path, &conf_content)
                            .map_err(|e| AppError::Service(ServiceError::OperationFailed(
                                format!("Failed to copy jail.conf to jail.local: {}", e)
                            )))?;
                        conf_content
                    },
                    Err(e) => {
                        return Err(AppError::Service(ServiceError::OperationFailed(
                            format!("Failed to read jail.conf: {}", e)
                        )));
                    }
                }
            }
        };
        
        // Prepare ignoreip line
        let ignoreip_line = if whitelist_ips.is_empty() {
            "ignoreip = 127.0.0.1 ::1".to_string()
        } else {
            format!("ignoreip = {}", whitelist_ips.join(" "))
        };
        
        // Update or add ignoreip line
        let mut updated_lines = Vec::new();
        let mut in_default_section = false;
        let mut ignoreip_updated = false;
        let mut found_default_section = false;
        
        for line in config_content.lines() {
            let trimmed = line.trim();
            
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_default_section = trimmed == "[DEFAULT]";
                if in_default_section {
                    found_default_section = true;
                }
                updated_lines.push(line.to_string());
                continue;
            }
            
            if in_default_section && (trimmed.starts_with("ignoreip") || trimmed.starts_with("#ignoreip")) {
                // Replace existing ignoreip line (both commented and uncommented)
                updated_lines.push(ignoreip_line.clone());
                ignoreip_updated = true;
            } else {
                updated_lines.push(line.to_string());
            }
        }
        
        // Add DEFAULT section and ignoreip if not found
        if !found_default_section {
            updated_lines.insert(0, "[DEFAULT]".to_string());
            updated_lines.insert(1, "# Auto-generated by f2b-buxjr".to_string());
            updated_lines.insert(2, ignoreip_line.clone());
            updated_lines.insert(3, "".to_string());
        } else if !ignoreip_updated {
            // Add ignoreip to DEFAULT section
            for (i, line) in updated_lines.iter().enumerate() {
                if line.trim() == "[DEFAULT]" {
                    updated_lines.insert(i + 1, ignoreip_line.clone());
                    break;
                }
            }
        }
        
        // Write updated configuration
        let updated_content = updated_lines.join("\n");
        std::fs::write(jail_config_path, &updated_content)
            .map_err(|e| AppError::Service(ServiceError::OperationFailed(
                format!("Failed to write whitelist configuration: {}", e)
            )))?;
        
        // Reload fail2ban configuration
        self.reload_config()?;
        
        Ok(())
    }
    
    /// Reload fail2ban configuration to apply changes
    fn reload_config(&self) -> Result<()> {
        let output = Command::new("fail2ban-client")
            .args(["reload"])
            .output()
            .map_err(|e| AppError::Service(ServiceError::CommunicationError(
                format!("Failed to reload fail2ban config: {}", e)
            )))?;
        
        if output.status.success() {
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(AppError::Service(ServiceError::OperationFailed(
                format!("Config reload failed: {}", error_msg)
            )))
        }
    }
}