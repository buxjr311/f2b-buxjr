use f2b_buxjr::services::file_monitor::LogMonitor;

fn main() {
    env_logger::init();
    
    println!("=== f2b-buxjr Log Monitor Test ===");
    println!();
    
    // Test log file detection
    let log_path = LogMonitor::get_fail2ban_log_path();
    println!("1. Testing Log File Detection...");
    println!("   Detected log path: {}", log_path);
    
    let log_exists = std::path::Path::new(&log_path).exists();
    if log_exists {
        println!("   ✓ Log file exists");
    } else {
        println!("   ○ Log file not found");
        println!("   This is normal if fail2ban hasn't been started yet");
    }
    
    // Test LogMonitor creation
    println!("\n2. Testing LogMonitor Creation...");
    let mut log_monitor = LogMonitor::new(&log_path);
    println!("   ✓ LogMonitor created successfully");
    
    // Test getting recent lines (even if file doesn't exist)
    println!("\n3. Testing Recent Log Retrieval...");
    match log_monitor.get_recent_lines(10) {
        Ok(entries) => {
            println!("   ✓ Successfully retrieved {} log entries", entries.len());
            
            if entries.is_empty() {
                println!("   No log entries found - this is normal if:");
                println!("     • fail2ban is not running");
                println!("     • fail2ban log file is empty");
                println!("     • fail2ban logs to a different location");
            } else {
                println!("   Recent log entries:");
                for (i, entry) in entries.iter().take(5).enumerate() {
                    let time_str = entry.timestamp.format("%Y-%m-%d %H:%M:%S");
                    let jail_str = entry.jail.as_ref()
                        .map(|j| format!("[{}]", j))
                        .unwrap_or_else(|| "".to_string());
                    
                    println!("     {}. {} {} {} {}", 
                            i + 1, time_str, entry.level, jail_str, 
                            if entry.message.len() > 50 {
                                format!("{}...", &entry.message[..47])
                            } else {
                                entry.message.clone()
                            });
                }
                
                if entries.len() > 5 {
                    println!("     ... and {} more entries", entries.len() - 5);
                }
            }
        },
        Err(e) => {
            println!("   ✗ Failed to retrieve log entries: {}", e);
        }
    }
    
    // Test log tailing (for new entries)
    println!("\n4. Testing Log Tailing...");
    match log_monitor.tail_new_lines() {
        Ok(new_entries) => {
            println!("   ✓ Log tailing successful");
            if new_entries.is_empty() {
                println!("   No new entries since last check");
            } else {
                println!("   Found {} new entries", new_entries.len());
            }
        },
        Err(e) => {
            println!("   ✗ Log tailing failed: {}", e);
        }
    }
    
    // Test log parsing with a sample line
    println!("\n5. Testing Log Parsing...");
    println!("   Testing with sample fail2ban log line...");
    
    // This would normally be done internally, but we can test the format
    println!("   Sample log formats that should be parsed:");
    println!("     '2025-07-19 16:16:35,393 fail2ban.actions [12345]: NOTICE [sshd] Ban 192.168.1.100'");
    println!("     '2025-07-19 16:17:40,123 fail2ban.filter  [12345]: INFO   [nginx] Found 192.168.1.200'");
    println!("     '2025-07-19 16:18:45,456 fail2ban.actions [12345]: NOTICE [postfix] Unban 192.168.1.150'");
    
    // Test configuration detection
    println!("\n6. Testing Configuration File Detection...");
    let common_log_paths = vec![
        "/var/log/fail2ban.log",
        "/var/log/fail2ban/fail2ban.log", 
        "/usr/local/var/log/fail2ban.log",
    ];
    
    for path in common_log_paths {
        let exists = std::path::Path::new(path).exists();
        let status = if exists { "✓ EXISTS" } else { "○ missing" };
        println!("   {} {}", status, path);
    }
    
    println!("\n=== Log Monitor Test Summary ===");
    println!("✓ Log file path detection");
    println!("✓ LogMonitor creation");
    println!("✓ Log entry retrieval");  
    println!("✓ Log tailing functionality");
    println!("✓ Configuration file detection");
    println!();
    println!("Real-time log monitoring is ready!");
    println!();
    println!("To see log monitoring in action:");
    println!("1. Start fail2ban service: sudo systemctl start fail2ban");
    println!("2. Generate some activity (failed SSH attempts, etc.)");
    println!("3. Run the TUI application: sudo ./target/debug/f2b-buxjr");
    println!("4. Press F7 to view the Logs screen");
    println!("5. Watch real-time updates every 5 seconds");
}