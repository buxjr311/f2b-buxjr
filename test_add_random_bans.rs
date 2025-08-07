#!/usr/bin/env rust-script

use std::process::Command;
use std::thread;
use std::time::Duration;
use rand::Rng;

fn main() {
    println!("Adding 100 random banned IPs for testing filtering functionality...");
    
    // Common jails to use
    let jails = vec!["sshd", "nginx-http", "postfix", "dovecot", "nginx-noscript"];
    
    // Generate 100 random IPs and ban them
    for i in 1..=100 {
        let mut rng = rand::thread_rng();
        
        // Generate random IP (avoiding localhost and private ranges for realism)
        let ip = format!("{}.{}.{}.{}", 
            rng.gen_range(1..223), // Avoid 0, 224-255 ranges
            rng.gen_range(0..255),
            rng.gen_range(0..255), 
            rng.gen_range(1..255)
        );
        
        // Pick random jail
        let jail = jails[rng.gen_range(0..jails.len())];
        
        // Ban the IP
        println!("Banning IP {} in jail {} ({}/100)", ip, jail, i);
        
        let result = Command::new("fail2ban-client")
            .args(&["set", jail, "banip", &ip])
            .output();
            
        match result {
            Ok(output) => {
                if !output.status.success() {
                    let error = String::from_utf8_lossy(&output.stderr);
                    println!("  ⚠ Failed to ban {}: {}", ip, error);
                }
            }
            Err(e) => {
                println!("  ⚠ Command failed: {}", e);
            }
        }
        
        // Small delay to avoid overwhelming the system
        thread::sleep(Duration::from_millis(50));
    }
    
    println!("\n✓ Finished adding test banned IPs!");
    println!("Now you can test the filtering functionality:");
    println!("  - Run: ./target/release/f2b-buxjr");
    println!("  - Focus on banned IPs section with TAB");
    println!("  - Use keys 0,1,2,3 to test different filters");
}