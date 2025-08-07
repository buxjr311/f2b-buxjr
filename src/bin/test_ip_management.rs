use f2b_buxjr::services::fail2ban_client::Fail2banClient;

fn main() {
    env_logger::init();
    
    println!("Testing f2b-buxjr IP management...");
    
    let fail2ban_client = Fail2banClient::new();
    
    // First get the available jails
    let jails = match fail2ban_client.get_jails() {
        Ok(jails) => {
            println!("✓ Found jails: {:?}", jails);
            jails
        },
        Err(e) => {
            println!("✗ Failed to get jails: {}", e);
            return;
        }
    };
    
    if jails.is_empty() {
        println!("No jails found - cannot test IP management");
        return;
    }
    
    let test_jail = &jails[0];
    let test_ip = "192.168.999.999"; // Use an obviously fake IP for testing
    
    println!("\nTesting IP management with jail '{}' and IP '{}'", test_jail, test_ip);
    
    // Check current banned IPs before test
    println!("Getting current banned IPs...");
    match fail2ban_client.get_banned_ips(test_jail) {
        Ok(banned_ips) => {
            println!("✓ Currently banned IPs in {}: {} IPs", test_jail, banned_ips.len());
            for ip in &banned_ips {
                println!("  - {}", ip.ip);
            }
        },
        Err(e) => {
            println!("✗ Failed to get banned IPs: {}", e);
        }
    }
    
    // Test banning an IP
    println!("\nTesting IP banning...");
    match fail2ban_client.ban_ip(test_jail, test_ip) {
        Ok(()) => {
            println!("✓ Successfully banned IP {} in jail {}", test_ip, test_jail);
            
            // Check if it appears in banned list
            match fail2ban_client.get_banned_ips(test_jail) {
                Ok(banned_ips) => {
                    let is_banned = banned_ips.iter().any(|ip| ip.ip == test_ip);
                    if is_banned {
                        println!("✓ IP {} confirmed in banned list", test_ip);
                    } else {
                        println!("⚠ IP {} not found in banned list (might be filtered by fail2ban)", test_ip);
                    }
                },
                Err(e) => {
                    println!("✗ Failed to check banned IPs after ban: {}", e);
                }
            }
            
            // Test unbanning the IP
            println!("\nTesting IP unbanning...");
            match fail2ban_client.unban_ip(test_jail, test_ip) {
                Ok(()) => {
                    println!("✓ Successfully unbanned IP {} from jail {}", test_ip, test_jail);
                },
                Err(e) => {
                    println!("✗ Failed to unban IP {}: {}", test_ip, e);
                }
            }
        },
        Err(e) => {
            println!("✗ Failed to ban IP {}: {}", test_ip, e);
        }
    }
    
    println!("IP management test complete!");
}