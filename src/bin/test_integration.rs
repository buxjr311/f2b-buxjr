use f2b_buxjr::services::system_service::SystemService;
use f2b_buxjr::services::fail2ban_client::Fail2banClient;

fn main() {
    env_logger::init();
    
    println!("Testing f2b-buxjr integration...");
    
    // Test system service
    let system_service = SystemService::new("fail2ban");
    
    match system_service.get_status() {
        Ok(status) => {
            println!("✓ Service status: {:?}", status);
        },
        Err(e) => {
            println!("✗ Failed to get service status: {}", e);
        }
    }
    
    // Test fail2ban client
    let fail2ban_client = Fail2banClient::new();
    
    if Fail2banClient::is_available() {
        println!("✓ fail2ban-client is available");
        
        match fail2ban_client.get_jails() {
            Ok(jails) => {
                println!("✓ Found {} jails: {:?}", jails.len(), jails);
                
                for jail_name in &jails {
                    match fail2ban_client.get_jail_status(jail_name) {
                        Ok(jail_state) => {
                            println!("  - {}: {} banned IPs, filter: {}", 
                                    jail_state.name, jail_state.banned_count, jail_state.filter);
                        },
                        Err(e) => {
                            println!("  - {}: Error getting status: {}", jail_name, e);
                        }
                    }
                }
            },
            Err(e) => {
                println!("✗ Failed to get jails: {}", e);
            }
        }
    } else {
        println!("✗ fail2ban-client is not available");
    }
    
    println!("Integration test complete!");
}