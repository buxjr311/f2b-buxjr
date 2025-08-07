use f2b_buxjr::services::system_service::SystemService;

fn main() {
    env_logger::init();
    
    println!("Testing f2b-buxjr service control...");
    
    let system_service = SystemService::new("fail2ban");
    
    // Test getting current status
    match system_service.get_status() {
        Ok(status) => {
            println!("✓ Current service status: {:?}", status);
        },
        Err(e) => {
            println!("✗ Failed to get service status: {}", e);
            return;
        }
    }
    
    // Test getting enabled status
    match system_service.is_enabled() {
        Ok(enabled) => {
            println!("✓ Service enabled: {}", enabled);
        },
        Err(e) => {
            println!("✗ Failed to check if service is enabled: {}", e);
        }
    }
    
    println!("\nTesting service operations (requires root privileges):");
    
    // Test reload (safest operation to test)
    println!("Testing configuration reload...");
    match system_service.reload() {
        Ok(()) => {
            println!("✓ Configuration reloaded successfully");
        },
        Err(e) => {
            println!("✗ Failed to reload configuration: {}", e);
        }
    }
    
    // Test restart (more comprehensive test)
    println!("Testing service restart...");
    match system_service.restart() {
        Ok(()) => {
            println!("✓ Service restarted successfully");
            
            // Wait a moment and check status
            std::thread::sleep(std::time::Duration::from_secs(2));
            match system_service.get_status() {
                Ok(status) => {
                    println!("✓ Service status after restart: {:?}", status);
                },
                Err(e) => {
                    println!("✗ Failed to get status after restart: {}", e);
                }
            }
        },
        Err(e) => {
            println!("✗ Failed to restart service: {}", e);
        }
    }
    
    println!("Service control test complete!");
}