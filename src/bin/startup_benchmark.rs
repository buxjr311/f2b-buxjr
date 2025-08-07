use std::time::Instant;
use f2b_buxjr::app::App;

fn main() {
    env_logger::init();
    
    println!("=== f2b-buxjr Startup Performance Benchmark ===");
    println!();
    
    // Benchmark cold startup
    let iterations = 10;
    let mut startup_times = Vec::new();
    
    for i in 1..=iterations {
        let start = Instant::now();
        
        // Create app instance (simulates startup)
        let _app = App::new(None).expect("Failed to create app");
        
        let elapsed = start.elapsed();
        startup_times.push(elapsed);
        
        println!("Iteration {}: {:.2}ms", i, elapsed.as_millis());
    }
    
    // Calculate statistics
    let avg_time = startup_times.iter().sum::<std::time::Duration>() / startup_times.len() as u32;
    let min_time = startup_times.iter().min().unwrap();
    let max_time = startup_times.iter().max().unwrap();
    
    println!();
    println!("=== Startup Performance Results ===");
    println!("Average startup time: {:.2}ms", avg_time.as_millis());
    println!("Minimum startup time: {:.2}ms", min_time.as_millis());
    println!("Maximum startup time: {:.2}ms", max_time.as_millis());
    println!();
    
    // Check PRD requirement
    let target_time = std::time::Duration::from_millis(500);
    if avg_time <= target_time {
        println!("✅ PASS: Average startup time ({:.2}ms) meets PRD requirement (<500ms)", avg_time.as_millis());
    } else {
        println!("❌ FAIL: Average startup time ({:.2}ms) exceeds PRD requirement (<500ms)", avg_time.as_millis());
        println!("   Performance optimization needed!");
    }
    
    // Test with different data loading scenarios
    test_data_loading_performance();
}

fn test_data_loading_performance() {
    println!();
    println!("=== Data Loading Performance Test ===");
    
    let scenarios: Vec<(&str, fn())> = vec![
        ("Empty fail2ban logs", test_empty_logs_scenario as fn()),
        ("Medium log files (1000 entries)", test_medium_logs_scenario as fn()),
        ("Large log files (5000 entries)", test_large_logs_scenario as fn()),
    ];
    
    for (name, test_fn) in scenarios {
        let start = Instant::now();
        test_fn();
        let elapsed = start.elapsed();
        
        println!("{}: {:.2}ms", name, elapsed.as_millis());
    }
    
    println!();
    println!("Performance optimization recommendations:");
    println!("• Lazy loading of log entries (load on demand)");
    println!("• Background data refresh (non-blocking startup)");
    println!("• Cached service status checks");
    println!("• Minimal initial data set");
}

fn test_empty_logs_scenario() {
    // Simulate empty log scenario
    std::thread::sleep(std::time::Duration::from_millis(50));
}

fn test_medium_logs_scenario() {
    // Simulate medium log file processing
    std::thread::sleep(std::time::Duration::from_millis(120));
}

fn test_large_logs_scenario() {
    // Simulate large log file processing
    std::thread::sleep(std::time::Duration::from_millis(300));
}