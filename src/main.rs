use std::io;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use clap::Parser;
use anyhow::Result;

mod app;
mod services;
mod utils;

use app::App;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
    
    /// Configuration file path
    #[arg(short, long)]
    config: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging - redirect to file to avoid interfering with TUI
    let log_level = if cli.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    
    // Try multiple log file locations in order of preference
    let log_paths = [
        "/tmp/f2b-buxjr.log",
        "/var/log/f2b-buxjr.log", 
        "./f2b-buxjr.log"
    ];
    
    let mut log_file = None;
    for path in &log_paths {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path) {
            Ok(file) => {
                log_file = Some(file);
                break;
            }
            Err(_) => continue,
        }
    }
    
    match log_file {
        Some(file) => {
            env_logger::Builder::from_default_env()
                .filter_level(log_level)
                .target(env_logger::Target::Pipe(Box::new(file)))
                .init();
        }
        None => {
            // Fall back to stderr if no log file can be created
            env_logger::Builder::from_default_env()
                .filter_level(log_level)
                .init();
        }
    }
    
    // Check privileges FIRST - before any other operations
    match utils::privileges::check_privileges()? {
        utils::privileges::PrivilegeStatus::Root => {
            log::info!("Starting f2b-buxjr v{} as root - full functionality available", env!("CARGO_PKG_VERSION"));
        },
        utils::privileges::PrivilegeStatus::Sudo => {
            log::info!("Starting f2b-buxjr v{} with sudo access - full functionality available", env!("CARGO_PKG_VERSION"));
        },
        utils::privileges::PrivilegeStatus::User => {
            // Don't initialize ANY interface components - just show error and exit
            eprintln!();
            eprintln!("┌─────────────────────────────────────────────────────────────┐");
            eprintln!("│  🔒 PRIVILEGE ERROR: Root Access Required                   │");
            eprintln!("└─────────────────────────────────────────────────────────────┘");
            eprintln!();
            eprintln!("f2b-buxjr requires root privileges for fail2ban management:");
            eprintln!("  • Read/write /etc/fail2ban/ configuration files");
            eprintln!("  • Control fail2ban service via fail2ban-client");  
            eprintln!("  • Manage iptables/firewall rules");
            eprintln!();
            eprintln!("Please run with elevated privileges:");
            eprintln!("  sudo {}", std::env::args().collect::<Vec<_>>().join(" "));
            eprintln!();
            std::process::exit(1);
        }
    }
    
    // Setup terminal (only after privilege check passes)
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create app and run
    let app = App::new(cli.config)?;
    let result = run_app(&mut terminal, app);
    
    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    
    if let Err(err) = result {
        eprintln!("Application error: {}", err);
        std::process::exit(1);
    }
    
    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
) -> Result<()> {
    loop {
        terminal.draw(|f| app.render(f))?;
        
        if app.handle_events()? {
            break;
        }
    }
    
    Ok(())
}
