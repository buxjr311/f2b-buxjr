use std::collections::HashMap;
use std::time::{Duration, Instant};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap, Clear, Table, Row, Cell, TableState},
    Frame,
};
use anyhow::Result;
use unicode_width::UnicodeWidthStr;

use crate::utils::errors::AppError;
use crate::services::system_service::SystemService;
use crate::services::fail2ban_client::Fail2banClient;
use crate::services::file_monitor::LogMonitor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Configuration,
    Logs,
    Whitelist,
    Settings,
    Help,
    About,
    JailEditor,
}

impl Screen {
    pub fn title(&self) -> &'static str {
        match self {
            Screen::Dashboard => "Dashboard",
            Screen::Configuration => "Configuration",
            Screen::Logs => "Logs",
            Screen::Whitelist => "Whitelist",
            Screen::Settings => "Settings",
            Screen::Help => "Help",
            Screen::About => "About",
            Screen::JailEditor => "Jail Editor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum DashboardFocus {
    #[default]
    Jails,
    BannedIPs,
}

#[derive(Debug, Clone)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Failed,
    Unknown,
}

impl ServiceStatus {
    pub fn color(&self) -> Color {
        match self {
            ServiceStatus::Running => Color::Green,
            ServiceStatus::Stopped => Color::Red,
            ServiceStatus::Failed => Color::Red,
            ServiceStatus::Unknown => Color::Gray,
        }
    }
    
    pub fn symbol(&self) -> &'static str {
        match self {
            ServiceStatus::Running => "●",
            ServiceStatus::Stopped => "○",
            ServiceStatus::Failed => "✖",
            ServiceStatus::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields will be used in jail management features (Epic 1)
pub struct JailState {
    pub name: String,
    pub enabled: bool,
    pub banned_count: usize,
    pub filter: String,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct JailConfig {
    pub name: String,
    pub enabled: bool,
    pub filter: String,
    pub port: String,
    pub protocol: String,
    pub log_path: String,
    pub max_retry: i32,
    pub find_time: String,
    pub ban_time: String,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct BannedIP {
    pub ip: String,
    pub jail: String,
    pub ban_time: chrono::DateTime<chrono::Utc>,
    pub unban_time: Option<chrono::DateTime<chrono::Utc>>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: String,
    pub message: String,
    pub jail: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Reload,
}

#[derive(Debug)]
#[allow(dead_code)] // Message variants needed for TEA pattern and planned features
pub enum AppMessage {
    // Navigation
    SwitchScreen(Screen),
    
    // Service management
    ServiceStatusUpdate(ServiceStatus),
    ServiceAction(ServiceAction),
    
    // Configuration and Jail Management
    JailToggled(String, bool),
    LoadAvailableJails,
    AvailableJailsLoaded(Vec<JailConfig>),
    SelectJail(usize),
    ToggleJailEnabled(String),
    SetJailEnabled(String, bool),     // jail_name, enabled
    PerformJailToggle(String, bool),  // jail_name, new_enabled
    OpenJailEditor(String),          // jail_name
    CloseJailEditor,
    UpdateJailEditorContent(String), // new_content
    SaveJailConfiguration,
    JailConfigSaved(bool),          // success
    
    // IP management
    BanIP(String, Option<String>),
    UnbanIP(String),
    OpenBanDialog,
    CloseBanDialog,
    UpdateBanIPInput(String),
    UpdateBanDurationInput(String),
    SelectJailForBan(String),
    ConfirmBan,
    OpenUnbanConfirmation(String, String), // IP, Jail
    CloseUnbanConfirmation,
    ConfirmUnban,
    SelectBannedIP(usize),
    ExportBannedIPs,
    // Whitelist management
    AddToWhitelist(String),
    RemoveFromWhitelist(usize),
    OpenWhitelistDialog,
    CloseWhitelistDialog,
    UpdateWhitelistInput(String),
    SelectWhitelistIP(usize),
    
    // Configuration management
    SelectConfigFile(usize),
    OpenConfigEditor(String),     // file_path
    CloseConfigEditor,
    SaveConfigFile,
    BackupConfiguration,
    RestoreConfiguration,
    TestConfiguration,
    
    // Monitoring
    LogUpdate(LogEntry),
    RefreshData,
    
    // System
    Error(AppError),
    Quit,
}

#[derive(Debug, Clone)]
pub struct IpManagementState {
    pub ban_dialog_open: bool,
    pub ban_ip_input: String,
    pub selected_jail_for_ban: Option<String>,
    pub ban_dialog_field_index: usize, // 0=IP, 1=Jail (removed duration field)
    pub selected_banned_ip_index: usize,
    pub unban_confirmation_open: bool,
    pub ip_to_unban: Option<String>,
    pub jail_for_unban: Option<String>,
    pub whitelist_dialog_open: bool,
    pub whitelist_ip_input: String,
    pub selected_whitelist_index: usize,
}

impl Default for IpManagementState {
    fn default() -> Self {
        Self {
            ban_dialog_open: false,
            ban_ip_input: String::new(),
            selected_jail_for_ban: None,
            ban_dialog_field_index: 0, // Start with IP field
            selected_banned_ip_index: 0,
            unban_confirmation_open: false,
            ip_to_unban: None,
            jail_for_unban: None,
            whitelist_dialog_open: false,
            whitelist_ip_input: String::new(),
            selected_whitelist_index: 0,
        }
    }
}

pub struct AppState {
    pub current_screen: Screen,
    pub fail2ban_service: ServiceStatus,
    pub jails: HashMap<String, JailState>,
    pub available_jails: Vec<JailConfig>,
    pub banned_ips: Vec<BannedIP>,
    pub log_entries: Vec<LogEntry>,
    // Removed unused error_state field
    pub last_update: Instant,
    pub status_message: Option<(String, chrono::DateTime<chrono::Utc>)>,
    pub service_message: Option<String>,
    pub last_service_action: Option<(String, chrono::DateTime<chrono::Local>)>, // Action name and timestamp
    // Log filtering state
    pub log_filter: LogFilter,
    // Banned IP filtering state
    pub banned_ip_filter: BannedIpFilter,
    // Pagination for banned IPs
    pub banned_ip_pagination: BannedIpPagination,
    // Performance optimization - track last full IP refresh
    pub last_ip_full_refresh: Option<Instant>,
    // Cached filtered IPs to avoid re-filtering 18k items on every render
    pub cached_filtered_ips: Vec<BannedIP>,
    pub filter_cache_version: u64,
    pub filtered_log_entries: Vec<LogEntry>,
    pub log_search_query: String,
    pub log_search_active: bool,
    pub log_scroll_offset: usize,
    pub help_scroll_offset: usize,
    // Progress tracking
    pub current_operation: Option<OperationProgress>,
    // Loading state for banned IPs
    pub is_loading_banned_ips: bool,
    pub loading_modal: Option<LoadingModalState>,
    // Jail management
    pub selected_jail_index: usize,
    pub jail_scroll_offset: usize,
    // IP management state
    pub ip_management: IpManagementState,
    pub whitelist_ips: Vec<String>,
    
    // Dashboard focus state
    pub dashboard_focus: DashboardFocus,
    pub dashboard_jail_selected_index: usize,
    pub dashboard_banned_ip_selected_index: usize,
    pub dashboard_jail_table_state: TableState,
    pub dashboard_banned_ip_table_state: TableState,
    // Error dialog state
    pub error_dialog: Option<String>,
    // Jail editor state
    pub jail_editor: JailEditorState,
    // Configuration management state
    pub config_management: ConfigManagementState,
}

#[derive(Debug, Clone)]
pub struct JailEditorState {
    pub is_open: bool,
    pub jail_name: String,
    pub original_content: String,
    pub current_content: String,
    pub backup_path: Option<String>,
    pub cursor_position: usize,
    pub scroll_offset: usize,
    pub modified: bool,
}

#[derive(Debug, Clone)]
pub struct ConfigFile {
    pub path: String,
    pub description: String,
    pub exists: bool,
    pub editable: bool,
}

#[derive(Debug, Clone)]
pub struct LoadingModalState {
    pub title: String,
    pub message: String,
    pub progress: Option<u8>,  // 0-100 percentage
    pub started_at: Instant,
    pub animated_dots: String, // For animated "..." effect
}

impl LoadingModalState {
    pub fn new(title: String, message: String) -> Self {
        Self {
            title,
            message,
            progress: None,
            started_at: Instant::now(),
            animated_dots: "".to_string(),
        }
    }
    
    pub fn with_progress(mut self, progress: u8) -> Self {
        self.progress = Some(progress);
        self
    }
    
    pub fn update_message(&mut self, message: String) {
        self.message = message;
    }
    
    pub fn update_animated_dots(&mut self) {
        let elapsed = self.started_at.elapsed().as_millis();
        let dot_count = ((elapsed / 500) % 4) as usize; // Change every 500ms, cycle through 0-3 dots
        self.animated_dots = ".".repeat(dot_count);
    }
}

#[derive(Debug, Clone)]
pub struct ConfigManagementState {
    pub config_files: Vec<ConfigFile>,
    pub selected_file_index: usize,
    pub table_state: TableState,
    pub editor_open: bool,
    pub current_file_path: String,
    pub current_file_content: String,
    pub original_content: String,
    pub cursor_position: usize,
    pub scroll_offset: usize,
    pub modified: bool,
    pub cursor_blink_timer: std::time::Instant,
    pub cursor_visible: bool,
}

impl Default for JailEditorState {
    fn default() -> Self {
        Self {
            is_open: false,
            jail_name: String::new(),
            original_content: String::new(),
            current_content: String::new(),
            backup_path: None,
            cursor_position: 0,
            scroll_offset: 0,
            modified: false,
        }
    }
}

impl Default for ConfigManagementState {
    fn default() -> Self {
        let config_files = vec![
            ConfigFile {
                path: "/etc/fail2ban/jail.local".to_string(),
                description: "Local jail overrides (user modifications)".to_string(),
                exists: std::path::Path::new("/etc/fail2ban/jail.local").exists(),
                editable: true,
            },
            ConfigFile {
                path: "/etc/fail2ban/jail.conf".to_string(),
                description: "Main jail configuration (system default)".to_string(),
                exists: std::path::Path::new("/etc/fail2ban/jail.conf").exists(),
                editable: false, // Read-only system file
            },
            ConfigFile {
                path: "/etc/fail2ban/fail2ban.local".to_string(),
                description: "Local daemon configuration overrides".to_string(),
                exists: std::path::Path::new("/etc/fail2ban/fail2ban.local").exists(),
                editable: true,
            },
            ConfigFile {
                path: "/etc/fail2ban/fail2ban.conf".to_string(),
                description: "fail2ban daemon configuration".to_string(),
                exists: std::path::Path::new("/etc/fail2ban/fail2ban.conf").exists(),
                editable: false, // Read-only system file
            },
        ];
        
        Self {
            config_files,
            selected_file_index: 0,
            table_state: TableState::default(),
            editor_open: false,
            current_file_path: String::new(),
            current_file_content: String::new(),
            original_content: String::new(),
            cursor_position: 0,
            scroll_offset: 0,
            modified: false,
            cursor_blink_timer: std::time::Instant::now(),
            cursor_visible: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogFilter {
    pub level: Option<String>,
    pub jail: Option<String>,
    pub show_only_bans: bool,
    pub show_only_unbans: bool,
    pub time_range_hours: Option<u32>,
}

impl Default for LogFilter {
    fn default() -> Self {
        Self {
            level: None,
            jail: None,
            show_only_bans: false,
            show_only_unbans: false,
            time_range_hours: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BannedIpFilter {
    pub ip_starting_digit: Option<char>, // Filter by first digit of IP (1-9)
    pub jail: Option<String>,           // Filter by specific jail
    pub ban_age_hours: Option<u32>,     // Filter by ban age (recent vs old)
    pub remaining_time: Option<RemainingTimeFilter>, // Filter by remaining ban time
    pub version: u64, // Version number to track filter changes for caching
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RemainingTimeFilter {
    Soon,      // Unbans within 1 hour
    Today,     // Unbans within 24 hours
    ThisWeek,  // Unbans within 1 week
    Permanent, // Permanent bans (no unban time)
}

impl Default for BannedIpFilter {
    fn default() -> Self {
        Self {
            ip_starting_digit: None,
            jail: None,
            ban_age_hours: None,
            remaining_time: None,
            version: 0,
        }
    }
}

impl BannedIpFilter {
    fn has_active_filters(&self) -> bool {
        self.ip_starting_digit.is_some() ||
        self.jail.is_some() ||
        self.ban_age_hours.is_some() ||
        self.remaining_time.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct BannedIpPagination {
    pub page_size: usize,
    pub current_page: usize,
    pub total_items: usize,
}

impl Default for BannedIpPagination {
    fn default() -> Self {
        Self {
            page_size: 100,  // Show 100 IPs per page
            current_page: 0,
            total_items: 0,
        }
    }
}

impl BannedIpPagination {
    pub fn total_pages(&self) -> usize {
        if self.total_items == 0 { 1 } else { (self.total_items + self.page_size - 1) / self.page_size }
    }
    
    pub fn start_index(&self) -> usize {
        self.current_page * self.page_size
    }
    
    pub fn end_index(&self) -> usize {
        ((self.current_page + 1) * self.page_size).min(self.total_items)
    }
    
    pub fn next_page(&mut self) -> bool {
        if self.current_page < self.total_pages().saturating_sub(1) {
            self.current_page += 1;
            true
        } else {
            false
        }
    }
    
    pub fn prev_page(&mut self) -> bool {
        if self.current_page > 0 {
            self.current_page -= 1;
            true
        } else {
            false
        }
    }
    
    pub fn go_to_first_page(&mut self) {
        self.current_page = 0;
    }
    
    pub fn go_to_last_page(&mut self) {
        if self.total_items > 0 {
            self.current_page = self.total_pages().saturating_sub(1);
        }
    }
    
    pub fn update_total_items(&mut self, total: usize) {
        self.total_items = total;
        // Ensure current page is valid
        let max_page = self.total_pages().saturating_sub(1);
        if self.current_page > max_page {
            self.current_page = max_page;
        }
    }
}

#[derive(Debug, Clone)]
pub struct OperationProgress {
    pub operation_type: OperationType,
    pub progress_percent: u8,
    pub status_text: String,
    pub started_at: Instant,
    pub estimated_completion: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationType {
    ServiceRestart,
    ServiceStart,
    ServiceStop,
    ServiceReload,
    LogRefresh,
    DataRefresh,
    IpBan,
    IpUnban,
}

impl OperationType {
    pub fn display_name(&self) -> &'static str {
        match self {
            OperationType::ServiceRestart => "Restarting fail2ban service",
            OperationType::ServiceStart => "Starting fail2ban service",
            OperationType::ServiceStop => "Stopping fail2ban service",
            OperationType::ServiceReload => "Reloading configuration",
            OperationType::LogRefresh => "Refreshing logs",
            OperationType::DataRefresh => "Refreshing data",
            OperationType::IpBan => "Banning IP address",
            OperationType::IpUnban => "Unbanning IP address",
        }
    }
    
    pub fn estimated_duration(&self) -> Duration {
        match self {
            OperationType::ServiceRestart => Duration::from_secs(5),
            OperationType::ServiceStart => Duration::from_secs(3),
            OperationType::ServiceStop => Duration::from_secs(2),
            OperationType::ServiceReload => Duration::from_secs(2),
            OperationType::LogRefresh => Duration::from_millis(500),
            OperationType::DataRefresh => Duration::from_secs(1),
            OperationType::IpBan => Duration::from_millis(300),
            OperationType::IpUnban => Duration::from_millis(300),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        // Start with empty jail data - will be loaded during startup refresh
        let jails = HashMap::new();
        
        Self {
            current_screen: Screen::Dashboard,
            fail2ban_service: ServiceStatus::Running,
            jails,
            available_jails: Vec::new(),
            banned_ips: Vec::new(),
            log_entries: Vec::with_capacity(1000),
            last_update: Instant::now(),
            status_message: None,
            service_message: None,
            last_service_action: None,
            log_filter: LogFilter::default(),
            banned_ip_filter: BannedIpFilter::default(),
            banned_ip_pagination: BannedIpPagination::default(),
            last_ip_full_refresh: None,
            cached_filtered_ips: Vec::new(),
            filter_cache_version: 0,
            filtered_log_entries: Vec::new(),
            log_search_query: String::new(),
            log_search_active: false,
            log_scroll_offset: 0,
            help_scroll_offset: 0,
            current_operation: None,
            is_loading_banned_ips: false,
            loading_modal: None,
            selected_jail_index: 0,
            jail_scroll_offset: 0,
            ip_management: IpManagementState::default(),
            whitelist_ips: vec!["127.0.0.1".to_string(), "192.168.1.0/24".to_string()],
            dashboard_focus: DashboardFocus::default(),
            dashboard_jail_selected_index: 0,
            dashboard_banned_ip_selected_index: 0,
            dashboard_jail_table_state: TableState::default(),
            dashboard_banned_ip_table_state: TableState::default(),
            error_dialog: None,
            jail_editor: JailEditorState::default(),
            config_management: ConfigManagementState::default(),
        }
    }
}

pub struct App {
    state: AppState,
    should_quit: bool,
    system_service: SystemService,
    fail2ban_client: Fail2banClient,
    log_monitor: LogMonitor,
    auto_refresh_interval: Duration,
    last_auto_refresh: Instant,
    // Refreshing state
    is_refreshing: bool,
    refresh_display_start: Option<Instant>,
    // UI update timing (separate from data refresh)
    last_ui_update: Instant,
    ui_update_interval: Duration,
    // Staggered refresh timers to prevent blocking
    last_service_check: Instant,
    last_jail_refresh: Instant,
    last_ip_refresh: Instant,
    last_log_refresh: Instant,
    // Performance monitoring
    performance_stats: PerformanceStats,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Performance monitoring for PRD requirements
pub struct PerformanceStats {
    pub memory_usage_mb: f64,
    pub cpu_load: f64,
    pub refresh_time_ms: u64,
    pub log_entries_processed: usize,
    pub ui_render_time_ms: u64,
    pub last_performance_check: Instant,
}

impl Default for PerformanceStats {
    fn default() -> Self {
        Self {
            memory_usage_mb: 0.0,
            cpu_load: 0.0,
            refresh_time_ms: 0,
            log_entries_processed: 0,
            ui_render_time_ms: 0,
            last_performance_check: Instant::now(),
        }
    }
}

impl App {
    pub fn new(_config_path: Option<String>) -> Result<Self> {
        let log_path = LogMonitor::get_fail2ban_log_path();
        let log_monitor = LogMonitor::new(&log_path);
        
        let mut app = Self {
            state: AppState::default(),
            should_quit: false,
            system_service: SystemService::new("fail2ban"),
            fail2ban_client: Fail2banClient::new(),
            log_monitor,
            auto_refresh_interval: Duration::from_secs(5),
            last_auto_refresh: Instant::now(),
            is_refreshing: false,
            refresh_display_start: None,
            last_ui_update: Instant::now(),
            ui_update_interval: Duration::from_millis(500), // Update UI every 500ms for smooth time displays
            // Staggered refresh intervals to prevent blocking
            last_service_check: Instant::now().checked_sub(Duration::from_secs(10)).unwrap_or(Instant::now()),
            last_jail_refresh: Instant::now().checked_sub(Duration::from_secs(10)).unwrap_or(Instant::now()),
            last_ip_refresh: Instant::now().checked_sub(Duration::from_secs(20)).unwrap_or(Instant::now()),
            last_log_refresh: Instant::now().checked_sub(Duration::from_secs(10)).unwrap_or(Instant::now()),
            performance_stats: PerformanceStats::default(),
        };
        
        // Perform initial load - service status and jail data needed for interface
        log::info!("Application initialized, loading initial data...");
        app.refresh_service_status();
        app.refresh_jail_data();
        // Load available jails for configuration management (done once on startup)
        app.load_available_jails(); 
        // Skip IP loading on startup - will load when user navigates to IP section
        
        // Initialize dashboard states since we start on the dashboard
        app.initialize_dashboard_states();
        
        Ok(app)
    }
    
    /// Load whitelist IPs from fail2ban configuration if not already loaded
    fn load_whitelist_if_needed(&mut self) {
        // Only load if whitelist is empty or contains only defaults
        let has_only_defaults = self.state.whitelist_ips.len() <= 2 && 
            self.state.whitelist_ips.contains(&"127.0.0.1".to_string()) &&
            (self.state.whitelist_ips.len() == 1 || self.state.whitelist_ips.contains(&"192.168.1.0/24".to_string()));
        
        if self.state.whitelist_ips.is_empty() || has_only_defaults {
            match self.fail2ban_client.get_whitelist_ips() {
                Ok(loaded_ips) => {
                    if !loaded_ips.is_empty() {
                        self.state.whitelist_ips = loaded_ips;
                        log::info!("Loaded {} whitelist IPs from configuration", self.state.whitelist_ips.len());
                    }
                },
                Err(e) => {
                    log::error!("Failed to load whitelist from configuration: {}", e);
                    self.set_status_message("⚠ Failed to load whitelist from configuration");
                }
            }
        }
    }
    
    pub fn handle_events(&mut self) -> Result<bool> {
        let mut _should_redraw = false;
        // Handle refreshing display timeout (show "Refreshing..." for 1 second)
        if let Some(refresh_start) = self.refresh_display_start {
            if refresh_start.elapsed() >= Duration::from_secs(1) {
                self.is_refreshing = false;
                self.refresh_display_start = None;
            }
        }
        
        // Staggered refresh system to prevent blocking
        let mut any_refresh_needed = false;
        
        // Dynamic refresh intervals based on dataset size for extreme performance optimization
        let banned_ip_count = self.state.banned_ips.len();
        let is_large_dataset = banned_ip_count > 10000;
        let is_massive_dataset = banned_ip_count > 15000;
        
        // Service status refresh - dramatically reduced for large datasets
        let service_refresh_interval = if is_massive_dataset {
            Duration::from_secs(300) // 5 minutes for massive datasets
        } else if is_large_dataset {
            Duration::from_secs(60)  // 1 minute for large datasets
        } else {
            Duration::from_secs(10)  // 10 seconds for normal datasets
        };
        
        if self.last_service_check.elapsed() >= service_refresh_interval {
            if !is_massive_dataset {  // Skip service refresh entirely for massive datasets
                self.refresh_service_status();
            }
            self.last_service_check = Instant::now();
            any_refresh_needed = true;
        }
        
        // Jail data refresh - dramatically reduced for large datasets
        let jail_refresh_interval = if is_massive_dataset {
            Duration::from_secs(300) // 5 minutes for massive datasets (18k+ IPs)
        } else if is_large_dataset {
            Duration::from_secs(60)  // 1 minute for large datasets (10k+ IPs)
        } else {
            Duration::from_secs(10)  // 10 seconds for normal datasets
        };
        
        if self.last_jail_refresh.elapsed() >= jail_refresh_interval {
            if !is_massive_dataset {  // Skip jail refresh entirely for massive datasets
                self.refresh_jail_data();
            }
            self.last_jail_refresh = Instant::now();
            any_refresh_needed = true;
        }
        
        // IP data refresh - even more conservative for large datasets
        let ip_refresh_interval = if is_massive_dataset {
            Duration::from_secs(120) // 2 minutes for massive datasets
        } else if is_large_dataset {
            Duration::from_secs(60)  // 1 minute for large datasets
        } else {
            Duration::from_secs(30)  // 30 seconds for normal datasets
        };
        
        if self.last_ip_refresh.elapsed() >= ip_refresh_interval {
            // Use two-phase loading: first set loading state, then load on next cycle
            if !self.state.is_loading_banned_ips {
                self.start_banned_ip_loading();
            } else {
                self.continue_banned_ip_loading();
                self.last_ip_refresh = Instant::now();
            }
            any_refresh_needed = true;
        }
        
        // Log entries - reduced frequency for large datasets
        let log_refresh_interval = if is_large_dataset {
            Duration::from_secs(30)  // 30 seconds for large datasets
        } else {
            Duration::from_secs(10)  // 10 seconds for normal datasets
        };
        
        if self.last_log_refresh.elapsed() >= log_refresh_interval {
            if !is_massive_dataset {  // Skip log refresh for massive datasets unless explicitly requested
                self.refresh_log_data();
            }
            self.last_log_refresh = Instant::now();
            any_refresh_needed = true;
        }
        
        // Update refresh display state
        if any_refresh_needed && !self.is_refreshing {
            self.is_refreshing = true;
            self.refresh_display_start = Some(Instant::now());
            self.last_auto_refresh = Instant::now();
        }
        
        // Check for UI updates (for time displays) - separate from data refresh
        if self.last_ui_update.elapsed() >= self.ui_update_interval {
            // Force UI redraw for time-sensitive elements without full data refresh
            self.last_ui_update = Instant::now();
            _should_redraw = true; // Trigger redraw for smooth time updates
        }
        
        // Update performance stats and run optimizations - reduced frequency for large datasets
        if !is_massive_dataset || self.performance_stats.last_performance_check.elapsed() >= Duration::from_secs(60) {
            self.update_performance_stats();
            self.optimize_performance();
        }
        
        // Update loading modal animation if present
        if let Some(ref mut modal) = self.state.loading_modal {
            modal.update_animated_dots();
        }
        
        // Update cursor blinking for config editor
        if self.state.config_management.editor_open {
            if self.state.config_management.cursor_blink_timer.elapsed() >= Duration::from_millis(500) {
                self.state.config_management.cursor_visible = !self.state.config_management.cursor_visible;
                self.state.config_management.cursor_blink_timer = Instant::now();
            }
        }
        
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Debug key presses when on Dashboard with BannedIPs focus
                if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs {
                    log::debug!("Key pressed: {:?}, Screen: {:?}, Focus: {:?}", key.code, self.state.current_screen, self.state.dashboard_focus);
                }
                
                match key.code {
                    // CSV EXPORT - X KEY
                    KeyCode::Char('X') | KeyCode::Char('x') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs => {
                        if !self.state.banned_ips.is_empty() {
                            self.export_banned_ips_to_csv();
                            self.set_status_message(&format!("✓ EXPORTED {} BANNED IPs TO CSV FILE!", self.state.banned_ips.len()));
                        } else {
                            self.set_status_message("⚠ NO BANNED IPs TO EXPORT");
                        }
                    },
                    // JAIL EDITOR KEY HANDLING (HIGHEST PRIORITY - must come first)
                    KeyCode::Esc if self.state.jail_editor.is_open => {
                        self.handle_message(AppMessage::CloseJailEditor);
                    },
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) && self.state.jail_editor.is_open => {
                        self.handle_message(AppMessage::SaveJailConfiguration);
                    },
                    KeyCode::Enter if self.state.jail_editor.is_open => {
                        let mut content = self.state.jail_editor.current_content.clone();
                        content.insert(self.state.jail_editor.cursor_position, '\n');
                        self.state.jail_editor.cursor_position += 1;
                        self.state.jail_editor.modified = content != self.state.jail_editor.original_content;
                        self.handle_message(AppMessage::UpdateJailEditorContent(content));
                        self.update_editor_scroll();
                    },
                    KeyCode::Char(c) if self.state.jail_editor.is_open => {
                        let mut content = self.state.jail_editor.current_content.clone();
                        content.insert(self.state.jail_editor.cursor_position, c);
                        self.state.jail_editor.cursor_position += 1;
                        self.state.jail_editor.modified = content != self.state.jail_editor.original_content;
                        self.handle_message(AppMessage::UpdateJailEditorContent(content));
                        self.update_editor_scroll();
                    },
                    KeyCode::Backspace if self.state.jail_editor.is_open => {
                        if self.state.jail_editor.cursor_position > 0 {
                            let mut content = self.state.jail_editor.current_content.clone();
                            content.remove(self.state.jail_editor.cursor_position - 1);
                            self.state.jail_editor.cursor_position -= 1;
                            self.state.jail_editor.modified = content != self.state.jail_editor.original_content;
                            self.handle_message(AppMessage::UpdateJailEditorContent(content));
                            self.update_editor_scroll();
                        }
                    },
                    KeyCode::Left if self.state.jail_editor.is_open => {
                        let new_pos = self.move_cursor_left();
                        if new_pos != self.state.jail_editor.cursor_position {
                            self.state.jail_editor.cursor_position = new_pos;
                            self.update_editor_scroll();
                        }
                    },
                    KeyCode::Right if self.state.jail_editor.is_open => {
                        let new_pos = self.move_cursor_right();
                        if new_pos != self.state.jail_editor.cursor_position {
                            self.state.jail_editor.cursor_position = new_pos;
                            self.update_editor_scroll();
                        }
                    },
                    KeyCode::Up if self.state.jail_editor.is_open => {
                        let new_pos = self.move_cursor_up();
                        if new_pos != self.state.jail_editor.cursor_position {
                            self.state.jail_editor.cursor_position = new_pos;
                            self.update_editor_scroll();
                        }
                    },
                    KeyCode::Down if self.state.jail_editor.is_open => {
                        let new_pos = self.move_cursor_down();
                        if new_pos != self.state.jail_editor.cursor_position {
                            self.state.jail_editor.cursor_position = new_pos;
                            self.update_editor_scroll();
                        }
                    },
                    
                    // CONFIG EDITOR KEY HANDLING (SECOND HIGHEST PRIORITY)
                    KeyCode::Esc if self.state.config_management.editor_open => {
                        self.handle_message(AppMessage::CloseConfigEditor);
                    },
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) && self.state.config_management.editor_open => {
                        self.handle_message(AppMessage::SaveConfigFile);
                    },
                    KeyCode::Enter if self.state.config_management.editor_open => {
                        let mut content = self.state.config_management.current_file_content.clone();
                        content.insert(self.state.config_management.cursor_position, '\n');
                        self.state.config_management.cursor_position += 1;
                        self.state.config_management.modified = content != self.state.config_management.original_content;
                        self.state.config_management.current_file_content = content;
                        self.state.config_management.cursor_visible = true;
                        self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                        self.update_config_editor_scroll();
                    },
                    KeyCode::Char(c) if self.state.config_management.editor_open => {
                        let mut content = self.state.config_management.current_file_content.clone();
                        content.insert(self.state.config_management.cursor_position, c);
                        self.state.config_management.cursor_position += 1;
                        self.state.config_management.modified = content != self.state.config_management.original_content;
                        self.state.config_management.current_file_content = content;
                        self.state.config_management.cursor_visible = true;
                        self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                        self.update_config_editor_scroll();
                    },
                    KeyCode::Backspace if self.state.config_management.editor_open => {
                        if self.state.config_management.cursor_position > 0 {
                            let mut content = self.state.config_management.current_file_content.clone();
                            content.remove(self.state.config_management.cursor_position - 1);
                            self.state.config_management.cursor_position -= 1;
                            self.state.config_management.modified = content != self.state.config_management.original_content;
                            self.state.config_management.current_file_content = content;
                            self.state.config_management.cursor_visible = true;
                            self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                            self.update_config_editor_scroll();
                        }
                    },
                    KeyCode::Left if self.state.config_management.editor_open => {
                        let new_pos = self.move_config_cursor_left();
                        if new_pos != self.state.config_management.cursor_position {
                            self.state.config_management.cursor_position = new_pos;
                            self.state.config_management.cursor_visible = true;
                            self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                            self.update_config_editor_scroll();
                        }
                    },
                    KeyCode::Right if self.state.config_management.editor_open => {
                        let new_pos = self.move_config_cursor_right();
                        if new_pos != self.state.config_management.cursor_position {
                            self.state.config_management.cursor_position = new_pos;
                            self.state.config_management.cursor_visible = true;
                            self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                            self.update_config_editor_scroll();
                        }
                    },
                    KeyCode::Up if self.state.config_management.editor_open => {
                        let new_pos = self.move_config_cursor_up();
                        if new_pos != self.state.config_management.cursor_position {
                            self.state.config_management.cursor_position = new_pos;
                            self.state.config_management.cursor_visible = true;
                            self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                            self.update_config_editor_scroll();
                        }
                    },
                    KeyCode::Down if self.state.config_management.editor_open => {
                        let new_pos = self.move_config_cursor_down();
                        if new_pos != self.state.config_management.cursor_position {
                            self.state.config_management.cursor_position = new_pos;
                            self.state.config_management.cursor_visible = true;
                            self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                            self.update_config_editor_scroll();
                        }
                    },
                    
                    // GLOBAL HOTKEYS (only when NO editor is open)
                    KeyCode::Char('q') | KeyCode::Char('Q') if !self.state.jail_editor.is_open && !self.state.config_management.editor_open => {
                        self.should_quit = true;
                    },
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.config_management.editor_open => {
                        self.should_quit = true;
                    },
                    // Global IP ban dialog - 'B' key (accessible from anywhere except config screen and any editor)
                    KeyCode::Char('B') | KeyCode::Char('b') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.ip_management.ban_dialog_open && self.state.current_screen != Screen::Configuration && !self.state.jail_editor.is_open && !self.state.config_management.editor_open => {
                        self.handle_message(AppMessage::OpenBanDialog);
                    },
                    // Dialog-specific Esc handling (must come before general Esc)
                    KeyCode::Esc if self.state.error_dialog.is_some() => {
                        self.state.error_dialog = None;
                    },
                    KeyCode::Esc if self.state.ip_management.ban_dialog_open => {
                        self.handle_message(AppMessage::CloseBanDialog);
                    },
                    KeyCode::Esc if self.state.ip_management.unban_confirmation_open => {
                        self.handle_message(AppMessage::CloseUnbanConfirmation);
                    },
                    KeyCode::Esc if self.state.ip_management.whitelist_dialog_open => {
                        self.handle_message(AppMessage::CloseWhitelistDialog);
                    },
                    // Jail Editor key bindings (must be before general Esc handler)
                    KeyCode::Esc if self.state.jail_editor.is_open => {
                        self.handle_message(AppMessage::CloseJailEditor);
                    },
                    KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) && self.state.jail_editor.is_open => {
                        self.handle_message(AppMessage::SaveJailConfiguration);
                    },
                    KeyCode::Esc if !self.state.jail_editor.is_open && !self.state.config_management.editor_open => {
                        // ESC returns to dashboard (disabled when any editor is open)
                        self.state.current_screen = Screen::Dashboard;
                        self.initialize_dashboard_states();
                    },
                    KeyCode::Char('R') | KeyCode::Char('r') if self.state.current_screen != Screen::Dashboard => {
                        // Handle screen-specific R key refresh actions (except Dashboard)
                        match self.state.current_screen {
                            Screen::Logs => {
                                self.start_operation(OperationType::LogRefresh);
                                self.update_operation_progress(50, Some("Loading recent logs...".to_string()));
                                self.load_recent_logs();
                                self.complete_operation(true, Some("✓ Logs refreshed".to_string()));
                            },
                            _ => {
                                // R key not applicable for this screen
                            }
                        }
                    },
                    
                    // HELP SCREEN SCROLLING (when help screen is active)
                    KeyCode::Up if self.state.current_screen == Screen::Help => {
                        if self.state.help_scroll_offset > 0 {
                            self.state.help_scroll_offset = self.state.help_scroll_offset.saturating_sub(1);
                        }
                    },
                    KeyCode::Down if self.state.current_screen == Screen::Help => {
                        // Get help content to calculate max scroll
                        let help_content = self.get_contextual_help();
                        let content_height = help_content.len();
                        let max_scroll = content_height.saturating_sub(20); // Approximate available height
                        self.state.help_scroll_offset = (self.state.help_scroll_offset + 1).min(max_scroll);
                    },
                    KeyCode::PageUp if self.state.current_screen == Screen::Help => {
                        self.state.help_scroll_offset = self.state.help_scroll_offset.saturating_sub(10);
                    },
                    KeyCode::PageDown if self.state.current_screen == Screen::Help => {
                        let help_content = self.get_contextual_help();
                        let content_height = help_content.len();
                        let max_scroll = content_height.saturating_sub(20); // Approximate available height
                        self.state.help_scroll_offset = (self.state.help_scroll_offset + 10).min(max_scroll);
                    },
                    KeyCode::Home if self.state.current_screen == Screen::Help => {
                        self.state.help_scroll_offset = 0;
                    },
                    
                    // Single-key navigation (only when not conflicting and not in any editor or ban dialog)
                    KeyCode::Char('h') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open => {
                        self.state.current_screen = Screen::Help;
                        self.state.help_scroll_offset = 0; // Reset scroll when entering help
                    },
                    KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open && self.state.current_screen != Screen::Logs => {
                        self.state.current_screen = Screen::Configuration;
                        self.initialize_configuration_states();
                    },
                    // Removed global 'r' handler - it conflicts with screen-specific 'R' handlers
                    // Users should use 'f' for global refresh instead
                    KeyCode::Char('l') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open => {
                        self.state.current_screen = Screen::Logs;
                        // Load recent logs when switching to logs screen
                        self.load_recent_logs();
                    },
                    KeyCode::Char('w') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open => {
                        self.state.current_screen = Screen::Whitelist;
                        self.load_whitelist_if_needed();
                    },
                    KeyCode::Char('g') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open => {
                        self.state.current_screen = Screen::Settings;
                    },
                    KeyCode::Char('i') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open => {
                        self.state.current_screen = Screen::About;
                    },
                    KeyCode::Char('0') if self.state.current_screen == Screen::Logs && !self.state.jail_editor.is_open => {
                        self.clear_log_filters();
                    },
                    
                    // Banned IP filtering (Dashboard with BannedIPs focus) - MUST come before global handlers
                    KeyCode::Char('0') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && !self.state.jail_editor.is_open => {
                        self.clear_banned_ip_filters();
                    },
                    KeyCode::Char('1') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && !self.state.jail_editor.is_open => {
                        self.cycle_ip_digit_filter();
                    },
                    KeyCode::Char('2') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && !self.state.jail_editor.is_open => {
                        self.cycle_jail_filter();
                    },
                    KeyCode::Char('3') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && !self.state.jail_editor.is_open => {
                        self.cycle_ban_age_filter();
                    },
                    KeyCode::Char('4') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && !self.state.jail_editor.is_open => {
                        self.cycle_remaining_time_filter();
                    },
                    
                    KeyCode::Char('f') | KeyCode::Char('F') if !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open && !self.state.ip_management.ban_dialog_open => {
                        // Global refresh - returns to dashboard with fresh data
                        self.start_operation(OperationType::DataRefresh);
                        self.update_operation_progress(25, Some("Refreshing service status...".to_string()));
                        // Use staggered refresh system instead of full refresh
                        self.refresh_service_status();
                        self.complete_operation(true, Some("✓ Data refreshed".to_string()));
                        
                        // Record refresh timestamp for service status display
                        self.state.last_service_action = Some(("Application Data Refreshed".to_string(), chrono::Local::now()));
                        
                        self.state.current_screen = Screen::Dashboard;
                        self.initialize_dashboard_states();
                    },
                    KeyCode::Home if !self.state.jail_editor.is_open && !self.state.config_management.editor_open => {
                        self.state.current_screen = Screen::Dashboard;
                        self.initialize_dashboard_states();
                    },
                    // Whitelist management actions (Whitelist screen)
                    KeyCode::Char('a') | KeyCode::Char('A') if self.state.current_screen == Screen::Whitelist && !self.state.ip_management.whitelist_dialog_open && !self.state.jail_editor.is_open => {
                        self.handle_message(AppMessage::OpenWhitelistDialog);
                    },
                    KeyCode::Char('d') | KeyCode::Char('D') if self.state.current_screen == Screen::Whitelist && !self.state.ip_management.whitelist_dialog_open && !self.state.jail_editor.is_open => {
                        let selected_index = self.state.ip_management.selected_whitelist_index;
                        if selected_index < self.state.whitelist_ips.len() {
                            self.handle_message(AppMessage::RemoveFromWhitelist(selected_index));
                        }
                    },
                    KeyCode::Up if self.state.current_screen == Screen::Whitelist && !self.state.ip_management.whitelist_dialog_open => {
                        if self.state.ip_management.selected_whitelist_index > 0 {
                            self.handle_message(AppMessage::SelectWhitelistIP(self.state.ip_management.selected_whitelist_index - 1));
                        }
                    },
                    KeyCode::Down if self.state.current_screen == Screen::Whitelist && !self.state.ip_management.whitelist_dialog_open => {
                        if !self.state.whitelist_ips.is_empty() && self.state.ip_management.selected_whitelist_index < self.state.whitelist_ips.len() - 1 {
                            self.handle_message(AppMessage::SelectWhitelistIP(self.state.ip_management.selected_whitelist_index + 1));
                        }
                    },
                    // Global dialog handling (accessible from any screen)
                    KeyCode::Enter if self.state.ip_management.ban_dialog_open => {
                        self.handle_message(AppMessage::ConfirmBan);
                    },
                    KeyCode::Enter if self.state.ip_management.unban_confirmation_open => {
                        self.handle_message(AppMessage::ConfirmUnban);
                    },
                    KeyCode::Enter if self.state.ip_management.whitelist_dialog_open => {
                        if !self.state.ip_management.whitelist_ip_input.trim().is_empty() {
                            self.handle_message(AppMessage::AddToWhitelist(self.state.ip_management.whitelist_ip_input.clone()));
                        }
                    },
                    KeyCode::Char('C') | KeyCode::Char('c') if self.state.current_screen == Screen::Logs && !key.modifiers.contains(KeyModifiers::CONTROL) && !self.state.jail_editor.is_open => {
                        self.state.log_entries.clear();
                        self.state.filtered_log_entries.clear();
                        self.set_status_message("✓ Log buffer cleared");
                    },
                    KeyCode::Char('1') if self.state.current_screen == Screen::Logs && !self.state.jail_editor.is_open => {
                        self.cycle_level_filter();
                    },
                    KeyCode::Char('2') if self.state.current_screen == Screen::Logs && !self.state.jail_editor.is_open => {
                        self.cycle_time_filter();
                    },
                    KeyCode::Char('3') if self.state.current_screen == Screen::Logs && !self.state.jail_editor.is_open => {
                        self.toggle_filter_bans_only();
                    },
                    KeyCode::Char('4') if self.state.current_screen == Screen::Logs && !self.state.jail_editor.is_open => {
                        self.toggle_filter_unbans_only();
                    },
                    KeyCode::Up if self.state.current_screen == Screen::Logs => {
                        self.scroll_logs_up();
                    },
                    KeyCode::Down if self.state.current_screen == Screen::Logs => {
                        self.scroll_logs_down();
                    },
                    
                    // Ban dialog navigation
                    KeyCode::Tab if self.state.ip_management.ban_dialog_open => {
                        self.state.ip_management.ban_dialog_field_index = 
                            (self.state.ip_management.ban_dialog_field_index + 1) % 2;
                    },
                    KeyCode::BackTab if self.state.ip_management.ban_dialog_open => {
                        self.state.ip_management.ban_dialog_field_index = 
                            if self.state.ip_management.ban_dialog_field_index == 0 { 1 } else { 0 };
                    },
                    KeyCode::Up if self.state.ip_management.ban_dialog_open && self.state.ip_management.ban_dialog_field_index == 1 => {
                        // Jail selection - previous jail
                        let jails: Vec<String> = self.state.jails.keys().cloned().collect();
                        if !jails.is_empty() {
                            let current_jail = self.state.ip_management.selected_jail_for_ban.as_ref();
                            let current_index = current_jail
                                .and_then(|jail| jails.iter().position(|j| j == jail))
                                .unwrap_or(0);
                            let new_index = if current_index == 0 { jails.len() - 1 } else { current_index - 1 };
                            self.state.ip_management.selected_jail_for_ban = Some(jails[new_index].clone());
                        }
                    },
                    KeyCode::Down if self.state.ip_management.ban_dialog_open && self.state.ip_management.ban_dialog_field_index == 1 => {
                        // Jail selection - next jail
                        let jails: Vec<String> = self.state.jails.keys().cloned().collect();
                        if !jails.is_empty() {
                            let current_jail = self.state.ip_management.selected_jail_for_ban.as_ref();
                            let current_index = current_jail
                                .and_then(|jail| jails.iter().position(|j| j == jail))
                                .unwrap_or(0);
                            let new_index = (current_index + 1) % jails.len();
                            self.state.ip_management.selected_jail_for_ban = Some(jails[new_index].clone());
                        }
                    },
                    // Character input for dialogs
                    KeyCode::Char(c) if self.state.ip_management.ban_dialog_open => {
                        match self.state.ip_management.ban_dialog_field_index {
                            0 => self.state.ip_management.ban_ip_input.push(c), // IP field
                            _ => {}, // Jail field doesn't accept direct input
                        }
                    },
                    KeyCode::Char(c) if self.state.ip_management.whitelist_dialog_open => {
                        self.state.ip_management.whitelist_ip_input.push(c);
                    },
                    KeyCode::Backspace if self.state.ip_management.ban_dialog_open => {
                        match self.state.ip_management.ban_dialog_field_index {
                            0 => { self.state.ip_management.ban_ip_input.pop(); }, // IP field
                            _ => {}, // Jail field doesn't accept backspace
                        }
                    },
                    KeyCode::Backspace if self.state.ip_management.whitelist_dialog_open => {
                        self.state.ip_management.whitelist_ip_input.pop();
                    },
                    // Configuration page navigation
                    KeyCode::Up if self.state.current_screen == Screen::Configuration && !self.state.config_management.editor_open => {
                        if self.state.config_management.selected_file_index > 0 {
                            self.state.config_management.selected_file_index -= 1;
                            self.state.config_management.table_state.select(Some(self.state.config_management.selected_file_index));
                        }
                    },
                    KeyCode::Down if self.state.current_screen == Screen::Configuration && !self.state.config_management.editor_open => {
                        if self.state.config_management.selected_file_index < self.state.config_management.config_files.len().saturating_sub(1) {
                            self.state.config_management.selected_file_index += 1;
                            self.state.config_management.table_state.select(Some(self.state.config_management.selected_file_index));
                        }
                    },
                    KeyCode::Enter if self.state.current_screen == Screen::Configuration && !self.state.config_management.editor_open => {
                        let selected_file = &self.state.config_management.config_files[self.state.config_management.selected_file_index];
                        if selected_file.exists && selected_file.editable {
                            self.handle_message(AppMessage::OpenConfigEditor(selected_file.path.clone()));
                        } else if !selected_file.exists {
                            self.set_status_message(&format!("⚠ File does not exist: {}", selected_file.path));
                        } else {
                            self.set_status_message(&format!("⚠ File is not editable: {}", selected_file.path));
                        }
                    },
                    KeyCode::Char('e') | KeyCode::Char('E') if self.state.current_screen == Screen::Configuration && !self.state.config_management.editor_open => {
                        let selected_file = &self.state.config_management.config_files[self.state.config_management.selected_file_index];
                        if selected_file.exists && selected_file.editable {
                            self.handle_message(AppMessage::OpenConfigEditor(selected_file.path.clone()));
                        } else if !selected_file.exists {
                            self.set_status_message(&format!("⚠ File does not exist: {}", selected_file.path));
                        } else {
                            self.set_status_message(&format!("⚠ File is not editable: {}", selected_file.path));
                        }
                    },
                    KeyCode::Char('b') | KeyCode::Char('B') if self.state.current_screen == Screen::Configuration && !self.state.config_management.editor_open => {
                        self.handle_message(AppMessage::BackupConfiguration);
                    },
                    KeyCode::Char('r') | KeyCode::Char('R') if self.state.current_screen == Screen::Configuration && !self.state.config_management.editor_open => {
                        self.handle_message(AppMessage::RestoreConfiguration);
                    },
                    KeyCode::Char('t') | KeyCode::Char('T') if self.state.current_screen == Screen::Configuration && !self.state.config_management.editor_open => {
                        self.handle_message(AppMessage::TestConfiguration);
                    },
                    
                    // Dashboard focus navigation
                    KeyCode::Tab if self.state.current_screen == Screen::Dashboard => {
                        self.state.dashboard_focus = match self.state.dashboard_focus {
                            DashboardFocus::Jails => DashboardFocus::BannedIPs,
                            DashboardFocus::BannedIPs => DashboardFocus::Jails,
                        };
                        // Update table states when switching focus
                        match self.state.dashboard_focus {
                            DashboardFocus::Jails => {
                                self.state.dashboard_jail_table_state.select(Some(self.state.dashboard_jail_selected_index));
                            },
                            DashboardFocus::BannedIPs => {
                                self.state.dashboard_banned_ip_table_state.select(Some(self.state.dashboard_banned_ip_selected_index));
                                
                                // On-demand loading: if banned IPs are empty, trigger immediate load
                                if self.state.banned_ips.is_empty() && matches!(self.state.fail2ban_service, ServiceStatus::Running) {
                                    log::info!("User switched to banned IPs view - triggering on-demand IP data load");
                                    if !self.state.is_loading_banned_ips {
                                        self.start_banned_ip_loading();
                                    }
                                }
                            },
                        }
                    },
                    // Dashboard jail table navigation
                    KeyCode::Up if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::Jails => {
                        if self.state.dashboard_jail_selected_index > 0 {
                            self.state.dashboard_jail_selected_index -= 1;
                            self.state.dashboard_jail_table_state.select(Some(self.state.dashboard_jail_selected_index));
                        }
                    },
                    KeyCode::Down if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::Jails => {
                        let sorted_jails = self.get_sorted_jails_for_display();
                        if self.state.dashboard_jail_selected_index < sorted_jails.len().saturating_sub(1) {
                            self.state.dashboard_jail_selected_index += 1;
                            self.state.dashboard_jail_table_state.select(Some(self.state.dashboard_jail_selected_index));
                        }
                    },
                    // Dashboard recent activity table navigation
                    KeyCode::Up if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs => {
                        if self.state.dashboard_banned_ip_selected_index > 0 {
                            self.state.dashboard_banned_ip_selected_index -= 1;
                            self.state.dashboard_banned_ip_table_state.select(Some(self.state.dashboard_banned_ip_selected_index));
                        }
                    },
                    KeyCode::Down if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs => {
                        let filtered_count = self.get_filtered_banned_ips().len();
                        if self.state.dashboard_banned_ip_selected_index < filtered_count.saturating_sub(1) {
                            self.state.dashboard_banned_ip_selected_index += 1;
                            self.state.dashboard_banned_ip_table_state.select(Some(self.state.dashboard_banned_ip_selected_index));
                        }
                    },
                    
                    // Pagination controls for banned IPs - Using comma/period keys (universal and no conflicts)
                    KeyCode::Char('.') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open => {
                        log::debug!("Period . pressed - attempting next page. Current page: {}, Total pages: {}", 
                            self.state.banned_ip_pagination.current_page + 1, 
                            self.state.banned_ip_pagination.total_pages());
                        if self.state.banned_ip_pagination.next_page() {
                            self.state.dashboard_banned_ip_selected_index = 0;
                            self.state.dashboard_banned_ip_table_state.select(Some(0));
                            self.set_status_message(&format!("Page {} of {}", 
                                self.state.banned_ip_pagination.current_page + 1, 
                                self.state.banned_ip_pagination.total_pages()));
                            log::debug!("Successfully moved to next page");
                        } else {
                            self.set_status_message("Already on last page");
                            log::debug!("Already on last page");
                        }
                    },
                    KeyCode::Char(',') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && !self.state.jail_editor.is_open && !self.state.config_management.editor_open && !self.state.ip_management.ban_dialog_open => {
                        log::debug!("Comma , pressed - attempting previous page. Current page: {}, Total pages: {}", 
                            self.state.banned_ip_pagination.current_page + 1, 
                            self.state.banned_ip_pagination.total_pages());
                        if self.state.banned_ip_pagination.prev_page() {
                            self.state.dashboard_banned_ip_selected_index = 0;
                            self.state.dashboard_banned_ip_table_state.select(Some(0));
                            self.set_status_message(&format!("Page {} of {}", 
                                self.state.banned_ip_pagination.current_page + 1, 
                                self.state.banned_ip_pagination.total_pages()));
                            log::debug!("Successfully moved to previous page");
                        } else {
                            self.set_status_message("Already on first page");
                            log::debug!("Already on first page");
                        }
                    },
                    // First/Last page shortcuts
                    KeyCode::Home if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.state.banned_ip_pagination.go_to_first_page();
                        self.state.dashboard_banned_ip_selected_index = 0;
                        self.state.dashboard_banned_ip_table_state.select(Some(0));
                        self.set_status_message("First page");
                    },
                    KeyCode::End if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs && key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.state.banned_ip_pagination.go_to_last_page();
                        self.state.dashboard_banned_ip_selected_index = 0;
                        self.state.dashboard_banned_ip_table_state.select(Some(0));
                        self.set_status_message("Last page");
                    },
                    // Dashboard jail enable/disable
                    KeyCode::Enter if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::Jails => {
                        let sorted_jails = self.get_sorted_jails_for_display();
                        if self.state.dashboard_jail_selected_index < sorted_jails.len() {
                            let jail_name = sorted_jails[self.state.dashboard_jail_selected_index].name.clone();
                            let current_enabled = sorted_jails[self.state.dashboard_jail_selected_index].enabled;
                            self.handle_message(AppMessage::SetJailEnabled(jail_name, !current_enabled));
                        }
                    },
                    // Dashboard screen-specific ENTER handling (dialogs are handled globally above)
                    KeyCode::Enter if self.state.current_screen == Screen::Dashboard => {
                        // Dashboard-specific ENTER actions go here if needed in the future
                    },
                    // Dashboard jail editor
                    KeyCode::Char('E') | KeyCode::Char('e') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::Jails => {
                        let sorted_jails = self.get_sorted_jails_for_display();
                        if self.state.dashboard_jail_selected_index < sorted_jails.len() {
                            let jail_name = sorted_jails[self.state.dashboard_jail_selected_index].name.clone();
                            self.handle_message(AppMessage::OpenJailEditor(jail_name));
                        }
                    },
                    // Dashboard whitelist management
                    KeyCode::Char('W') | KeyCode::Char('w') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs => {
                        self.state.ip_management.whitelist_dialog_open = true;
                        self.state.ip_management.whitelist_ip_input.clear();
                    },
                    // Dashboard IP unbanning
                    KeyCode::Char('U') | KeyCode::Char('u') if self.state.current_screen == Screen::Dashboard && self.state.dashboard_focus == DashboardFocus::BannedIPs => {
                        if !self.state.banned_ips.is_empty() && self.state.dashboard_banned_ip_selected_index < self.state.banned_ips.len() {
                            let banned_ip = &self.state.banned_ips[self.state.dashboard_banned_ip_selected_index];
                            self.state.ip_management.unban_confirmation_open = true;
                            self.state.ip_management.ip_to_unban = Some(banned_ip.ip.clone());
                            self.state.ip_management.jail_for_unban = Some(banned_ip.jail.clone());
                        }
                    },
                    // Dashboard service actions
                    KeyCode::Char('R') | KeyCode::Char('r') if self.state.current_screen == Screen::Dashboard && !self.state.ip_management.ban_dialog_open && !self.state.ip_management.whitelist_dialog_open && !self.state.ip_management.unban_confirmation_open && !self.state.jail_editor.is_open => {
                        self.handle_service_action(ServiceAction::Restart);
                    },
                    KeyCode::Char('S') | KeyCode::Char('s') if self.state.current_screen == Screen::Dashboard && !self.state.ip_management.ban_dialog_open && !self.state.ip_management.whitelist_dialog_open && !self.state.ip_management.unban_confirmation_open && !self.state.jail_editor.is_open => {
                        self.handle_service_action(ServiceAction::Start);
                    },
                    KeyCode::Char('T') | KeyCode::Char('t') if self.state.current_screen == Screen::Dashboard && !self.state.ip_management.ban_dialog_open && !self.state.ip_management.whitelist_dialog_open && !self.state.ip_management.unban_confirmation_open && !self.state.jail_editor.is_open => {
                        self.handle_service_action(ServiceAction::Stop);
                    },
                    KeyCode::Char('D') | KeyCode::Char('d') if self.state.current_screen == Screen::Dashboard && !self.state.ip_management.ban_dialog_open && !self.state.ip_management.whitelist_dialog_open && !self.state.ip_management.unban_confirmation_open && !self.state.jail_editor.is_open => {
                        self.handle_service_action(ServiceAction::Reload);
                    },
                    // Number keys for quick jail navigation
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        let index = c.to_digit(10).unwrap() as usize;
                        if index > 0 && index <= self.state.jails.len() {
                            // Quick jail selection functionality
                            log::debug!("Quick jail selection: {}", index);
                        }
                    },
                    _ => {}
                }
            }
        }
        
        Ok(self.should_quit)
    }
    
    // Removed legacy refresh_data function - replaced with optimized individual refresh functions
    
    fn refresh_service_status(&mut self) {
        // Lightweight service status check
        match self.system_service.get_status() {
            Ok(status) => {
                log::info!("Service status check result: {:?}", status);
                self.state.fail2ban_service = status;
            },
            Err(e) => {
                log::error!("Failed to get service status: {}", e);
                self.state.fail2ban_service = ServiceStatus::Unknown;
            }
        }
        self.state.last_update = Instant::now();
    }
    
    fn refresh_jail_data(&mut self) {
        log::info!("Refreshing jail data - service status: {:?}", self.state.fail2ban_service);
        // Only refresh jail data if service is running
        if matches!(self.state.fail2ban_service, ServiceStatus::Running) {
            match self.fail2ban_client.get_jails() {
                Ok(jail_names) => {
                    log::info!("Found {} jails: {:?}", jail_names.len(), jail_names);
                    let mut new_jails = HashMap::new();
                    
                    for jail_name in jail_names {
                        match self.fail2ban_client.get_jail_status(&jail_name) {
                            Ok(jail_state) => {
                                new_jails.insert(jail_name.clone(), jail_state);
                            },
                            Err(e) => {
                                log::warn!("Failed to get status for jail {}: {}", jail_name, e);
                                // Keep existing data if we can't get new data
                                if let Some(existing) = self.state.jails.get(&jail_name) {
                                    new_jails.insert(jail_name, existing.clone());
                                }
                            }
                        }
                    }
                    
                    if !new_jails.is_empty() {
                        log::info!("Successfully loaded {} jails into state", new_jails.len());
                        self.state.jails = new_jails;
                    }
                },
                Err(e) => {
                    log::error!("Failed to get jail list: {}", e);
                }
            }
        }
    }
    
    fn refresh_ip_data(&mut self) {
        let banned_ip_count = self.state.banned_ips.len();
        let is_massive_dataset = banned_ip_count > 15000;
        let is_large_dataset = banned_ip_count > 10000;
        
        // Dramatically more conservative refresh logic for large datasets
        let force_refresh_interval = if is_massive_dataset {
            Duration::from_secs(300) // 5 minutes for massive datasets (18k+ IPs)
        } else if is_large_dataset {
            Duration::from_secs(120) // 2 minutes for large datasets (10k+ IPs)
        } else {
            Duration::from_secs(60)  // 1 minute for normal datasets
        };
        
        let force_refresh = self.state.last_ip_full_refresh.map_or(
            self.state.banned_ips.is_empty(), // Only if empty on first load
            |last| last.elapsed() > force_refresh_interval
        );
        
        let should_refresh = self.state.banned_ips.is_empty() || force_refresh;
        
        if matches!(self.state.fail2ban_service, ServiceStatus::Running) && 
           !self.state.jails.is_empty() && should_refresh {
            
            // Show user-visible loading message
            if is_massive_dataset {
                self.set_status_message("🔄 Loading banned IPs... (Large dataset detected, this may take 10-15 seconds)");
                log::info!("Loading banned IP data for {} jails (PERFORMANCE MODE: 18k+ IPs detected)...", self.state.jails.len());
            } else if is_large_dataset {
                self.set_status_message("🔄 Loading banned IPs... (this may take several seconds)");
                log::info!("Loading banned IP data for {} jails (PERFORMANCE MODE: 10k+ IPs detected)...", self.state.jails.len());
            } else {
                self.set_status_message("🔄 Loading banned IPs...");
                log::info!("Loading banned IP data for {} jails...", self.state.jails.len());
            }
            let start_time = Instant::now();
            
            let mut all_banned_ips = Vec::new();
            let mut total_processed = 0;
            let total_jails = self.state.jails.len();
            
            // Collect jail names to avoid borrowing issues
            let jail_names: Vec<String> = self.state.jails.keys().cloned().collect();
            
            for (index, jail_name) in jail_names.iter().enumerate() {
                // Update progress for large datasets
                if is_large_dataset && total_jails > 3 {
                    let progress_percent = ((index + 1) * 100) / total_jails;
                    self.set_status_message(&format!("🔄 Loading banned IPs... ({}/{} jails, {}%)", 
                                                     index + 1, total_jails, progress_percent));
                }
                
                match self.fail2ban_client.get_banned_ips(jail_name) {
                    Ok(mut ips) => {
                        total_processed += ips.len();
                        all_banned_ips.append(&mut ips);
                        log::debug!("Loaded {} IPs from jail {} ({}/{})", 
                                   ips.len(), jail_name, index + 1, self.state.jails.len());
                    },
                    Err(e) => {
                        log::warn!("Failed to get banned IPs for jail {}: {}", jail_name, e);
                    }
                }
            }
            
            let load_duration = start_time.elapsed();
            log::info!("Loaded {} total banned IPs from {} jails in {:.2}s", 
                      total_processed, self.state.jails.len(), load_duration.as_secs_f32());
            
            // Show sorting progress for large datasets
            if is_large_dataset {
                self.set_status_message("🔄 Sorting banned IPs...");
            }
            
            // Sort banned IPs by IP address first, then by jail name
            all_banned_ips.sort_by(|a, b| {
                a.ip.cmp(&b.ip).then_with(|| a.jail.cmp(&b.jail))
            });
            
            self.state.banned_ips = all_banned_ips;
            self.state.last_ip_full_refresh = Some(Instant::now());
            
            // Update pagination with total count
            self.state.banned_ip_pagination.update_total_items(self.state.banned_ips.len());
            
            // Show completion message
            self.set_status_message(&format!("✅ Loaded {} banned IPs from {} jails in {:.1}s", 
                                            total_processed, total_jails, load_duration.as_secs_f32()));
        } else if !matches!(self.state.fail2ban_service, ServiceStatus::Running) {
            // Clear data if service is not running
            self.state.banned_ips.clear();
            self.state.banned_ip_pagination.update_total_items(0);
        }
    }
    
    fn start_banned_ip_loading(&mut self) {
        // Phase 1: Show full-screen loading modal - UI will redraw before next event
        self.state.is_loading_banned_ips = true;
        
        let banned_ip_count = self.state.banned_ips.len();
        let is_massive_dataset = banned_ip_count > 15000;
        let is_large_dataset = banned_ip_count > 10000;
        
        // Show full-screen modal that's impossible to miss
        let (title, message) = if is_massive_dataset {
            (
                "🔄 Loading Banned IPs".to_string(),
                format!("Large dataset detected ({} existing IPs)\n\nThis operation may take 10-15 seconds\nPlease wait while we load all banned IPs", banned_ip_count)
            )
        } else if is_large_dataset {
            (
                "🔄 Loading Banned IPs".to_string(),
                format!("Loading {} banned IPs\n\nThis may take several seconds\nPlease wait", banned_ip_count)
            )
        } else {
            (
                "🔄 Loading Banned IPs".to_string(),
                "Loading banned IPs from all jails\n\nPlease wait".to_string()
            )
        };
        
        self.state.loading_modal = Some(LoadingModalState::new(title, message));
        
        log::info!("PHASE 1: Showing full-screen loading modal for {} dataset ({}+ IPs)", 
                  if is_massive_dataset { "massive" } else if is_large_dataset { "large" } else { "normal" }, 
                  banned_ip_count);
        
        // Force immediate UI refresh by returning - actual loading happens in next cycle
        log::info!("PHASE 1 COMPLETE: Loading modal displayed, will load data on next event cycle");
    }
    
    fn continue_banned_ip_loading(&mut self) {
        // Phase 2: Actually perform the expensive loading operation
        log::info!("PHASE 2: Starting actual banned IP loading operation");
        
        let banned_ip_count = self.state.banned_ips.len();
        let is_massive_dataset = banned_ip_count > 15000;
        let is_large_dataset = banned_ip_count > 10000;
        
        // Use the exact same loading logic as before, but now the loading message is already visible
        let force_refresh_interval = if is_massive_dataset {
            Duration::from_secs(300) // 5 minutes for massive datasets (18k+ IPs)
        } else if is_large_dataset {
            Duration::from_secs(120) // 2 minutes for large datasets (10k+ IPs)
        } else {
            Duration::from_secs(60)  // 1 minute for normal datasets
        };
        
        let force_refresh = self.state.last_ip_full_refresh.map_or(
            self.state.banned_ips.is_empty(), // Only if empty on first load
            |last| last.elapsed() > force_refresh_interval
        );
        
        let should_refresh = self.state.banned_ips.is_empty() || force_refresh;
        
        if matches!(self.state.fail2ban_service, ServiceStatus::Running) && 
           !self.state.jails.is_empty() && should_refresh {
            
            let start_time = Instant::now();
            
            let mut all_banned_ips = Vec::new();
            let mut total_processed = 0;
            let total_jails = self.state.jails.len();
            
            // Collect jail names to avoid borrowing issues
            let jail_names: Vec<String> = self.state.jails.keys().cloned().collect();
            
            for (index, jail_name) in jail_names.iter().enumerate() {
                // Update modal progress for large datasets
                if is_large_dataset && total_jails > 3 {
                    let progress_percent = ((index + 1) * 100) / total_jails;
                    if let Some(ref mut modal) = self.state.loading_modal {
                        modal.update_message(format!("Loading banned IPs from jails ({}/{})\n\nProgress: {}%\n\nCurrently processing: {}", 
                                                     index + 1, total_jails, progress_percent, jail_name));
                        modal.progress = Some(progress_percent as u8);
                    }
                }
                
                match self.fail2ban_client.get_banned_ips(jail_name) {
                    Ok(mut ips) => {
                        total_processed += ips.len();
                        all_banned_ips.append(&mut ips);
                        log::debug!("Loaded {} IPs from jail {} ({}/{})", 
                                   ips.len(), jail_name, index + 1, self.state.jails.len());
                    },
                    Err(e) => {
                        log::warn!("Failed to get banned IPs for jail {}: {}", jail_name, e);
                    }
                }
            }
            
            let load_duration = start_time.elapsed();
            log::info!("Loaded {} total banned IPs from {} jails in {:.2}s", 
                      total_processed, self.state.jails.len(), load_duration.as_secs_f32());
            
            // Show sorting progress in modal for large datasets
            if is_large_dataset {
                if let Some(ref mut modal) = self.state.loading_modal {
                    modal.update_message(format!("Sorting {} banned IPs...\n\nThis may take a moment", total_processed));
                    modal.progress = Some(95);
                }
            }
            
            // Sort banned IPs by IP address first, then by jail name
            all_banned_ips.sort_by(|a, b| {
                a.ip.cmp(&b.ip).then_with(|| a.jail.cmp(&b.jail))
            });
            
            self.state.banned_ips = all_banned_ips;
            self.state.last_ip_full_refresh = Some(Instant::now());
            
            // Update pagination with total count
            self.state.banned_ip_pagination.update_total_items(self.state.banned_ips.len());
            
            // Show completion in modal briefly
            if let Some(ref mut modal) = self.state.loading_modal {
                modal.update_message(format!("✅ Successfully loaded {} banned IPs\nfrom {} jails in {:.1}s", 
                                            total_processed, total_jails, load_duration.as_secs_f32()));
                modal.progress = Some(100);
            }
        } else if !matches!(self.state.fail2ban_service, ServiceStatus::Running) {
            // Clear data if service is not running
            self.state.banned_ips.clear();
            self.state.banned_ip_pagination.update_total_items(0);
        }
        
        // Reset loading state and clear modal
        self.state.is_loading_banned_ips = false;
        self.state.loading_modal = None;
        log::info!("PHASE 2 COMPLETE: Banned IP loading finished, clearing modal");
    }
    
    fn refresh_log_data(&mut self) {
        // Update log entries - should be fast
        self.update_log_entries();
    }
    
    fn handle_service_action(&mut self, action: ServiceAction) {
        // Start progress tracking
        let operation_type = match action {
            ServiceAction::Start => OperationType::ServiceStart,
            ServiceAction::Stop => OperationType::ServiceStop,
            ServiceAction::Restart => OperationType::ServiceRestart,
            ServiceAction::Reload => OperationType::ServiceReload,
        };
        
        self.start_operation(operation_type);
        
        // Simulate progress for better user experience
        self.update_operation_progress(25, Some("Preparing operation...".to_string()));
        
        let result = match action {
            ServiceAction::Start => {
                self.update_operation_progress(50, Some("Starting service...".to_string()));
                self.system_service.start()
            },
            ServiceAction::Stop => {
                self.update_operation_progress(50, Some("Stopping service...".to_string()));
                self.system_service.stop()
            },
            ServiceAction::Restart => {
                self.update_operation_progress(33, Some("Stopping service...".to_string()));
                let stop_result = self.system_service.stop();
                if stop_result.is_ok() {
                    self.update_operation_progress(66, Some("Starting service...".to_string()));
                }
                self.system_service.restart()
            },
            ServiceAction::Reload => {
                self.update_operation_progress(50, Some("Reloading configuration...".to_string()));
                self.system_service.reload()
            },
        };
        
        self.update_operation_progress(90, Some("Finalizing...".to_string()));
        
        match result {
            Ok(()) => {
                let success_msg = match action {
                    ServiceAction::Start => "✓ Service started successfully",
                    ServiceAction::Stop => "✓ Service stopped successfully", 
                    ServiceAction::Restart => "✓ Service restarted successfully",
                    ServiceAction::Reload => "✓ Configuration reloaded successfully",
                };
                
                self.complete_operation(true, Some(success_msg.to_string()));
                
                // Set service-specific message
                self.set_service_message(success_msg);
                
                // Record the action and timestamp
                let action_name = match action {
                    ServiceAction::Start => "Started",
                    ServiceAction::Stop => "Stopped",
                    ServiceAction::Restart => "Restarted",
                    ServiceAction::Reload => "Config Reloaded",
                };
                self.state.last_service_action = Some((action_name.to_string(), chrono::Local::now()));
                
                // Trigger targeted IP refresh after successful ban
                self.last_ip_refresh = Instant::now().checked_sub(Duration::from_secs(4)).unwrap_or(Instant::now());
            },
            Err(e) => {
                let error_msg = format!("✗ Service action failed: {}", e);
                self.complete_operation(false, Some(error_msg.clone()));
                self.set_service_message(&error_msg);
                log::error!("Service action {:?} failed: {}", action, e);
            }
        }
    }
    
    fn set_status_message(&mut self, message: &str) {
        self.state.status_message = Some((message.to_string(), chrono::Utc::now()));
    }
    
    fn set_service_message(&mut self, message: &str) {
        self.state.service_message = Some(message.to_string());
    }
    
    fn handle_unban_ip(&mut self, ip: &str, jail: &str) {
        log::info!("Unbanning IP {} from jail {}", ip, jail);
        
        self.start_operation(OperationType::IpUnban);
        self.update_operation_progress(30, Some(format!("Unbanning {} from {}...", ip, jail)));
        
        match self.fail2ban_client.unban_ip(jail, ip) {
            Ok(()) => {
                self.update_operation_progress(80, Some("Updating IP list...".to_string()));
                
                let success_msg = format!("✓ Successfully unbanned {} from {}", ip, jail);
                self.complete_operation(true, Some(success_msg));
                
                // Trigger targeted IP refresh after operation
                self.last_ip_refresh = Instant::now().checked_sub(Duration::from_secs(4)).unwrap_or(Instant::now());
            },
            Err(e) => {
                let error_msg = format!("✗ Failed to unban {}: {}", ip, e);
                self.complete_operation(false, Some(error_msg));
                log::error!("Failed to unban IP {}: {}", ip, e);
            }
        }
    }
    
    fn handle_ban_ip(&mut self, ip: &str, jail: &str) {
        log::info!("Banning IP {} in jail {} using jail's configured bantime", ip, jail);
        
        self.start_operation(OperationType::IpBan);
        self.update_operation_progress(30, Some(format!("Banning {} in {}...", ip, jail)));
        
        // Always use the jail's configured bantime (no custom duration support)
        let result = self.fail2ban_client.ban_ip(jail, ip);
        
        match result {
            Ok(()) => {
                self.update_operation_progress(80, Some("Updating IP list...".to_string()));
                
                let success_msg = format!("✓ Successfully banned {} in {} (using jail's configured bantime)", ip, jail);
                self.complete_operation(true, Some(success_msg));
                
                // Trigger targeted IP refresh after operation
                self.last_ip_refresh = Instant::now().checked_sub(Duration::from_secs(4)).unwrap_or(Instant::now());
            },
            Err(e) => {
                let error_msg = format!("✗ Failed to ban {}: {}", ip, e);
                self.complete_operation(false, Some(error_msg));
                log::error!("Failed to ban IP {}: {}", ip, e);
            }
        }
    }
    
    fn export_banned_ips_to_csv(&mut self) {
        use std::io::Write;
        
        if self.state.banned_ips.is_empty() {
            self.set_status_message("⚠ No banned IPs to export");
            return;
        }
        
        // Generate filename with timestamp
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let filename = format!("banned_ips_{}.csv", timestamp);
        
        // Try multiple export locations in order of preference
        let export_paths = [
            format!("/tmp/{}", filename),
            format!("/var/log/{}", filename),
            format!("./{}", filename),
        ];
        
        let mut export_result = None;
        for path in &export_paths {
            match std::fs::File::create(path) {
                Ok(mut file) => {
                    // Write CSV header
                    if let Err(e) = writeln!(file, "IP Address,Jail,Ban Time,Unban Time,Reason") {
                        log::error!("Failed to write CSV header to {}: {}", path, e);
                        continue;
                    }
                    
                    // Write banned IP data
                    let mut success = true;
                    for banned_ip in &self.state.banned_ips {
                        let unban_time_str = banned_ip.unban_time
                            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                            .unwrap_or_else(|| "N/A".to_string());
                            
                        if let Err(e) = writeln!(
                            file, 
                            "{},{},{},{},{}", 
                            banned_ip.ip, 
                            banned_ip.jail, 
                            banned_ip.ban_time.format("%Y-%m-%d %H:%M:%S UTC"),
                            unban_time_str,
                            banned_ip.reason
                        ) {
                            log::error!("Failed to write banned IP data to {}: {}", path, e);
                            success = false;
                            break;
                        }
                    }
                    
                    if success {
                        export_result = Some((path.clone(), self.state.banned_ips.len()));
                        break;
                    }
                },
                Err(_) => continue,
            }
        }
        
        match export_result {
            Some((path, count)) => {
                let success_msg = format!("✓ Exported {} banned IPs to {}", count, path);
                self.set_status_message(&success_msg);
                log::info!("Successfully exported banned IPs to {}", path);
            },
            None => {
                let error_msg = "✗ Failed to export banned IPs - could not create file in any location";
                self.set_status_message(error_msg);
                log::error!("Failed to export banned IPs to any location");
            }
        }
    }
    
    fn handle_message(&mut self, message: AppMessage) {
        match message {
            // IP management messages
            AppMessage::OpenBanDialog => {
                // Use existing jail data - no need for expensive reload on dialog open
                // Jail data is kept current by the staggered refresh system
                
                self.state.ip_management.ban_dialog_open = true;
                self.state.ip_management.ban_ip_input.clear();
                self.state.ip_management.ban_dialog_field_index = 0; // Start with IP field
                
                // Set default jail to first available jail
                if let Some(first_jail) = self.state.jails.keys().next() {
                    self.state.ip_management.selected_jail_for_ban = Some(first_jail.clone());
                } else {
                    // Show status message if no jails are available
                    self.set_status_message("⚠ No active jails found - check fail2ban service status");
                }
            },
            AppMessage::CloseBanDialog => {
                self.state.ip_management.ban_dialog_open = false;
                self.state.ip_management.ban_ip_input.clear();
                self.state.ip_management.selected_jail_for_ban = None;
            },
            AppMessage::ConfirmBan => {
                let ip = self.state.ip_management.ban_ip_input.trim().to_string();
                if !ip.is_empty() && self.state.ip_management.selected_jail_for_ban.is_some() {
                    let jail = self.state.ip_management.selected_jail_for_ban.clone().unwrap();
                    self.handle_ban_ip(&ip, &jail);
                    self.state.ip_management.ban_dialog_open = false;
                    self.state.ip_management.ban_ip_input.clear();
                }
            },
            AppMessage::SelectJailForBan(jail) => {
                self.state.ip_management.selected_jail_for_ban = Some(jail);
            },
            AppMessage::OpenUnbanConfirmation(ip, jail) => {
                self.state.ip_management.unban_confirmation_open = true;
                self.state.ip_management.ip_to_unban = Some(ip);
                self.state.ip_management.jail_for_unban = Some(jail);
            },
            AppMessage::CloseUnbanConfirmation => {
                self.state.ip_management.unban_confirmation_open = false;
                self.state.ip_management.ip_to_unban = None;
                self.state.ip_management.jail_for_unban = None;
            },
            AppMessage::ConfirmUnban => {
                if let (Some(ip), Some(jail)) = (self.state.ip_management.ip_to_unban.clone(), self.state.ip_management.jail_for_unban.clone()) {
                    self.handle_unban_ip(&ip, &jail);
                    self.state.ip_management.unban_confirmation_open = false;
                    self.state.ip_management.ip_to_unban = None;
                    self.state.ip_management.jail_for_unban = None;
                }
            },
            AppMessage::SelectBannedIP(index) => {
                self.state.ip_management.selected_banned_ip_index = index;
            },
            AppMessage::ExportBannedIPs => {
                self.export_banned_ips_to_csv();
            },
            // Whitelist management messages
            AppMessage::OpenWhitelistDialog => {
                self.state.ip_management.whitelist_dialog_open = true;
                self.state.ip_management.whitelist_ip_input.clear();
            },
            AppMessage::CloseWhitelistDialog => {
                self.state.ip_management.whitelist_dialog_open = false;
                self.state.ip_management.whitelist_ip_input.clear();
            },
            AppMessage::AddToWhitelist(ip) => {
                let ip = ip.trim().to_string();
                if ip.is_empty() {
                    self.set_status_message("⚠ Please enter an IP address or range");
                } else if !self.is_valid_ip_or_range(&ip) {
                    self.set_status_message(&format!("⚠ Invalid IP address or CIDR range: {}", ip));
                } else if self.state.whitelist_ips.contains(&ip) {
                    self.set_status_message(&format!("⚠ {} is already in the whitelist", ip));
                } else {
                    self.state.whitelist_ips.push(ip.clone());
                    
                    // Save to fail2ban configuration
                    match self.fail2ban_client.save_whitelist_ips(&self.state.whitelist_ips) {
                        Ok(()) => {
                            self.set_status_message(&format!("✓ {} added to whitelist and saved", ip));
                        },
                        Err(e) => {
                            // Keep in memory even if save failed
                            self.set_status_message(&format!("⚠ {} added to whitelist but failed to save: {}", ip, e));
                            log::error!("Failed to save whitelist: {}", e);
                        }
                    }
                }
                self.state.ip_management.whitelist_dialog_open = false;
                self.state.ip_management.whitelist_ip_input.clear();
            },
            AppMessage::RemoveFromWhitelist(index) => {
                if index < self.state.whitelist_ips.len() {
                    let removed_ip = self.state.whitelist_ips.remove(index);
                    
                    // Save to fail2ban configuration
                    match self.fail2ban_client.save_whitelist_ips(&self.state.whitelist_ips) {
                        Ok(()) => {
                            self.set_status_message(&format!("✓ {} removed from whitelist and saved", removed_ip));
                        },
                        Err(e) => {
                            // Re-add to memory if save failed
                            self.state.whitelist_ips.insert(index, removed_ip.clone());
                            self.set_status_message(&format!("⚠ Failed to remove {} from whitelist: {}", removed_ip, e));
                            log::error!("Failed to save whitelist: {}", e);
                            return;
                        }
                    }
                    
                    // Adjust selection if needed
                    if self.state.ip_management.selected_whitelist_index >= self.state.whitelist_ips.len() && !self.state.whitelist_ips.is_empty() {
                        self.state.ip_management.selected_whitelist_index = self.state.whitelist_ips.len() - 1;
                    }
                }
            },
            AppMessage::SelectWhitelistIP(index) => {
                self.state.ip_management.selected_whitelist_index = index;
            },
            // Jail management messages
            AppMessage::LoadAvailableJails => {
                self.load_available_jails();
            },
            AppMessage::AvailableJailsLoaded(jails) => {
                self.state.available_jails = jails;
                // Reset selection if it's out of bounds
                if self.state.selected_jail_index >= self.state.available_jails.len() {
                    self.state.selected_jail_index = 0;
                    self.state.jail_scroll_offset = 0;
                }
                // Also reset dashboard jail selection if it's out of bounds
                let sorted_jails = self.get_sorted_jails_for_display();
                if self.state.dashboard_jail_selected_index >= sorted_jails.len() {
                    self.state.dashboard_jail_selected_index = 0;
                }
                // Set status message to show jails were loaded
                if self.state.available_jails.is_empty() {
                    self.set_status_message("⚠ No jail configurations found in fail2ban config files");
                } else {
                    self.set_status_message(&format!("✓ Loaded {} jail configurations", self.state.available_jails.len()));
                }
            },
            AppMessage::SelectJail(index) => {
                if index < self.state.available_jails.len() {
                    self.state.selected_jail_index = index;
                }
            },
            AppMessage::ToggleJailEnabled(jail_name) => {
                self.toggle_jail_enabled(jail_name);
            },
            AppMessage::SetJailEnabled(jail_name, enabled) => {
                self.perform_jail_toggle(jail_name, enabled);
            },
            AppMessage::PerformJailToggle(jail_name, new_enabled) => {
                self.perform_jail_toggle(jail_name, new_enabled);
            },
            // Jail Editor messages
            AppMessage::OpenJailEditor(jail_name) => {
                self.open_jail_editor(jail_name);
            },
            AppMessage::CloseJailEditor => {
                self.close_jail_editor();
            },
            AppMessage::UpdateJailEditorContent(content) => {
                self.state.jail_editor.current_content = content;
            },
            AppMessage::SaveJailConfiguration => {
                self.save_jail_configuration();
            },
            AppMessage::JailConfigSaved(success) => {
                self.handle_jail_config_saved(success);
            },
            // Configuration management messages
            AppMessage::SelectConfigFile(index) => {
                if index < self.state.config_management.config_files.len() {
                    self.state.config_management.selected_file_index = index;
                    self.state.config_management.table_state.select(Some(index));
                }
            },
            AppMessage::OpenConfigEditor(file_path) => {
                self.open_config_editor(file_path);
            },
            AppMessage::CloseConfigEditor => {
                self.close_config_editor();
            },
            AppMessage::SaveConfigFile => {
                self.save_config_file();
            },
            AppMessage::BackupConfiguration => {
                self.backup_configuration();
            },
            AppMessage::RestoreConfiguration => {
                self.restore_configuration();
            },
            AppMessage::TestConfiguration => {
                self.test_configuration();
            },
            // Other messages would be handled here
            _ => {
                // For now, just log unhandled messages
                log::debug!("Unhandled message: {:?}", message);
            }
        }
    }
    
    pub fn render(&mut self, frame: &mut Frame) {
        let mut constraints = vec![
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Content
            Constraint::Length(2), // Footer
        ];
        
        // Add space for progress bar if operation is running
        if self.state.current_operation.is_some() {
            constraints.insert(1, Constraint::Length(3)); // Progress bar
        }
        
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(frame.size());
        
        // Header
        self.render_header(frame, chunks[0]);
        
        let mut content_index = 1;
        
        // Progress bar (if operation is running)
        if self.state.current_operation.is_some() {
            self.render_progress_bar(frame, chunks[1]);
            content_index = 2;
        }
        
        // Content based on current screen
        self.render_content(frame, chunks[content_index]);
        
        // Footer
        self.render_footer(frame, chunks[chunks.len() - 1]);
        
        // Render error dialog on top of everything if present
        if self.state.error_dialog.is_some() {
            self.render_error_dialog(frame, frame.size());
        }
        
        // Render IP management dialogs on top if open (available from dashboard)
        if self.state.ip_management.ban_dialog_open {
            self.render_ban_dialog(frame, frame.size());
        }
        if self.state.ip_management.unban_confirmation_open {
            self.render_unban_confirmation(frame, frame.size());
        }
        if self.state.ip_management.whitelist_dialog_open {
            self.render_whitelist_dialog(frame, frame.size());
        }
        
        // Render loading modal on top of EVERYTHING if present (highest priority)
        if let Some(ref modal) = self.state.loading_modal {
            self.render_loading_modal(frame, frame.size(), modal);
        }
    }
    
    fn render_header(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let now = chrono::Local::now();
        
        // Check for recent status messages (show for 8 seconds for better visibility)
        let status_display = if let Some((ref msg, timestamp)) = self.state.status_message {
            let age = chrono::Utc::now().signed_duration_since(timestamp);
            if age.num_seconds() < 8 {
                Some(msg.clone())
            } else {
                None
            }
        } else {
            None
        };
        
        // Calculate dynamic spacing for header including status message
        let version_prefix = "F2B-BUXjr v";
        let version_number = env!("CARGO_PKG_VERSION");
        let service_status = format!("[{}]", self.state.fail2ban_service.symbol());
        let screen_title = format!(" {} ", self.state.current_screen.title());
        let datetime_str = now.format("%Y-%m-%d %H:%M:%S").to_string();
        
        // Calculate left side width based on actual spans
        let mut left_side_width = version_prefix.len() + version_number.len() + 1 + service_status.len() + screen_title.len();
        
        // Add status message length to calculation if present
        if let Some(ref msg) = status_display {
            // Use Unicode width for proper visual character counting
            let pipe_separator = " | ";
            let total_status_width = pipe_separator.width() + msg.width();
            log::debug!("Status message: '{}' (visual_width={}), pipe: '{}' (visual_width={}), total status width: {}", 
                       msg, msg.width(), pipe_separator, pipe_separator.width(), total_status_width);
            left_side_width += total_status_width;
        }
        
        let datetime_width = datetime_str.len();
        let total_width = area.width as usize;
        
        // Debug: log the calculation
        log::debug!("Header calculation: total_width={}, left_side_width={}, datetime_width={}, padding_space={}", 
                   total_width, left_side_width, datetime_width, total_width.saturating_sub(left_side_width + datetime_width));
        
        // Simple math: Total width - left content - datetime = padding needed
        let padding_space = total_width.saturating_sub(left_side_width + datetime_width);

        let mut header_spans = vec![
            Span::styled(version_prefix, Style::default()),
            Span::styled(version_number, Style::default()),
            Span::raw(" "),
            Span::styled(
                &service_status,
                Style::default().fg(self.state.fail2ban_service.color())
            ),
            Span::styled(
                &screen_title,
                Style::default().fg(Color::White)
            ),
        ];
        
        // Add status message to the same line if present
        if let Some(status_msg) = status_display {
            let status_color = if status_msg.starts_with('✓') || status_msg.contains("EXPORTED") {
                Color::Green
            } else if status_msg.starts_with('✗') {
                Color::Red
            } else {
                Color::Yellow
            };
            
            header_spans.extend(vec![
                Span::raw(" | "),
                Span::styled(status_msg, Style::default().fg(status_color)),
            ]);
        }
        
        header_spans.extend(vec![
            Span::raw(" ".repeat(padding_space)),
            Span::styled(
                datetime_str,
                Style::default().fg(Color::Gray)
            ),
        ]);
        
        let header_text = vec![Line::from(header_spans)];
        
        let header = Paragraph::new(header_text)
            .block(Block::default().borders(Borders::ALL));
        
        frame.render_widget(header, area);
    }
    
    fn render_content(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        match self.state.current_screen {
            Screen::Dashboard => self.render_dashboard(frame, area),
            Screen::Help => self.render_help(frame, area),
            Screen::About => self.render_about(frame, area),
            Screen::Whitelist => self.render_whitelist(frame, area),
            Screen::Configuration => self.render_configuration(frame, area),
            Screen::Logs => self.render_logs(frame, area),
            Screen::Settings => self.render_settings(frame, area),
            Screen::JailEditor => self.render_jail_editor(frame, area),
        }
    }
    
    fn render_dashboard(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let base_service_text = match self.state.fail2ban_service {
            ServiceStatus::Running => "Running",
            ServiceStatus::Stopped => "Stopped", 
            ServiceStatus::Failed => "Failed",
            ServiceStatus::Unknown => "Unknown",
        };
        
        // Append action result if available
        let service_text = if let Some((action, timestamp)) = &self.state.last_service_action {
            format!("{} - {} at {}", base_service_text, action, timestamp.format("%m/%d/%Y %H:%M:%S"))
        } else {
            base_service_text.to_string()
        };
        
        // Split layout: Service status, jails table, and Banned IPs table
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),   // Service status header
                Constraint::Min(8),      // Jails table
                Constraint::Min(8),      // Banned IPs table
            ])
            .split(area);
        
        // Render service status header
        let service_title = Line::from(vec![
            Span::raw("Service Status - "),
            Span::styled("R", Style::default().fg(Color::Rgb(0, 150, 255))),
            Span::raw(":Restart | "),
            Span::styled("S", Style::default().fg(Color::Rgb(0, 150, 255))),
            Span::raw(":Start | "),
            Span::styled("T", Style::default().fg(Color::Rgb(0, 150, 255))),
            Span::raw(":Stop | "),
            Span::styled("D", Style::default().fg(Color::Rgb(0, 150, 255))),
            Span::raw(":Reload"),
        ]);
        let service_header = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!("{} {}", self.state.fail2ban_service.symbol(), service_text),
                    Style::default().fg(self.state.fail2ban_service.color())
                ),
            ]),
        ])
        .block(Block::default().title(service_title).borders(Borders::ALL));
        
        frame.render_widget(service_header, chunks[0]);
        
        // Render jails table
        self.render_jails_table(frame, chunks[1]);
        
        // Render Banned IPs table (same format as IP Management)
        self.render_recent_activity_table(frame, chunks[2]);
    }
    
    fn render_jails_table(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let mut rows = Vec::new();
        
        if self.state.available_jails.is_empty() {
            // Show loading state
            rows.push(Row::new(vec![
                Cell::from("Loading jails...").style(Style::default().fg(Color::Yellow)),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ]));
        } else {
            let sorted_jails = self.get_sorted_jails_for_display();
            
            for jail_config in sorted_jails.iter() {
                // Get current ban count from runtime state if available
                let ban_count = self.state.jails.get(&jail_config.name)
                    .map(|js| js.banned_count)
                    .unwrap_or(0);
                
                let status_symbol = if jail_config.enabled { "●" } else { "○" };
                let status_color = if jail_config.enabled { Color::Green } else { Color::Red };
                let status_text = if jail_config.enabled { "Enabled" } else { "Disabled" };
                
                let ban_count_text = if ban_count > 0 {
                    format!("{} 🚫", ban_count)
                } else {
                    "0".to_string()
                };
                
                // Clean up display values
                let filter_display = if jail_config.filter.is_empty() { "-".to_string() } else { jail_config.filter.clone() };
                let port_display = if jail_config.port.is_empty() { "-".to_string() } else { jail_config.port.clone() };
                let find_time_display = if jail_config.find_time.is_empty() { "-".to_string() } else { jail_config.find_time.clone() };
                
                rows.push(Row::new(vec![
                    Cell::from(format!("{} {}", status_symbol, status_text)).style(Style::default().fg(status_color)),
                    Cell::from(jail_config.name.clone()).style(Style::default().fg(Color::White)),
                    Cell::from(ban_count_text).style(Style::default().fg(Color::White)),
                    Cell::from(filter_display).style(Style::default().fg(Color::White)),
                    Cell::from(port_display).style(Style::default().fg(Color::White)),
                    Cell::from(jail_config.ban_time.clone()).style(Style::default().fg(Color::White)),
                    Cell::from(find_time_display).style(Style::default().fg(Color::White)),
                    Cell::from(jail_config.max_retry.to_string()).style(Style::default().fg(Color::White)),
                ]));
            }
        }
        
        let table = Table::new(
            rows,
            [
                Constraint::Length(12),  // Status
                Constraint::Length(20),  // Jail Name
                Constraint::Length(10),  // Bans
                Constraint::Length(18),  // Filter
                Constraint::Length(12),  // Port
                Constraint::Length(12),  // Ban Time
                Constraint::Length(12),  // Find Time
                Constraint::Length(8),   // Max Retry
            ]
        )
        .header(Row::new(vec![
            Cell::from("Status").style(Style::default().fg(Color::Yellow)),
            Cell::from("Jail Name").style(Style::default().fg(Color::Yellow)),
            Cell::from("Bans").style(Style::default().fg(Color::Yellow)),
            Cell::from("Filter").style(Style::default().fg(Color::Yellow)),
            Cell::from("Port").style(Style::default().fg(Color::Yellow)),
            Cell::from("Ban Time").style(Style::default().fg(Color::Yellow)),
            Cell::from("Find Time").style(Style::default().fg(Color::Yellow)),
            Cell::from("Retry").style(Style::default().fg(Color::Yellow)),
        ]))
        .block(Block::default().borders(Borders::ALL).title(
            if self.state.dashboard_focus == DashboardFocus::Jails {
                let active_count = self.state.available_jails.iter().filter(|j| j.enabled).count();
                Line::from(vec![
                    Span::raw(format!("Jails ({} Total / {} Active) - ", self.state.available_jails.len(), active_count)),
                    Span::styled("ENTER", Style::default().fg(Color::Rgb(0, 150, 255))),
                    Span::raw(":En/Disable | "),
                    Span::styled("E", Style::default().fg(Color::Rgb(0, 150, 255))),
                    Span::raw(":Edit | "),
                    Span::styled("↑↓", Style::default().fg(Color::Rgb(0, 150, 255))),
                    Span::raw(":Navigate | "),
                    Span::styled("TAB", Style::default().fg(Color::Rgb(0, 150, 255))),
                    Span::raw(":Switch Focus"),
                ])
            } else {
                let active_count = self.state.available_jails.iter().filter(|j| j.enabled).count();
                Line::from(vec![
                    Span::raw(format!("Jails ({} Total / {} Active) - ", self.state.available_jails.len(), active_count)),
                    Span::styled("TAB", Style::default().fg(Color::Rgb(0, 150, 255))),
                    Span::raw(":Switch Focus"),
                ])
            }
        ))
        .highlight_style(Style::default().bg(Color::DarkGray));
        
        // Set the table state selection
        if self.state.dashboard_focus == DashboardFocus::Jails {
            self.state.dashboard_jail_table_state.select(Some(self.state.dashboard_jail_selected_index));
        } else {
            self.state.dashboard_jail_table_state.select(None);
        }
        
        frame.render_stateful_widget(table, area, &mut self.state.dashboard_jail_table_state);
    }
    
    fn render_recent_activity_table(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let mut rows = Vec::new();
        
        // Compute all needed data first to avoid borrowing conflicts
        let all_filtered_ips = self.get_filtered_banned_ips().clone();
        let total_count = self.state.banned_ips.len();
        let filtered_count = all_filtered_ips.len();
        
        // Update pagination total with filtered count
        self.state.banned_ip_pagination.update_total_items(filtered_count);
        
        // Get pagination indices after updating
        let start_idx = self.state.banned_ip_pagination.start_index();
        let end_idx = self.state.banned_ip_pagination.end_index();
        
        // Get only the current page of filtered IPs
        let filtered_ips: Vec<BannedIP> = all_filtered_ips
            .into_iter()
            .skip(start_idx)
            .take(end_idx - start_idx)
            .collect();
        
        // Compute filter spans inline to avoid borrowing issues
        let mut filter_spans = Vec::new();
        if let Some(digit) = self.state.banned_ip_filter.ip_starting_digit {
            filter_spans.push(Span::styled(format!("IP:{}", digit), Style::default().fg(Color::Yellow)));
        }
        if let Some(ref jail) = self.state.banned_ip_filter.jail {
            if !filter_spans.is_empty() {
                filter_spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            filter_spans.push(Span::styled(format!("Jail:{}", jail), Style::default().fg(Color::Yellow)));
        }
        if let Some(hours) = self.state.banned_ip_filter.ban_age_hours {
            if !filter_spans.is_empty() {
                filter_spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            let age_text = match hours {
                1 => "Age:1h".to_string(),
                24 => "Age:24h".to_string(), 
                168 => "Age:1w".to_string(),
                _ => format!("Age:{}h", hours),
            };
            filter_spans.push(Span::styled(age_text, Style::default().fg(Color::Yellow)));
        }
        if let Some(remaining_filter) = self.state.banned_ip_filter.remaining_time {
            if !filter_spans.is_empty() {
                filter_spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            let remaining_text = match remaining_filter {
                RemainingTimeFilter::Soon => "Remaining:<1h",
                RemainingTimeFilter::Today => "Remaining:<24h", 
                RemainingTimeFilter::ThisWeek => "Remaining:<1w",
                RemainingTimeFilter::Permanent => "Remaining:∞",
            };
            filter_spans.push(Span::styled(remaining_text, Style::default().fg(Color::Yellow)));
        }
        
        let dashboard_focus = self.state.dashboard_focus;
        let banned_ip_selected_index = self.state.dashboard_banned_ip_selected_index;
        
        for banned_ip in &filtered_ips {
            let ban_time_local = banned_ip.ban_time.with_timezone(&chrono::Local);
            let ban_date = ban_time_local.format("%Y-%m-%d").to_string();
            let ban_time = ban_time_local.format("%H:%M:%S").to_string();
            
            let unban_info = if let Some(unban_time) = banned_ip.unban_time {
                let now = chrono::Utc::now();
                if unban_time > now {
                    let remaining = unban_time - now;
                    self.format_duration(remaining)
                } else {
                    "Expired".to_string()
                }
            } else {
                "Permanent".to_string()
            };
            
            let unban_date_time = if let Some(unban_time) = banned_ip.unban_time {
                let unban_time_local = unban_time.with_timezone(&chrono::Local);
                format!("{} {}", 
                    unban_time_local.format("%Y-%m-%d"),
                    unban_time_local.format("%H:%M:%S"))
            } else {
                "Never".to_string()
            };
            
            rows.push(Row::new(vec![
                Cell::from(banned_ip.ip.clone()).style(Style::default().fg(Color::White)),
                Cell::from(banned_ip.jail.clone()).style(Style::default().fg(Color::White)),
                Cell::from(format!("{} {}", ban_date, ban_time)).style(Style::default().fg(Color::White)),
                Cell::from(unban_date_time).style(Style::default().fg(Color::White)),
                Cell::from(unban_info).style(Style::default().fg(Color::White)),
                Cell::from(banned_ip.reason.clone()).style(Style::default().fg(Color::White)),
            ]));
        }
        
        // Use pre-computed values for titles with pagination info
        let pagination = &self.state.banned_ip_pagination;
        let count_text = if filtered_count != total_count {
            format!("Banned IPs ({} of {}, Pg {} of {}) - ", 
                filtered_count, total_count, 
                pagination.current_page + 1, pagination.total_pages())
        } else {
            format!("Banned IPs ({}, Pg {} of {}) - ", 
                total_count,
                pagination.current_page + 1, pagination.total_pages())
        };
        
        let table = if rows.is_empty() {
            Table::new(
                vec![Row::new(vec![
                    Cell::from("No banned IPs").style(Style::default().fg(Color::Gray)),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                ])],
                [
                    Constraint::Length(16),  // IP Address
                    Constraint::Length(12),  // Jail
                    Constraint::Length(20),  // Ban Date/Time
                    Constraint::Length(20),  // Unban Date/Time
                    Constraint::Length(16),  // Time Remaining
                    Constraint::Min(15),     // Reason
                ]
            )
            .header(Row::new(vec![
                Cell::from("IP Address").style(Style::default().fg(Color::Yellow)),
                Cell::from("Jail").style(Style::default().fg(Color::Yellow)),
                Cell::from("Banned At").style(Style::default().fg(Color::Yellow)),
                Cell::from("Unbans At").style(Style::default().fg(Color::Yellow)),
                Cell::from("Remaining").style(Style::default().fg(Color::Yellow)),
                Cell::from("Reason").style(Style::default().fg(Color::Yellow)),
            ]))
            .block(Block::default().borders(Borders::ALL).title(
                if dashboard_focus == DashboardFocus::BannedIPs {
                    let mut title_spans = vec![
                        Span::raw(count_text.clone()),
                        Span::styled("0", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Clr|"),
                        Span::styled("1", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":IP|"),
                        Span::styled("2", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Jail|"),
                        Span::styled("3", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Age|"),
                        Span::styled("4", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Rem|"),
                        Span::styled(",.", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Pgs|"),
                        Span::styled("X", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Export|"),
                        Span::styled("TAB", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Focus"),
                    ];
                    
                    // Add active filters if any
                    if !filter_spans.is_empty() {
                        title_spans.push(Span::raw(" ["));
                        title_spans.extend(filter_spans.clone());
                        title_spans.push(Span::raw("]"));
                    }
                    
                    Line::from(title_spans)
                } else {
                    let mut title_spans = vec![
                        Span::raw(count_text.clone()),
                        Span::styled("TAB", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Switch Focus"),
                    ];
                    
                    // Add active filters if any (even when not focused)
                    if !filter_spans.is_empty() {
                        title_spans.push(Span::raw(" ["));
                        title_spans.extend(filter_spans);
                        title_spans.push(Span::raw("]"));
                    }
                    
                    Line::from(title_spans)
                }
            ))
            .highlight_style(Style::default().bg(Color::DarkGray))
        } else {
            Table::new(
                rows,
                [
                    Constraint::Length(16),  // IP Address
                    Constraint::Length(12),  // Jail
                    Constraint::Length(20),  // Ban Date/Time
                    Constraint::Length(20),  // Unban Date/Time
                    Constraint::Length(16),  // Time Remaining
                    Constraint::Min(15),     // Reason
                ]
            )
            .header(Row::new(vec![
                Cell::from("IP Address").style(Style::default().fg(Color::Yellow)),
                Cell::from("Jail").style(Style::default().fg(Color::Yellow)),
                Cell::from("Banned At").style(Style::default().fg(Color::Yellow)),
                Cell::from("Unbans At").style(Style::default().fg(Color::Yellow)),
                Cell::from("Remaining").style(Style::default().fg(Color::Yellow)),
                Cell::from("Reason").style(Style::default().fg(Color::Yellow)),
            ]))
            .block(Block::default().borders(Borders::ALL).title(
                if dashboard_focus == DashboardFocus::BannedIPs {
                    let mut title_spans = vec![
                        Span::raw(count_text.clone()),
                        Span::styled("0", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Clear | "),
                        Span::styled("1", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":IP | "),
                        Span::styled("2", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Jail | "),
                        Span::styled("3", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Age | "),
                        Span::styled("4", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Remaining | "),
                        Span::styled(",.", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Pages | "),
                        Span::styled("U", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Unban | "),
                        Span::styled("X", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Export"),
                    ];
                    
                    // Add active filters if any
                    if !filter_spans.is_empty() {
                        title_spans.push(Span::raw(" ["));
                        title_spans.extend(filter_spans.clone());
                        title_spans.push(Span::raw("]"));
                    }
                    
                    Line::from(title_spans)
                } else {
                    let mut title_spans = vec![
                        Span::raw(count_text.clone()),
                        Span::styled("X", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Export | "),
                        Span::styled("TAB", Style::default().fg(Color::Rgb(0, 150, 255))),
                        Span::raw(":Switch Focus"),
                    ];
                    
                    // Add active filters if any (even when not focused)
                    if !filter_spans.is_empty() {
                        title_spans.push(Span::raw(" ["));
                        title_spans.extend(filter_spans);
                        title_spans.push(Span::raw("]"));
                    }
                    
                    Line::from(title_spans)
                }
            ))
            .highlight_style(Style::default().bg(Color::DarkGray))
        };
        
        // Set the table state selection
        if dashboard_focus == DashboardFocus::BannedIPs {
            self.state.dashboard_banned_ip_table_state.select(Some(banned_ip_selected_index));
        } else {
            self.state.dashboard_banned_ip_table_state.select(None);
        }
        
        frame.render_stateful_widget(table, area, &mut self.state.dashboard_banned_ip_table_state);
    }
    
    fn initialize_dashboard_states(&mut self) {
        // Initialize table states based on current focus and data
        match self.state.dashboard_focus {
            DashboardFocus::Jails => {
                self.state.dashboard_jail_table_state.select(Some(self.state.dashboard_jail_selected_index));
                self.state.dashboard_banned_ip_table_state.select(None);
            },
            DashboardFocus::BannedIPs => {
                self.state.dashboard_jail_table_state.select(None);
                self.state.dashboard_banned_ip_table_state.select(Some(self.state.dashboard_banned_ip_selected_index));
            },
        }
    }
    
    fn initialize_configuration_states(&mut self) {
        // Initialize configuration table state
        self.state.config_management.table_state.select(Some(self.state.config_management.selected_file_index));
        
        // Update file existence status
        for file in &mut self.state.config_management.config_files {
            file.exists = std::path::Path::new(&file.path).exists();
        }
    }
    
    fn render_help(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let help_text = self.get_contextual_help();
        
        // Calculate max scroll based on content length and available space
        let content_height = help_text.len();
        let available_height = area.height.saturating_sub(2) as usize; // Subtract border height
        let max_scroll = content_height.saturating_sub(available_height);
        
        // Ensure scroll offset doesn't exceed max
        let scroll_offset = self.state.help_scroll_offset.min(max_scroll);
        
        let help = Paragraph::new(help_text)
            .block(Block::default()
                .title(format!("Help & Quick Reference (↑↓ to scroll, Page Up/Down, Home) [{}/{}]", 
                    scroll_offset + 1, 
                    content_height.max(1)))
                .borders(Borders::ALL))
            .scroll((scroll_offset as u16, 0));
        
        frame.render_widget(help, area);
    }
    
    fn get_contextual_help(&self) -> Vec<Line> {
        let mut help_lines = vec![
            Line::from(vec![
                Span::styled("f2b-buxjr", Style::default().fg(Color::Cyan)),
                Span::raw(" - Professional fail2ban TUI Administration Tool"),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("💡 Navigation Tip: ", Style::default().fg(Color::Yellow)),
                Span::raw("Use ↑↓ arrows, Page Up/Down, or Home to scroll through this help"),
            ]),
            Line::raw(""),
            Line::from(vec![
                Span::styled("🚀 NEW: High-Performance Pagination", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::raw("Efficiently handles "),
                Span::styled("thousands of banned IPs", Style::default().fg(Color::Yellow)),
                Span::raw(" with responsive pagination (Dashboard → Banned IPs → ,. keys)"),
            ]),
            Line::raw(""),
        ];
        
        // Add current screen specific help
        match self.state.current_screen {
            Screen::Dashboard => self.add_dashboard_help(&mut help_lines),
            Screen::Logs => self.add_logs_help(&mut help_lines),
            Screen::Configuration => self.add_configuration_help(&mut help_lines),
            Screen::Settings => self.add_settings_help(&mut help_lines),
            Screen::JailEditor => self.add_jail_editor_help(&mut help_lines),
            Screen::Whitelist => self.add_whitelist_help(&mut help_lines),
            _ => self.add_general_help(&mut help_lines),
        }
        
        // Add universal navigation
        help_lines.push(Line::raw(""));
        help_lines.push(Line::from(vec![
            Span::styled("🌐 Universal Navigation:", Style::default().fg(Color::Yellow)),
        ]));
        help_lines.push(Line::raw(""));
        
        let nav_sections = vec![
            ("H", "Help", "L", "Real-time Logs"),
            ("C", "Configuration", "W", "Whitelist"),
            ("G", "Settings & Performance", "I", "About & Version"),
            ("F", "Global Refresh", "Q", "Quit Application"),
            ("B", "Ban IP Dialog", "", ""),
            ("", "", "", ""),
        ];
        
        for (key1, desc1, key2, desc2) in nav_sections {
            help_lines.push(Line::from(vec![
                Span::styled(format!("{:>4}", key1), Style::default().fg(Color::Green)),
                Span::raw(format!(" {:<25}", desc1)),
                Span::styled(format!("{:>4}", key2), Style::default().fg(Color::Green)),
                Span::raw(format!(" {}", desc2)),
            ]));
        }
        
        help_lines.push(Line::raw(""));
        help_lines.push(Line::from(vec![
            Span::styled("ESC", Style::default().fg(Color::Cyan)),
            Span::raw(" Dashboard    "),
            Span::styled("Ctrl+C", Style::default().fg(Color::Red)),
            Span::raw(" Emergency Exit    "),
            Span::styled("Home", Style::default().fg(Color::Cyan)),
            Span::raw(" Dashboard"),
        ]));
        
        help_lines
    }
    
    fn add_dashboard_help(&self, lines: &mut Vec<Line>) {
        lines.push(Line::from(vec![
            Span::styled("📊 Dashboard Screen Help:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::raw("The Dashboard provides complete fail2ban management in one place."));
        lines.push(Line::raw("Use TAB to switch focus between Jails and Banned IPs panels."));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("🚀 Service Management:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• [R] Restart fail2ban service"));
        lines.push(Line::raw("• [S] Start fail2ban service"));
        lines.push(Line::raw("• [T] Stop fail2ban service"));
        lines.push(Line::raw("• [D] Reload configuration"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("⚖️  Jail Management (when Jails panel focused):", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• [↑/↓] Navigate jail list"));
        lines.push(Line::raw("• [ENTER] Enable/disable selected jail"));
        lines.push(Line::raw("• [E] Edit jail configuration"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("🚫 IP Management (when Banned IPs panel focused):", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• [↑/↓] Navigate banned IP list"));
        lines.push(Line::raw("• [U] Unban selected IP"));
        lines.push(Line::raw("• [W] Open whitelist dialog"));
        lines.push(Line::raw("• [X] Export banned IPs to CSV"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("🔍 Banned IP Filtering (Banned IPs panel):", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• [0] Clear all filters"));
        lines.push(Line::raw("• [1] Cycle IP address filter"));
        lines.push(Line::raw("• [2] Cycle jail name filter"));
        lines.push(Line::raw("• [3] Cycle ban age filter"));
        lines.push(Line::raw("• [4] Cycle remaining time filter"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("📄 Large Dataset Pagination (Banned IPs panel):", Style::default().fg(Color::Green)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("⚡ Performance Optimized", Style::default().fg(Color::Yellow)),
            Span::raw(" - Handles thousands of banned IPs efficiently"),
        ]));
        lines.push(Line::raw("• [,] (Comma) Previous page"));
        lines.push(Line::raw("• [.] (Period) Next page"));
        lines.push(Line::raw("• [Ctrl+Home] Jump to first page"));
        lines.push(Line::raw("• [Ctrl+End] Jump to last page"));
        lines.push(Line::raw("• Shows 100 IPs per page for optimal performance"));
        lines.push(Line::raw("• Page info displayed in table header (Page X of Y)"));
        lines.push(Line::raw("• Works seamlessly with all filtering options"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("⌨️  Navigation:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• [TAB] Switch focus between panels"));
        lines.push(Line::raw("• [↑↓] Navigate within current page"));
        lines.push(Line::raw("• [F] Global refresh (return to Dashboard)"));
    }
    
    
    
    fn add_jail_editor_help(&self, lines: &mut Vec<Line>) {
        lines.push(Line::from(vec![
            Span::styled("📝 Jail Configuration Editor Help:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::raw("Edit jail configuration with automatic backup and rollback:"));
        lines.push(Line::raw(""));
        
        let editor_commands = vec![
            ("[Ctrl+S]", "Save and Close", "Save configuration, reload fail2ban, and close editor"),
            ("[Esc]", "Cancel/Close", "Close editor (warns if unsaved changes)"),
            ("[Arrow Keys]", "Navigate", "Move cursor within the configuration"),
            ("[Enter]", "New Line", "Insert line break at cursor position"),
            ("[Backspace]", "Delete", "Delete character before cursor"),
        ];
        
        for (key, action, desc) in editor_commands {
            lines.push(Line::from(vec![
                Span::styled(key, Style::default().fg(Color::Green)),
                Span::raw(": "),
                Span::styled(action, Style::default().fg(Color::Cyan)),
                Span::raw(" - "),
                Span::raw(desc),
            ]));
        }
        
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("⚠️  Safety Features:", Style::default().fg(Color::Red)),
        ]));
        lines.push(Line::raw("• Automatic backup created before editing"));
        lines.push(Line::raw("• Configuration tested with fail2ban reload"));
        lines.push(Line::raw("• Automatic rollback if reload fails"));
        lines.push(Line::raw("• Changes reverted to maintain system stability"));
        lines.push(Line::raw(""));
        lines.push(Line::raw("Edit jail settings like enabled, port, maxretry, bantime, etc."));
    }
    
    
    fn add_logs_help(&self, lines: &mut Vec<Line>) {
        lines.push(Line::from(vec![
            Span::styled("📜 Real-time Log Monitoring Help:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::raw("Advanced log filtering and real-time monitoring:"));
        lines.push(Line::raw(""));
        
        let log_commands = vec![
            ("[R]", "Refresh Logs", "Reload recent log entries"),
            ("[C]", "Clear Buffer", "Clear log buffer from memory"),
            ("[0]", "Clear Filters", "Remove all active filters"),
        ];
        
        for (key, action, desc) in log_commands {
            lines.push(Line::from(vec![
                Span::styled(key, Style::default().fg(Color::Green)),
                Span::raw(format!(" {:<15} ", action)),
                Span::styled(desc, Style::default().fg(Color::Gray)),
            ]));
        }
        
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("🔍 Advanced Filtering:", Style::default().fg(Color::Cyan)),
        ]));
        
        let filter_commands = vec![
            ("[1]", "Log Level", "ERROR → WARN → NOTICE → INFO → DEBUG → All"),
            ("[2]", "Time Range", "1h → 6h → 24h → 1week → All"),
            ("[3]", "Ban Events", "Show only IP ban operations"),
            ("[4]", "Unban Events", "Show only IP unban operations"),
        ];
        
        for (key, action, desc) in filter_commands {
            lines.push(Line::from(vec![
                Span::styled(key, Style::default().fg(Color::Green)),
                Span::raw(format!(" {:<15} ", action)),
                Span::styled(desc, Style::default().fg(Color::Gray)),
            ]));
        }
        
        lines.push(Line::raw(""));
        lines.push(Line::raw("🟢 Logs update automatically every 5 seconds"));
        lines.push(Line::raw("🔍 Active filters shown at top with current criteria"));
    }
    
    fn add_configuration_help(&self, lines: &mut Vec<Line>) {
        lines.push(Line::from(vec![
            Span::styled("📝 Configuration Management Help:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::raw("fail2ban configuration file management:"));
        lines.push(Line::raw(""));
        
        let config_files = vec![
            ("jail.conf", "System default jail configuration"),
            ("jail.local", "Local overrides (recommended for changes)"),
            ("fail2ban.conf", "Main daemon configuration"),
            ("fail2ban.local", "Local daemon overrides"),
        ];
        
        for (file, desc) in config_files {
            lines.push(Line::from(vec![
                Span::styled(format!("● {:<15}", file), Style::default().fg(Color::Cyan)),
                Span::raw(desc),
            ]));
        }
        
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("📋 Available Actions:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• [↑/↓] Navigate configuration files"));
        lines.push(Line::raw("• [ENTER] Open selected file for editing"));
        lines.push(Line::raw("• [E] Edit selected configuration file"));
        lines.push(Line::raw("• [B] Backup current configuration"));
        lines.push(Line::raw("• [R] Restore configuration from backup"));
        lines.push(Line::raw("• [T] Test configuration validity"));
        lines.push(Line::raw(""));
        lines.push(Line::from(vec![
            Span::styled("⚠️  Best Practice:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw("Always edit .local files, not .conf files"));
        lines.push(Line::raw("Local files override system defaults safely"));
    }
    
    fn add_settings_help(&self, lines: &mut Vec<Line>) {
        lines.push(Line::from(vec![
            Span::styled("⚙️  Settings & Performance Help:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::raw("Monitor application performance and configure settings:"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("📊 Performance Metrics:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• Memory Usage: Real-time memory consumption"));
        lines.push(Line::raw("• CPU Load: Estimated processing load"));
        lines.push(Line::raw("• Refresh Time: Data update performance"));
        lines.push(Line::raw("• Log Entries: Current buffer utilization"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("🎯 Performance Indicators:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("🟢 Green", Style::default().fg(Color::Green)),
            Span::raw(": Optimal performance"),
        ]));
        lines.push(Line::from(vec![
            Span::styled("🟡 Yellow", Style::default().fg(Color::Yellow)),
            Span::raw(": Moderate usage"),
        ]));
        lines.push(Line::from(vec![
            Span::styled("🔴 Red", Style::default().fg(Color::Red)),
            Span::raw(": High usage - consider optimization"),
        ]));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("🔧 Memory Management:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• Automatic cleanup at 2000 log entries"));
        lines.push(Line::raw("• Filtered entries limited to 1000"));
        lines.push(Line::raw("• Performance stats updated every 10 seconds"));
    }
    
    fn add_whitelist_help(&self, lines: &mut Vec<Line>) {
        lines.push(Line::from(vec![
            Span::styled("🛡️  IP Whitelist Management Help:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::raw("Manage IP addresses that should never be banned by fail2ban:"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("📋 Whitelist Actions:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• [↑/↓] Navigate through whitelist entries"));
        lines.push(Line::raw("• [A] Add new IP address to whitelist"));
        lines.push(Line::raw("• [D] Delete selected IP from whitelist"));
        lines.push(Line::raw("• [ENTER] Edit selected whitelist entry"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("💡 Whitelist Examples:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• Single IP: 192.168.1.100"));
        lines.push(Line::raw("• IP Range: 192.168.1.0/24"));
        lines.push(Line::raw("• Multiple IPs: Add each separately"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("⚠️  Important Notes:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw("• Whitelisted IPs are never banned"));
        lines.push(Line::raw("• Changes take effect immediately"));
        lines.push(Line::raw("• Use carefully to avoid security risks"));
        lines.push(Line::raw("• Consider IP ranges for office networks"));
    }
    
    fn add_general_help(&self, lines: &mut Vec<Line>) {
        lines.push(Line::from(vec![
            Span::styled("🚀 Getting Started:", Style::default().fg(Color::Yellow)),
        ]));
        lines.push(Line::raw(""));
        lines.push(Line::raw("1. Check service status on Dashboard (F to refresh)"));
        lines.push(Line::raw("2. View and manage jails directly on Dashboard"));
        lines.push(Line::raw("3. Monitor real-time activity in Logs (L)"));
        lines.push(Line::raw("4. Manage banned IPs directly from Dashboard"));
        lines.push(Line::raw("5. Configure jails and settings (C)"));
        lines.push(Line::raw("6. Ban/unban IPs manually with B/U keys"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("💡 Pro Tips:", Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::raw("• Run with 'sudo' for full functionality"));
        lines.push(Line::raw("• Use TAB to switch focus between panels"));
        lines.push(Line::raw("• Use number keys (1-4) for quick filtering"));
        lines.push(Line::raw("• Use log filters to focus on specific events"));
        lines.push(Line::raw("• Monitor performance in Settings screen (G)"));
        lines.push(Line::raw("• Check banned IPs regularly for false positives"));
        lines.push(Line::raw("• Use ESC/HOME keys to quickly return to Dashboard"));
        lines.push(Line::raw(""));
        
        lines.push(Line::from(vec![
            Span::styled("🔥 Quick Actions:", Style::default().fg(Color::Red)),
        ]));
        lines.push(Line::raw("• B - Ban IP immediately"));
        lines.push(Line::raw("• U - Unban selected IP"));
        lines.push(Line::raw("• R/S/T/D - Service control (Restart/Start/sTlop/reloaD)"));
        lines.push(Line::raw("• F - Global refresh"));
        lines.push(Line::raw("• Ctrl+C - Emergency exit"));
    }
    
    fn render_about(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let about_text = vec![
            Line::from(vec![
                Span::styled("f2b-buxjr", Style::default().fg(Color::Cyan)),
                Span::raw(" v"),
                Span::styled(env!("CARGO_PKG_VERSION"), Style::default()),
            ]),
            Line::raw(""),
            Line::raw("Terminal User Interface for fail2ban administration"),
            Line::raw(""),
            Line::raw("Built with Rust + ratatui + crossterm"),
            Line::raw(""),
            Line::raw("For more information, visit:"),
            Line::styled("https://github.com/buxjr/f2b-buxjr", Style::default().fg(Color::Blue)),
        ];
        
        let about = Paragraph::new(about_text)
            .block(Block::default().title("About").borders(Borders::ALL));
        
        frame.render_widget(about, area);
    }
    
    
    
    
    
    
    fn render_whitelist(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header
                Constraint::Min(5),     // Content
                Constraint::Length(3),  // Instructions
            ])
            .split(area);
        
        // Header
        let header = Paragraph::new("IP Whitelist Management")
            .style(Style::default().fg(Color::Cyan))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, chunks[0]);
        
        // Content
        let mut whitelist_lines = vec![
            Line::from(vec![
                Span::styled("Whitelisted IPs and Ranges", Style::default().fg(Color::Yellow)),
                Span::raw(format!(" ({} total)", self.state.whitelist_ips.len())),
            ]),
            Line::raw(""),
        ];
        
        if self.state.whitelist_ips.is_empty() {
            whitelist_lines.push(Line::from(vec![
                Span::styled("No IPs in whitelist", Style::default().fg(Color::Yellow)),
            ]));
            whitelist_lines.push(Line::raw("Press [A] to add an IP address or range"));
        } else {
            whitelist_lines.push(Line::from(vec![
                Span::raw("IP Address / Range                    Status"),
            ]));
            whitelist_lines.push(Line::from(vec![
                Span::raw("─".repeat(50)),
            ]));
            
            for (index, ip) in self.state.whitelist_ips.iter().enumerate() {
                let style = if index == self.state.ip_management.selected_whitelist_index {
                    Style::default().bg(Color::Blue).fg(Color::White)
                } else {
                    Style::default()
                };
                
                let ip_padded = format!("{:<35}", ip);
                whitelist_lines.push(Line::from(vec![
                    Span::styled(
                        format!("{} ✓ Protected", ip_padded),
                        style
                    ),
                ]));
            }
        }
        
        let whitelist_widget = Paragraph::new(whitelist_lines)
            .block(Block::default().title("Whitelist").borders(Borders::ALL));
        frame.render_widget(whitelist_widget, chunks[1]);
        
        // Instructions
        let instructions = Paragraph::new("Use ↑/↓ to select • [A] Add IP • [D] Delete Selected • [Esc] Back to Dashboard")
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(instructions, chunks[2]);
        
        // Render dialog on top if open
        if self.state.ip_management.whitelist_dialog_open {
            self.render_whitelist_dialog(frame, area);
        }
    }
    
    fn render_ban_dialog(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        // Apply standard dialog clearing pattern
        frame.render_widget(Clear, area);
        
        // Create a completely solid background using filled text to ensure no bleed-through
        let overlay = " ".repeat((area.width * area.height) as usize);
        let solid_background = Paragraph::new(overlay)
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(solid_background, area);
        
        // Create a centered popup (increased height to fit all content)
        let popup_area = centered_rect(70, 60, area);
        
        // Then render the dialog border
        let dialog_border = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Manually Ban IP ");
        frame.render_widget(dialog_border, popup_area);
        
        // Create inner area for content (accounting for borders)
        let inner_area = popup_area.inner(&ratatui::layout::Margin { horizontal: 1, vertical: 1 });
        
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // IP input
                Constraint::Length(3),  // Jail selection
                Constraint::Length(3),  // Bantime display
                Constraint::Length(4),  // Buttons/instructions
            ])
            .split(inner_area);
        
        // IP input
        let ip_text = if self.state.ip_management.ban_ip_input.is_empty() {
            "Type IP address here...".to_string()
        } else {
            format!("{}_", self.state.ip_management.ban_ip_input) // Add cursor
        };
        
        let ip_active = self.state.ip_management.ban_dialog_field_index == 0;
        let ip_input = Paragraph::new(ip_text)
            .style(if ip_active { 
                Style::default().fg(Color::White).bg(Color::Blue) 
            } else { 
                Style::default().fg(Color::Gray).bg(Color::Black) 
            })
            .alignment(Alignment::Center)
            .block(Block::default()
                .title(" Enter IP Address ")
                .borders(Borders::ALL)
                .border_style(if ip_active {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                }));
        frame.render_widget(ip_input, chunks[0]);
        
        // Jail selection
        let jail_count = self.state.jails.len();
        let jail_active = self.state.ip_management.ban_dialog_field_index == 1;
        let jail_text = if jail_count == 0 {
            "No active jails available (check fail2ban service)".to_string()
        } else {
            let selected_jail = self.state.ip_management.selected_jail_for_ban
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or("(none selected)");
            
            if jail_active {
                format!("▶ {} ◀ (↑/↓ to change)", selected_jail)
            } else {
                selected_jail.to_string()
            }
        };
        let jail_selection = Paragraph::new(jail_text)
            .style(if jail_active { 
                Style::default().fg(Color::White).bg(Color::Blue) 
            } else { 
                Style::default().fg(Color::Gray) 
            })
            .alignment(Alignment::Center)
            .block(Block::default()
                .title("Jail")
                .borders(Borders::ALL)
                .border_style(if jail_active {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                }));
        frame.render_widget(jail_selection, chunks[1]);
        
        // Bantime display (read-only, shows jail's configured bantime)
        let (bantime_text, bantime_title) = if let Some(ref selected_jail) = self.state.ip_management.selected_jail_for_ban {
            let bantime = self.get_jail_bantime(selected_jail);
            (bantime, format!(" Ban Duration (jail configured: {}) ", selected_jail))
        } else {
            ("Select a jail to see bantime".to_string(), " Ban Duration (jail configured) ".to_string())
        };
        let bantime_display = Paragraph::new(bantime_text)
            .style(Style::default().fg(Color::Cyan))
            .alignment(Alignment::Center)
            .block(Block::default()
                .title(bantime_title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)));
        frame.render_widget(bantime_display, chunks[2]);
        
        // Instructions and buttons
        let current_field = match self.state.ip_management.ban_dialog_field_index {
            0 => "IP Address",
            1 => "Jail (use ↑/↓)",
            _ => "Unknown"
        };
        
        let instructions = vec![
            Line::from(vec![
                Span::styled("Current field: ", Style::default().fg(Color::Gray)),
                Span::styled(current_field, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("[Tab]", Style::default().fg(Color::Green)),
                Span::styled(" Next Field  ", Style::default().fg(Color::Gray)),
                Span::styled("[Enter]", Style::default().fg(Color::Green)),
                Span::styled(" Ban IP  ", Style::default().fg(Color::Gray)),
                Span::styled("[Esc]", Style::default().fg(Color::Red)),
                Span::styled(" Cancel", Style::default().fg(Color::Gray)),
            ]),
        ];
        
        let buttons = Paragraph::new(instructions)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(buttons, chunks[3]);
    }
    
    fn render_unban_confirmation(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        // Apply standard dialog clearing pattern
        frame.render_widget(Clear, area);
        
        // Create a completely solid background using filled text to ensure no bleed-through
        let overlay = " ".repeat((area.width * area.height) as usize);
        let solid_background = Paragraph::new(overlay)
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(solid_background, area);
        
        let popup_area = centered_rect(50, 40, area);
        
        // Then render the dialog border
        let dialog_border = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .title(" Confirm Unban ");
        frame.render_widget(dialog_border, popup_area);
        
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Min(3),     // Message
                Constraint::Length(4),  // Buttons - right size for instruction text
            ])
            .split(popup_area);
        
        let title = Paragraph::new("Confirm Unban")
            .style(Style::default().fg(Color::Red))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(title, chunks[0]);
        
        let default_ip = "Unknown".to_string();
        let default_jail = "Unknown".to_string();
        let ip = self.state.ip_management.ip_to_unban.as_ref().unwrap_or(&default_ip);
        let jail = self.state.ip_management.jail_for_unban.as_ref().unwrap_or(&default_jail);
        
        let message = Paragraph::new(format!("Unban IP {} from jail {}?", ip, jail))
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(message, chunks[1]);
        
        let buttons = Paragraph::new("[Enter] Confirm • [Esc] Cancel")
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(buttons, chunks[2]);
    }
    
    fn render_whitelist_dialog(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        // Create a solid overlay using Clear widget and filled paragraph
        frame.render_widget(Clear, area);
        
        // Create a completely solid background using filled text to ensure no bleed-through
        let overlay = " ".repeat((area.width * area.height) as usize);
        let solid_background = Paragraph::new(overlay)
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(solid_background, area);
        
        let popup_area = centered_rect(70, 50, area);
        
        // Then render the dialog border with white text
        let dialog_border = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::White))
            .title(" Add IP or Range to Whitelist ")
            .title_style(Style::default().fg(Color::White));
        frame.render_widget(dialog_border, popup_area);
        
        // Split popup area into sections
        let inner = popup_area.inner(&Margin { horizontal: 2, vertical: 2 });
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Input field
                Constraint::Length(1),  // Spacer
                Constraint::Length(4),  // Instructions
                Constraint::Length(1),  // Spacer  
                Constraint::Length(1),  // Buttons
            ])
            .split(inner);
        
        // Input field with white text on blue background
        let input_text = if self.state.ip_management.whitelist_ip_input.is_empty() {
            "Type IP address or CIDR range here...".to_string()
        } else {
            format!("{}_", self.state.ip_management.whitelist_ip_input) // cursor
        };
        
        let input = Paragraph::new(input_text)
            .style(Style::default().fg(Color::White).bg(Color::Blue))
            .alignment(Alignment::Center)
            .block(Block::default()
                .title(" Enter IP Address or Range ")
                .title_style(Style::default().fg(Color::White))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)));
        frame.render_widget(input, chunks[0]);
        
        // Instructions with examples
        let instructions = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("• Single IP: ", Style::default().fg(Color::White)),
                Span::styled("192.168.1.100", Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("• IP range: ", Style::default().fg(Color::White)),
                Span::styled("192.168.1.0/24", Style::default().fg(Color::Green)),
                Span::styled(" (entire subnet)", Style::default().fg(Color::Gray)),
            ]),
            Line::from(vec![
                Span::styled("• Large range: ", Style::default().fg(Color::White)),
                Span::styled("10.0.0.0/8", Style::default().fg(Color::Green)),
                Span::styled(" (private network)", Style::default().fg(Color::Gray)),
            ]),
        ])
            .style(Style::default().bg(Color::Black)) // Ensure solid background
            .block(Block::default()
                .title(" Examples ")
                .title_style(Style::default().fg(Color::White))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)));
        frame.render_widget(instructions, chunks[2]);
        
        // Buttons
        let buttons = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("[Enter]", Style::default().fg(Color::Green)),
                Span::styled(" Add to Whitelist  •  ", Style::default().fg(Color::White)),
                Span::styled("[Esc]", Style::default().fg(Color::Red)),
                Span::styled(" Cancel", Style::default().fg(Color::White)),
            ]),
        ])
            .style(Style::default().bg(Color::Black))
            .alignment(Alignment::Center);
        frame.render_widget(buttons, chunks[4]);
    }
    
    fn render_configuration(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        // If config editor is open, render that instead
        if self.state.config_management.editor_open {
            self.render_config_editor(frame, area);
            return;
        }
        
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),     // Main table
                Constraint::Length(5),  // Status info
            ])
            .split(area);
        
        // Create table data
        let header = Row::new(vec![
            Cell::from("Status"),
            Cell::from("File Path"),
            Cell::from("Description"),
            Cell::from("Editable"),
        ]).style(Style::default().fg(Color::Yellow));
        
        let rows: Vec<Row> = self.state.config_management.config_files.iter().map(|file| {
            let status_symbol = if file.exists { "●" } else { "○" };
            let status_color = if file.exists { Color::Green } else { Color::Gray };
            let editable_text = if file.editable { "Yes" } else { "No" };
            let editable_color = if file.editable { Color::Green } else { Color::Gray };
            
            Row::new(vec![
                Cell::from(Span::styled(status_symbol, Style::default().fg(status_color))),
                Cell::from(Span::styled(file.path.clone(), Style::default().fg(Color::Cyan))),
                Cell::from(Span::styled(file.description.clone(), Style::default().fg(Color::Gray))),
                Cell::from(Span::styled(editable_text, Style::default().fg(editable_color))),
            ])
        }).collect();
        
        let table = Table::new(rows, &[
            Constraint::Length(6),       // Status
            Constraint::Length(32),      // File Path
            Constraint::Min(30),         // Description
            Constraint::Length(8),       // Editable
        ])
        .header(header)
        .block(Block::default()
            .title(Line::from(vec![
                Span::raw("Configuration Files - "),
                Span::styled("E", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Edit | "),
                Span::styled("B", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Backup | "),
                Span::styled("R", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Restore | "),
                Span::styled("T", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Test | "),
                Span::styled("ESC", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Back"),
            ]))
            .borders(Borders::ALL))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White));
        
        frame.render_stateful_widget(table, chunks[0], &mut self.state.config_management.table_state.clone());
        
        // Status section
        let mut status_lines = vec![
            Line::from(vec![
                Span::styled("Configuration Status:", Style::default().fg(Color::Yellow)),
            ]),
        ];
        
        if matches!(self.state.fail2ban_service, ServiceStatus::Running) {
            status_lines.push(Line::from(vec![
                Span::styled("✓", Style::default().fg(Color::Green)),
                Span::raw(" fail2ban service is running"),
            ]));
            status_lines.push(Line::from(vec![
                Span::styled("✓", Style::default().fg(Color::Green)),
                Span::raw(format!(" {} jails configured", self.state.jails.len())),
            ]));
        } else {
            status_lines.push(Line::from(vec![
                Span::styled("⚠", Style::default().fg(Color::Yellow)),
                Span::raw(" fail2ban service is not running"),
            ]));
            status_lines.push(Line::raw("  Configuration may have errors"));
        }
        
        let status_widget = Paragraph::new(status_lines)
            .block(Block::default().borders(Borders::ALL));
        
        frame.render_widget(status_widget, chunks[1]);
    }
    
    fn render_logs(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let mut log_lines = vec![];
        
        
        let log_path = LogMonitor::get_fail2ban_log_path();
        let log_exists = std::path::Path::new(&log_path).exists();
        
        if !log_exists {
            log_lines.push(Line::from(vec![
                Span::styled("⚠ Log file not found", Style::default().fg(Color::Yellow)),
            ]));
            log_lines.push(Line::raw(""));
            log_lines.push(Line::raw("The fail2ban log file could not be found."));
            log_lines.push(Line::raw("This may be because:"));
            log_lines.push(Line::raw("  • fail2ban is not installed"));
            log_lines.push(Line::raw("  • fail2ban has not started yet"));
            log_lines.push(Line::raw("  • fail2ban is configured to log elsewhere"));
            log_lines.push(Line::raw(""));
            log_lines.push(Line::raw("Check your fail2ban configuration or start the service."));
        } else if self.state.log_entries.is_empty() {
            log_lines.push(Line::from(vec![
                Span::styled("No log entries loaded", Style::default().fg(Color::Yellow)),
            ]));
            log_lines.push(Line::raw(""));
            log_lines.push(Line::raw("This may be because:"));
            log_lines.push(Line::raw("  • The log file is empty"));
            log_lines.push(Line::raw("  • fail2ban has not generated any log entries yet"));
            log_lines.push(Line::raw("  • Log file permissions prevent reading"));
            log_lines.push(Line::raw(""));
            log_lines.push(Line::raw("Try running as root or check fail2ban configuration."));
        } else {
            // Show filter status
            let filter_active = self.state.log_filter.level.is_some() ||
                              self.state.log_filter.jail.is_some() ||
                              self.state.log_filter.show_only_bans ||
                              self.state.log_filter.show_only_unbans ||
                              self.state.log_filter.time_range_hours.is_some() ||
                              !self.state.log_search_query.is_empty();
            
            // Use filtered entries or all entries
            let entries_to_display = if filter_active {
                &self.state.filtered_log_entries
            } else {
                &self.state.log_entries.iter().cloned().collect::<Vec<_>>()
            };
            
            // Always render the log table, even when empty due to filters
            self.render_log_table(frame, area, entries_to_display, filter_active);
            return; // Exit early since we're rendering the table directly
        }
        
        log_lines.push(Line::raw(""));
        log_lines.push(Line::from(vec![
            Span::styled("Auto-refresh:", Style::default().fg(Color::Gray)),
            Span::raw(format!(" every {}s", self.auto_refresh_interval.as_secs())),
        ]));
        
        let log_title = format!("Logs [{}] - ", LogMonitor::get_fail2ban_log_path());
        let logs_widget = Paragraph::new(log_lines)
            .block(Block::default().title(Line::from(vec![
                Span::raw(&log_title),
                Span::styled("R", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Refresh | "),
                Span::styled("C", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Clear | "),
                Span::styled("0", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Clear Filters | "),
                Span::styled("1", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Level | "),
                Span::styled("2", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Time | "),
                Span::styled("3", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Bans | "),
                Span::styled("4", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Unbans | "),
                Span::styled("↑↓", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Scroll"),
            ])).borders(Borders::ALL));
        
        frame.render_widget(logs_widget, area);
    }
    
    fn render_log_table(&self, frame: &mut Frame, area: ratatui::layout::Rect, entries: &[LogEntry], _filter_active: bool) {
        let log_title = format!("Logs [{}] - ", LogMonitor::get_fail2ban_log_path());
        // Create layout for table and footer (filters now in table title)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(10), // Table (minimum 10 rows, but will expand)
                Constraint::Length(2), // Footer
            ])
            .split(area);
        
        // Calculate scrollable viewing window for table
        let available_height = chunks[0].height.saturating_sub(3) as usize; // Reserve space for table header and borders
        let total_entries = entries.len();
        let entries_to_show = std::cmp::min(available_height, total_entries);
        
        // Adjust scroll offset to be within bounds
        let max_scroll = total_entries.saturating_sub(entries_to_show);
        let scroll_offset = std::cmp::min(self.state.log_scroll_offset, max_scroll);
        
        // Calculate start index for current view
        let start_index = if total_entries <= entries_to_show {
            0
        } else {
            scroll_offset
        };
        
        // Create table rows
        let mut rows = Vec::new();
        for entry in entries.iter().skip(start_index).take(entries_to_show) {
            let date_str = entry.timestamp.format("%Y-%m-%d").to_string();
            let time_str = entry.timestamp.format("%H:%M:%S").to_string();
            let level_color = match entry.level.as_str() {
                "ERROR" => Color::Red,
                "WARN" | "WARNING" => Color::Yellow,
                "NOTICE" => Color::Blue,
                "INFO" => Color::Green,
                "DEBUG" => Color::Gray,
                _ => Color::White,
            };
            
            let jail_name = entry.jail.as_deref().unwrap_or("-");
            
            // Truncate message if too long to fit in table
            let message = if entry.message.len() > 100 {
                format!("{}...", &entry.message[..97])
            } else {
                entry.message.clone()
            };
            
            rows.push(Row::new(vec![
                Cell::from(date_str).style(Style::default().fg(Color::White)),
                Cell::from(time_str).style(Style::default().fg(Color::White)),
                Cell::from(entry.level.clone()).style(Style::default().fg(level_color)),
                Cell::from(jail_name).style(Style::default().fg(Color::White)),
                Cell::from(message).style(Style::default().fg(Color::White)),
            ]));
        }
        
        // Create table with headers
        let table = Table::new(
            rows,
            [
                Constraint::Length(12), // Date: YYYY-MM-DD
                Constraint::Length(10), // Time: HH:MM:SS
                Constraint::Length(8),  // Level
                Constraint::Length(12), // Jail
                Constraint::Min(50),    // Message (remaining space)
            ]
        )
            .header(Row::new(vec![
                Cell::from("Date").style(Style::default().fg(Color::Yellow)),
                Cell::from("Time").style(Style::default().fg(Color::Yellow)),
                Cell::from("Level").style(Style::default().fg(Color::Yellow)),
                Cell::from("Jail").style(Style::default().fg(Color::Yellow)),
                Cell::from("Message").style(Style::default().fg(Color::Yellow)),
            ]))
            .block(Block::default().borders(Borders::ALL).title(Line::from(vec![
                Span::raw(&log_title),
                Span::styled("R", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Refresh | "),
                Span::styled("C", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Clear | "),
                Span::styled("0", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Clear Filters | "),
                Span::styled("1", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Level | "),
                Span::styled("2", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Time | "),
                Span::styled("3", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Bans | "),
                Span::styled("4", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Unbans | "),
                Span::styled("↑↓", Style::default().fg(Color::Rgb(0, 150, 255))),
                Span::raw(":Scroll"),
            ])));
        
        frame.render_widget(table, chunks[0]);
        
        // Render footer with scroll status and auto-refresh info
        let mut footer_lines = vec![];
        
        if total_entries > entries_to_show {
            let current_range_start = start_index + 1;
            let current_range_end = std::cmp::min(start_index + entries_to_show, total_entries);
            
            let scroll_indicator = if scroll_offset == 0 {
                format!("Showing newest {} of {} entries (↑/↓ to scroll)", 
                       entries_to_show, total_entries)
            } else {
                format!("Showing entries {}-{} of {} (↑/↓ to scroll)", 
                       current_range_start, current_range_end, total_entries)
            };
            
            footer_lines.push(Line::from(vec![
                Span::styled(scroll_indicator, Style::default().fg(Color::Gray)),
            ]));
        }
        
        // Add active filters display with color-coded levels
        let filter_spans = self.get_active_filters_spans();
        if !filter_spans.is_empty() {
            let mut line_spans = vec![Span::styled("Active filters: ", Style::default().fg(Color::Gray))];
            line_spans.extend(filter_spans);
            footer_lines.push(Line::from(line_spans));
        }
        
        // Add auto-refresh countdown or refreshing status
        if self.is_refreshing {
            footer_lines.push(Line::from(vec![
                Span::styled("Refreshing...", Style::default().fg(Color::Yellow)),
            ]));
        } else {
            let refresh_remaining = self.auto_refresh_interval.as_secs() as i64 - self.last_auto_refresh.elapsed().as_secs() as i64;
            let refresh_remaining = refresh_remaining.max(0) as u64;
            
            footer_lines.push(Line::from(vec![
                Span::styled("Auto Refresh in ", Style::default().fg(Color::Gray)),
                Span::styled(format!("{}s", refresh_remaining), Style::default().fg(Color::Cyan)),
            ]));
        }
        
        let footer_widget = Paragraph::new(footer_lines);
        frame.render_widget(footer_widget, chunks[1]);
    }
    
    fn render_settings(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let mut settings_lines = vec![
            Line::from(vec![
                Span::styled("Settings & Performance", Style::default().fg(Color::Cyan)),
            ]),
            Line::raw(""),
        ];
        
        // Performance section
        settings_lines.push(Line::from(vec![
            Span::styled("Performance Metrics:", Style::default().fg(Color::Yellow)),
        ]));
        settings_lines.push(Line::raw(""));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Memory Usage:    "),
            Span::styled(
                format!("{:.1} MB", self.performance_stats.memory_usage_mb),
                if self.performance_stats.memory_usage_mb > 50.0 {
                    Style::default().fg(Color::Red)
                } else if self.performance_stats.memory_usage_mb > 25.0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                }
            ),
        ]));
        
        settings_lines.push(Line::from(vec![
            Span::raw("CPU Load:        "),
            Span::styled(
                format!("{:.1}%", self.performance_stats.cpu_load),
                if self.performance_stats.cpu_load > 80.0 {
                    Style::default().fg(Color::Red)
                } else if self.performance_stats.cpu_load > 50.0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                }
            ),
        ]));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Refresh Time:    "),
            Span::styled(
                format!("{} ms", self.performance_stats.refresh_time_ms),
                if self.performance_stats.refresh_time_ms > 500 {
                    Style::default().fg(Color::Red)
                } else if self.performance_stats.refresh_time_ms > 200 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                }
            ),
        ]));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Log Entries:     "),
            Span::styled(
                format!("{}", self.performance_stats.log_entries_processed),
                Style::default().fg(Color::Cyan)
            ),
        ]));
        
        settings_lines.push(Line::raw(""));
        
        // Application settings
        settings_lines.push(Line::from(vec![
            Span::styled("Application Settings:", Style::default().fg(Color::Yellow)),
        ]));
        settings_lines.push(Line::raw(""));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Auto-refresh:    "),
            Span::styled(
                format!("{}s", self.auto_refresh_interval.as_secs()),
                Style::default().fg(Color::Cyan)
            ),
        ]));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Log Buffer:      "),
            Span::styled(
                format!("{} / 2000 entries", self.state.log_entries.len()),
                if self.state.log_entries.len() > 1500 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                }
            ),
        ]));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Filtered Logs:   "),
            Span::styled(
                format!("{} / 1000 entries", self.state.filtered_log_entries.len()),
                if self.state.filtered_log_entries.len() > 800 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                }
            ),
        ]));
        
        settings_lines.push(Line::raw(""));
        
        // System information
        settings_lines.push(Line::from(vec![
            Span::styled("System Information:", Style::default().fg(Color::Yellow)),
        ]));
        settings_lines.push(Line::raw(""));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Application:     "),
            Span::styled("f2b-buxjr", Style::default().fg(Color::Cyan)),
            Span::raw(" v"),
            Span::styled(env!("CARGO_PKG_VERSION"), Style::default()),
        ]));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Build:           "),
            Span::styled("Rust + ratatui + crossterm", Style::default().fg(Color::Gray)),
        ]));
        
        settings_lines.push(Line::from(vec![
            Span::raw("Target:          "),
            Span::styled("fail2ban administration", Style::default().fg(Color::Gray)),
        ]));
        
        settings_lines.push(Line::raw(""));
        
        // Memory management info
        settings_lines.push(Line::from(vec![
            Span::styled("Memory Management:", Style::default().fg(Color::Yellow)),
        ]));
        settings_lines.push(Line::raw(""));
        
        settings_lines.push(Line::raw("• Log entries automatically trimmed at 2000 entries"));
        settings_lines.push(Line::raw("• Filtered entries limited to 1000 entries"));
        settings_lines.push(Line::raw("• Performance stats updated every 10 seconds"));
        settings_lines.push(Line::raw("• Old status messages cleared after 10 seconds"));
        
        settings_lines.push(Line::raw(""));
        
        // Performance recommendations
        if self.performance_stats.memory_usage_mb > 50.0 || 
           self.performance_stats.refresh_time_ms > 500 ||
           self.state.log_entries.len() > 1500 {
            settings_lines.push(Line::from(vec![
                Span::styled("⚠ Performance Recommendations:", Style::default().fg(Color::Yellow)),
            ]));
            settings_lines.push(Line::raw(""));
            
            if self.performance_stats.memory_usage_mb > 50.0 {
                settings_lines.push(Line::raw("• Consider clearing log buffer (Logs screen -> C)"));
            }
            if self.performance_stats.refresh_time_ms > 500 {
                settings_lines.push(Line::raw("• System may be under high load"));
            }
            if self.state.log_entries.len() > 1500 {
                settings_lines.push(Line::raw("• Log buffer is getting full"));
            }
        } else {
            settings_lines.push(Line::from(vec![
                Span::styled("✓ Performance Status: Good", Style::default().fg(Color::Green)),
            ]));
        }
        
        let settings_widget = Paragraph::new(settings_lines)
            .block(Block::default().title("Settings").borders(Borders::ALL));
        
        frame.render_widget(settings_widget, area);
    }
    
    
    fn render_footer(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let hotkey_color = Color::Rgb(0, 150, 255); // Consistent bright blue
        
        let mut footer_spans = vec![
            Span::styled("H", Style::default().fg(hotkey_color)),
            Span::raw(":Help"),
            Span::styled(" | ", Style::default().fg(Color::Gray)),
            Span::styled("C", Style::default().fg(hotkey_color)),
            Span::raw(":Config"),
            Span::styled(" | ", Style::default().fg(Color::Gray)),
            Span::styled("F", Style::default().fg(hotkey_color)),
            Span::raw(":Refresh"),
            Span::styled(" | ", Style::default().fg(Color::Gray)),
            Span::styled("L", Style::default().fg(hotkey_color)),
            Span::raw(":Logs"),
            Span::styled(" | ", Style::default().fg(Color::Gray)),
            Span::styled("W", Style::default().fg(hotkey_color)),
            Span::raw(":Whitelist"),
        ];
        
        // Add screen-specific shortcuts
        match self.state.current_screen {
            Screen::JailEditor => {
                footer_spans.extend(vec![
                    Span::styled(" | Ctrl+S", Style::default().fg(hotkey_color)),
                    Span::raw(" Save "),
                    Span::styled("Esc", Style::default().fg(hotkey_color)),
                    Span::raw(" Close "),
                ]);
            },
            _ => {}
        }
        
        // Add universal shortcuts
        footer_spans.extend(vec![
            Span::styled(" | ", Style::default().fg(Color::Gray)),
            Span::styled("B", Style::default().fg(hotkey_color)),
            Span::raw(":Ban IP"),
            Span::styled(" | ", Style::default().fg(Color::Gray)),
            Span::styled("ESC", Style::default().fg(hotkey_color)),
            Span::raw(":Back"),
            Span::styled(" | ", Style::default().fg(Color::Gray)),
            Span::styled("Q", Style::default().fg(hotkey_color)),
            Span::raw(":Quit"),
        ]);
        
        let footer_lines = vec![Line::from(footer_spans)];
        
        let footer = Paragraph::new(footer_lines)
            .block(Block::default().borders(Borders::TOP));
        
        frame.render_widget(footer, area);
    }
    
    fn render_progress_bar(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        if let Some(ref operation) = self.state.current_operation {
            let elapsed = operation.started_at.elapsed();
            let estimated_remaining = operation.estimated_completion
                .map(|completion| completion.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(0));
            
            // Create progress bar
            let progress_ratio = operation.progress_percent as f64 / 100.0;
            let bar_width = (area.width as f64 * 0.6) as usize;
            let filled_width = (bar_width as f64 * progress_ratio) as usize;
            
            let progress_bar = format!(
                "[{}{}] {}%",
                "█".repeat(filled_width),
                "░".repeat(bar_width.saturating_sub(filled_width)),
                operation.progress_percent
            );
            
            let mut progress_lines = vec![
                Line::from(vec![
                    Span::styled(
                        format!("🔄 {}", operation.status_text),
                        Style::default().fg(Color::Cyan)
                    ),
                    Span::raw(format!(" ({}s elapsed)", elapsed.as_secs())),
                ]),
            ];
            
            if estimated_remaining.as_secs() > 0 {
                progress_lines.push(Line::from(vec![
                    Span::styled(progress_bar, Style::default().fg(Color::Yellow)),
                    Span::raw(format!(" ETA: {}s", estimated_remaining.as_secs())),
                ]));
            } else {
                progress_lines.push(Line::from(vec![
                    Span::styled(progress_bar, Style::default().fg(Color::Green)),
                    Span::raw(" Completing..."),
                ]));
            }
            
            let progress_widget = Paragraph::new(progress_lines)
                .block(Block::default().borders(Borders::ALL).title("Operation Progress"));
            
            frame.render_widget(progress_widget, area);
        }
    }
    
    fn load_recent_logs(&mut self) {
        match self.log_monitor.get_recent_lines(100) {
            Ok(entries) => {
                // Clear existing entries and add new ones (already sorted by timestamp, newest first)
                self.state.log_entries = entries;
                log::debug!("Loaded {} recent log entries", self.state.log_entries.len());
                
                // Update filtered entries
                self.update_filtered_logs();
            },
            Err(e) => {
                log::warn!("Failed to load recent logs: {}", e);
            }
        }
    }
    
    fn update_log_entries(&mut self) {
        match self.log_monitor.tail_new_lines() {
            Ok(new_entries) => {
                if !new_entries.is_empty() {
                    // Add new entries and re-sort to maintain chronological order (newest first)
                    self.state.log_entries.extend(new_entries);
                    self.state.log_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                    
                    // Keep only the most recent 1000 entries to prevent memory issues
                    if self.state.log_entries.len() > 1000 {
                        self.state.log_entries.truncate(1000);
                    }
                    
                    // Update filtered entries when new entries are added
                    self.update_filtered_logs();
                }
            },
            Err(e) => {
                log::warn!("Failed to tail log file: {}", e);
            }
        }
    }
    
    fn update_filtered_logs(&mut self) {
        let mut filtered = Vec::new();
        let now = chrono::Utc::now();
        
        for entry in &self.state.log_entries {
            // Apply time range filter
            if let Some(hours) = self.state.log_filter.time_range_hours {
                let cutoff = now - chrono::Duration::hours(hours as i64);
                if entry.timestamp < cutoff {
                    continue;
                }
            }
            
            // Apply level filter
            if let Some(ref level_filter) = self.state.log_filter.level {
                if entry.level != *level_filter {
                    continue;
                }
            }
            
            // Apply jail filter
            if let Some(ref jail_filter) = self.state.log_filter.jail {
                match &entry.jail {
                    Some(jail) if jail == jail_filter => {},
                    None if jail_filter == "none" => {},
                    _ => continue,
                }
            }
            
            // Apply ban/unban filters
            if self.state.log_filter.show_only_bans {
                if !entry.message.to_lowercase().contains("ban ") || 
                   entry.message.to_lowercase().contains("unban") {
                    continue;
                }
            }
            
            if self.state.log_filter.show_only_unbans {
                if !entry.message.to_lowercase().contains("unban") {
                    continue;
                }
            }
            
            // Apply search query filter
            if !self.state.log_search_query.is_empty() {
                let query = self.state.log_search_query.to_lowercase();
                let message_match = entry.message.to_lowercase().contains(&query);
                let jail_match = entry.jail.as_ref()
                    .map(|j| j.to_lowercase().contains(&query))
                    .unwrap_or(false);
                let level_match = entry.level.to_lowercase().contains(&query);
                
                if !message_match && !jail_match && !level_match {
                    continue;
                }
            }
            
            filtered.push(entry.clone());
        }
        
        self.state.filtered_log_entries = filtered;
    }
    
    fn clear_log_filters(&mut self) {
        self.state.log_filter = LogFilter::default();
        self.state.log_search_query.clear();
        self.state.log_search_active = false;
        self.state.log_scroll_offset = 0; // Reset scroll position
        self.update_filtered_logs();
        self.set_status_message("✓ Log filters cleared");
    }
    
    
    fn get_sorted_jails_for_display(&self) -> Vec<JailConfig> {
        let mut sorted_jails = self.state.available_jails.clone();
        sorted_jails.sort_by(|a, b| {
            match (a.enabled, b.enabled) {
                (true, false) => std::cmp::Ordering::Less,    // enabled first
                (false, true) => std::cmp::Ordering::Greater, // disabled second
                _ => a.name.cmp(&b.name),                     // alphabetical within same status
            }
        });
        sorted_jails
    }
    
    fn get_active_filters_spans(&self) -> Vec<Span> {
        let mut spans = Vec::new();
        let mut filter_count = 0;
        
        if let Some(ref level) = self.state.log_filter.level {
            if filter_count > 0 {
                spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            spans.push(Span::styled("Level: ", Style::default().fg(Color::Yellow)));
            
            // Apply same color scheme as log table
            let level_color = match level.as_str() {
                "ERROR" => Color::Red,
                "WARN" | "WARNING" => Color::Yellow,
                "NOTICE" => Color::Blue,
                "INFO" => Color::Green,
                "DEBUG" => Color::Gray,
                _ => Color::White,
            };
            spans.push(Span::styled(level, Style::default().fg(level_color)));
            filter_count += 1;
        }
        
        if let Some(ref jail) = self.state.log_filter.jail {
            if filter_count > 0 {
                spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            spans.push(Span::styled(format!("Jail: {}", jail), Style::default().fg(Color::Yellow)));
            filter_count += 1;
        }
        
        if self.state.log_filter.show_only_bans {
            if filter_count > 0 {
                spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            spans.push(Span::styled("Bans only", Style::default().fg(Color::Yellow)));
            filter_count += 1;
        }
        
        if self.state.log_filter.show_only_unbans {
            if filter_count > 0 {
                spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            spans.push(Span::styled("Unbans only", Style::default().fg(Color::Yellow)));
            filter_count += 1;
        }
        
        if let Some(hours) = self.state.log_filter.time_range_hours {
            if filter_count > 0 {
                spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            spans.push(Span::styled(format!("Last {}h", hours), Style::default().fg(Color::Yellow)));
            filter_count += 1;
        }
        
        if !self.state.log_search_query.is_empty() {
            if filter_count > 0 {
                spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
            }
            spans.push(Span::styled(format!("Search: '{}'", self.state.log_search_query), Style::default().fg(Color::Yellow)));
        }
        
        spans
    }
    
    // Removed unused get_banned_ip_filter_spans function - now computed inline
    
    fn get_filtered_banned_ips(&mut self) -> &Vec<BannedIP> {
        let is_massive_dataset = self.state.banned_ips.len() > 15000;
        
        // For massive datasets (18k+ IPs), skip expensive filtering entirely and return original data
        if is_massive_dataset && !self.state.banned_ip_filter.has_active_filters() {
            // Just return the original banned IPs without any expensive operations
            self.state.cached_filtered_ips = Vec::new(); // Clear cache to save memory
            return &self.state.banned_ips;
        }
        
        // Check if we need to recalculate the filtered results
        let cache_is_valid = self.state.filter_cache_version == self.state.banned_ip_filter.version &&
                            !self.state.cached_filtered_ips.is_empty() &&
                            self.state.cached_filtered_ips.len() <= self.state.banned_ips.len();
        
        if !cache_is_valid {
            log::debug!("Rebuilding banned IP filter cache (version: {} -> {})", 
                       self.state.filter_cache_version, self.state.banned_ip_filter.version);
            let start_time = Instant::now();
            
            // For massive datasets, use iterator-based filtering to avoid cloning entire vector
            let filtered_ips: Vec<BannedIP> = if is_massive_dataset {
                log::warn!("PERFORMANCE MODE: Using iterator-based filtering for {} IPs", self.state.banned_ips.len());
                
                // Use iterator chain instead of cloning, which is much more memory efficient
                self.state.banned_ips.iter()
                    .filter(|ip| {
                        // Apply IP starting digit filter
                        if let Some(digit) = self.state.banned_ip_filter.ip_starting_digit {
                            if !ip.ip.starts_with(&digit.to_string()) {
                                return false;
                            }
                        }
                        
                        // Apply jail filter
                        if let Some(ref jail_filter) = self.state.banned_ip_filter.jail {
                            if &ip.jail != jail_filter {
                                return false;
                            }
                        }
                        
                        // Apply ban age filter
                        if let Some(hours) = self.state.banned_ip_filter.ban_age_hours {
                            let cutoff_time = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
                            if ip.ban_time < cutoff_time {
                                return false;
                            }
                        }
                        
                        // Apply remaining time filter
                        if let Some(remaining_filter) = self.state.banned_ip_filter.remaining_time {
                            let now = chrono::Utc::now();
                            match remaining_filter {
                                RemainingTimeFilter::Soon => {
                                    if let Some(unban_time) = ip.unban_time {
                                        if unban_time > now + chrono::Duration::hours(1) {
                                            return false;
                                        }
                                    } else {
                                        return false; // Permanent bans don't qualify for "soon"
                                    }
                                }
                                RemainingTimeFilter::Today => {
                                    if let Some(unban_time) = ip.unban_time {
                                        if unban_time > now + chrono::Duration::hours(24) {
                                            return false;
                                        }
                                    } else {
                                        return false; // Permanent bans don't qualify for "today"
                                    }
                                }
                                RemainingTimeFilter::ThisWeek => {
                                    if let Some(unban_time) = ip.unban_time {
                                        if unban_time > now + chrono::Duration::weeks(1) {
                                            return false;
                                        }
                                    } else {
                                        return false; // Permanent bans don't qualify for "this week"
                                    }
                                }
                                RemainingTimeFilter::Permanent => {
                                    if ip.unban_time.is_some() {
                                        return false; // Not a permanent ban
                                    }
                                }
                            }
                        }
                        
                        true
                    })
                    .cloned()
                    .collect()
            } else {
                // For smaller datasets, use the original retain-based approach
                let mut filtered_ips: Vec<BannedIP> = self.state.banned_ips.clone();
                
                // Apply IP starting digit filter
                if let Some(digit) = self.state.banned_ip_filter.ip_starting_digit {
                    filtered_ips.retain(|ip| ip.ip.starts_with(&digit.to_string()));
                }
                
                // Apply jail filter
                if let Some(ref jail_filter) = self.state.banned_ip_filter.jail {
                    filtered_ips.retain(|ip| &ip.jail == jail_filter);
                }
                
                // Apply ban age filter
                if let Some(hours) = self.state.banned_ip_filter.ban_age_hours {
                    let cutoff_time = chrono::Utc::now() - chrono::Duration::hours(hours as i64);
                    filtered_ips.retain(|ip| ip.ban_time >= cutoff_time);
                }
                
                filtered_ips
            };
            
            self.state.cached_filtered_ips = filtered_ips;
            self.state.filter_cache_version = self.state.banned_ip_filter.version;
            
            let filter_duration = start_time.elapsed();
            if filter_duration.as_millis() > 100 {
                log::info!("Filtered {} banned IPs to {} results in {:.2}ms", 
                          self.state.banned_ips.len(), self.state.cached_filtered_ips.len(), filter_duration.as_millis());
            }
        }
        
        &self.state.cached_filtered_ips
    }
    
    fn toggle_filter_bans_only(&mut self) {
        self.state.log_filter.show_only_bans = !self.state.log_filter.show_only_bans;
        if self.state.log_filter.show_only_bans {
            self.state.log_filter.show_only_unbans = false;
        }
        self.state.log_scroll_offset = 0; // Reset scroll position
        self.update_filtered_logs();
        
        let status = if self.state.log_filter.show_only_bans {
            "✓ Showing only ban events"
        } else {
            "✓ Showing all events"
        };
        self.set_status_message(status);
    }
    
    fn toggle_filter_unbans_only(&mut self) {
        self.state.log_filter.show_only_unbans = !self.state.log_filter.show_only_unbans;
        if self.state.log_filter.show_only_unbans {
            self.state.log_filter.show_only_bans = false;
        }
        self.state.log_scroll_offset = 0; // Reset scroll position
        self.update_filtered_logs();
        
        let status = if self.state.log_filter.show_only_unbans {
            "✓ Showing only unban events"
        } else {
            "✓ Showing all events"
        };
        self.set_status_message(status);
    }
    
    fn scroll_logs_up(&mut self) {
        // Determine which entries to use for scrolling calculation
        let entries = if self.state.log_filter.level.is_some() ||
                        self.state.log_filter.jail.is_some() ||
                        self.state.log_filter.show_only_bans ||
                        self.state.log_filter.show_only_unbans ||
                        self.state.log_filter.time_range_hours.is_some() ||
                        !self.state.log_search_query.is_empty() {
            &self.state.filtered_log_entries
        } else {
            &self.state.log_entries
        };
        
        // Calculate available display size
        let available_height = 20; // Approximate - will be calculated properly by render logic
        let entries_per_page = std::cmp::min(available_height, entries.len());
        
        if entries.len() > entries_per_page {
            let scroll_step = 5;
            
            if self.state.log_scroll_offset == 0 {
                // Already showing newest entries, can't scroll up further
                self.set_status_message("↑ Already at newest entries");
                return;
            }
            
            // Scroll up towards newer entries (decrease offset)
            let new_offset = if self.state.log_scroll_offset > scroll_step {
                self.state.log_scroll_offset - scroll_step
            } else {
                0 // Go to newest entries
            };
            
            self.state.log_scroll_offset = new_offset;
            if new_offset == 0 {
                self.set_status_message("↑ Scrolled to newest entries");
            } else {
                self.set_status_message("↑ Scrolled up to newer entries");
            }
        }
    }
    
    fn scroll_logs_down(&mut self) {
        // Determine which entries to use for scrolling calculation
        let entries = if self.state.log_filter.level.is_some() ||
                        self.state.log_filter.jail.is_some() ||
                        self.state.log_filter.show_only_bans ||
                        self.state.log_filter.show_only_unbans ||
                        self.state.log_filter.time_range_hours.is_some() ||
                        !self.state.log_search_query.is_empty() {
            &self.state.filtered_log_entries
        } else {
            &self.state.log_entries
        };
        
        // Calculate available display size
        let available_height = 20; // Approximate - will be calculated properly by render logic
        let entries_per_page = std::cmp::min(available_height, entries.len());
        
        if entries.len() > entries_per_page {
            let scroll_step = 5;
            let max_offset = entries.len().saturating_sub(entries_per_page);
            
            if self.state.log_scroll_offset >= max_offset {
                // Already showing oldest entries, can't scroll down further
                self.set_status_message("↓ Already at oldest entries");
                return;
            }
            
            // Scroll down towards older entries (increase offset)
            let new_offset = std::cmp::min(
                self.state.log_scroll_offset + scroll_step,
                max_offset
            );
            
            self.state.log_scroll_offset = new_offset;
            if new_offset == max_offset {
                self.set_status_message("↓ Scrolled to oldest entries");
            } else {
                self.set_status_message("↓ Scrolled down to older entries");
            }
        }
    }
    
    fn cycle_level_filter(&mut self) {
        self.state.log_filter.level = match &self.state.log_filter.level {
            None => Some("ERROR".to_string()),
            Some(level) => match level.as_str() {
                "ERROR" => Some("WARN".to_string()),
                "WARN" => Some("NOTICE".to_string()),
                "NOTICE" => Some("INFO".to_string()),
                "INFO" => Some("DEBUG".to_string()),
                _ => None,
            }
        };
        
        self.state.log_scroll_offset = 0; // Reset scroll position
        self.update_filtered_logs();
        
        let status = match &self.state.log_filter.level {
            None => "✓ Showing all log levels",
            Some(level) => {
                match level.as_str() {
                    "ERROR" => "✓ Showing only ERROR level",
                    "WARN" => "✓ Showing only WARN level", 
                    "NOTICE" => "✓ Showing only NOTICE level",
                    "INFO" => "✓ Showing only INFO level",
                    "DEBUG" => "✓ Showing only DEBUG level",
                    _ => "✓ Level filter updated",
                }
            }
        };
        self.set_status_message(status);
    }
    
    fn cycle_time_filter(&mut self) {
        self.state.log_filter.time_range_hours = match self.state.log_filter.time_range_hours {
            None => Some(1),
            Some(1) => Some(6),
            Some(6) => Some(24),
            Some(24) => Some(168), // 1 week
            _ => None,
        };
        
        self.state.log_scroll_offset = 0; // Reset scroll position
        self.update_filtered_logs();
        
        let status = match self.state.log_filter.time_range_hours {
            None => "✓ Showing all time ranges",
            Some(1) => "✓ Showing last 1 hour",
            Some(6) => "✓ Showing last 6 hours",
            Some(24) => "✓ Showing last 24 hours",
            Some(168) => "✓ Showing last week",
            Some(hours) => &format!("✓ Showing last {} hours", hours),
        };
        self.set_status_message(status);
    }
    
    // Banned IP filtering methods
    fn clear_banned_ip_filters(&mut self) {
        self.state.banned_ip_filter = BannedIpFilter::default();
        self.state.banned_ip_filter.version += 1;
        self.set_status_message("✓ Banned IP filters cleared");
    }
    
    fn cycle_ip_digit_filter(&mut self) {
        self.state.banned_ip_filter.ip_starting_digit = match self.state.banned_ip_filter.ip_starting_digit {
            None => Some('1'),
            Some('1') => Some('2'),
            Some('2') => Some('3'),
            Some('3') => Some('4'),
            Some('4') => Some('5'),
            Some('5') => Some('6'),
            Some('6') => Some('7'),
            Some('7') => Some('8'),
            Some('8') => Some('9'),
            _ => None,
        };
        self.state.banned_ip_filter.version += 1;
        
        let status = match self.state.banned_ip_filter.ip_starting_digit {
            None => "✓ Showing all IP addresses",
            Some(digit) => &format!("✓ Showing IPs starting with {}", digit),
        };
        self.set_status_message(status);
    }
    
    fn cycle_jail_filter(&mut self) {
        let available_jails: Vec<String> = self.state.jails.keys().cloned().collect();
        if available_jails.is_empty() {
            self.set_status_message("⚠ No jails available for filtering");
            return;
        }
        
        self.state.banned_ip_filter.jail = match &self.state.banned_ip_filter.jail {
            None => available_jails.get(0).cloned(),
            Some(current_jail) => {
                let current_index = available_jails.iter().position(|j| j == current_jail);
                match current_index {
                    Some(index) if index < available_jails.len() - 1 => {
                        available_jails.get(index + 1).cloned()
                    }
                    _ => None,
                }
            }
        };
        self.state.banned_ip_filter.version += 1;
        
        let status = match &self.state.banned_ip_filter.jail {
            None => "✓ Showing all jails",
            Some(jail) => &format!("✓ Showing only jail: {}", jail),
        };
        self.set_status_message(status);
    }
    
    fn cycle_ban_age_filter(&mut self) {
        self.state.banned_ip_filter.ban_age_hours = match self.state.banned_ip_filter.ban_age_hours {
            None => Some(1),      // Last hour
            Some(1) => Some(24),  // Last day  
            Some(24) => Some(168), // Last week
            _ => None,            // All times
        };
        self.state.banned_ip_filter.version += 1;
        
        let status = match self.state.banned_ip_filter.ban_age_hours {
            None => "✓ Showing bans from all times",
            Some(1) => "✓ Showing bans from last hour",
            Some(24) => "✓ Showing bans from last day",
            Some(168) => "✓ Showing bans from last week",
            Some(hours) => &format!("✓ Showing bans from last {} hours", hours),
        };
        self.set_status_message(status);
    }
    
    fn cycle_remaining_time_filter(&mut self) {
        self.state.banned_ip_filter.remaining_time = match self.state.banned_ip_filter.remaining_time {
            None => Some(RemainingTimeFilter::Soon),      // Within 1 hour
            Some(RemainingTimeFilter::Soon) => Some(RemainingTimeFilter::Today),     // Within 24 hours  
            Some(RemainingTimeFilter::Today) => Some(RemainingTimeFilter::ThisWeek), // Within 1 week
            Some(RemainingTimeFilter::ThisWeek) => Some(RemainingTimeFilter::Permanent), // Permanent only
            Some(RemainingTimeFilter::Permanent) => None, // All times
        };
        self.state.banned_ip_filter.version += 1;
        
        let status = match self.state.banned_ip_filter.remaining_time {
            None => "✓ Showing all remaining times",
            Some(RemainingTimeFilter::Soon) => "✓ Showing bans ending within 1 hour",
            Some(RemainingTimeFilter::Today) => "✓ Showing bans ending within 24 hours",
            Some(RemainingTimeFilter::ThisWeek) => "✓ Showing bans ending within 1 week",
            Some(RemainingTimeFilter::Permanent) => "✓ Showing permanent bans only",
        };
        self.set_status_message(status);
    }
    
    fn start_operation(&mut self, operation_type: OperationType) {
        let now = Instant::now();
        let estimated_completion = now + operation_type.estimated_duration();
        
        self.state.current_operation = Some(OperationProgress {
            operation_type: operation_type.clone(),
            progress_percent: 0,
            status_text: operation_type.display_name().to_string(),
            started_at: now,
            estimated_completion: Some(estimated_completion),
        });
        
    }
    
    fn update_operation_progress(&mut self, progress_percent: u8, status_text: Option<String>) {
        if let Some(ref mut operation) = self.state.current_operation {
            operation.progress_percent = progress_percent.min(100);
            
            if let Some(text) = status_text.clone() {
                operation.status_text = text;
            }
            
            // Update estimated completion based on current progress
            if progress_percent > 0 && progress_percent < 100 {
                let elapsed = operation.started_at.elapsed();
                let estimated_total = elapsed.mul_f32(100.0 / progress_percent as f32);
                operation.estimated_completion = Some(operation.started_at + estimated_total);
            }
            
        }
    }
    
    fn complete_operation(&mut self, success: bool, final_message: Option<String>) {
        let message = if let Some(operation) = &self.state.current_operation {
            let duration = operation.started_at.elapsed();
            
            let msg = if let Some(message) = final_message {
                message
            } else {
                let result = if success { "✓" } else { "✗" };
                format!("{} {} completed in {:.1}s", 
                       result, 
                       operation.operation_type.display_name(),
                       duration.as_secs_f32())
            };
            
            
            Some(msg)
        } else {
            final_message
        };
        
        self.state.current_operation = None;
        
        if let Some(msg) = message {
            self.set_status_message(&msg);
        }
    }
    
    fn update_performance_stats(&mut self) {
        let now = Instant::now();
        
        // Update performance stats every 10 seconds
        if now.duration_since(self.performance_stats.last_performance_check) >= Duration::from_secs(10) {
            self.performance_stats.memory_usage_mb = self.get_memory_usage_mb();
            self.performance_stats.cpu_load = self.get_cpu_load();
            self.performance_stats.log_entries_processed = self.state.log_entries.len();
            self.performance_stats.last_performance_check = now;
        }
    }
    
    fn get_memory_usage_mb(&self) -> f64 {
        // Simple memory estimation based on data structures
        let log_entries_size = self.state.log_entries.len() * std::mem::size_of::<crate::app::LogEntry>();
        let filtered_entries_size = self.state.filtered_log_entries.len() * std::mem::size_of::<crate::app::LogEntry>();
        let banned_ips_size = self.state.banned_ips.len() * std::mem::size_of::<crate::app::BannedIP>();
        let jails_size = self.state.jails.len() * (std::mem::size_of::<String>() + std::mem::size_of::<crate::app::JailState>());
        
        let total_bytes = log_entries_size + filtered_entries_size + banned_ips_size + jails_size + 1024 * 1024; // Base overhead
        total_bytes as f64 / (1024.0 * 1024.0)
    }
    
    fn get_cpu_load(&self) -> f64 {
        // Simple CPU load estimation based on recent activity
        let recent_activity = self.state.log_entries.len() as f64 / 1000.0; // Normalized to 0-1 scale
        recent_activity.min(1.0) * 100.0 // Convert to percentage
    }
    
    fn check_memory_limits(&mut self) {
        // Implement memory management to prevent excessive memory usage
        const MAX_LOG_ENTRIES: usize = 2000;
        const MAX_FILTERED_ENTRIES: usize = 1000;
        
        // Trim log entries if they exceed the limit (keep the newest entries)
        if self.state.log_entries.len() > MAX_LOG_ENTRIES {
            self.state.log_entries.truncate(MAX_LOG_ENTRIES);
        }
        
        // Trim filtered entries if they exceed the limit
        if self.state.filtered_log_entries.len() > MAX_FILTERED_ENTRIES {
            let excess = self.state.filtered_log_entries.len() - MAX_FILTERED_ENTRIES;
            self.state.filtered_log_entries.drain(0..excess);
        }
        
        // Log warning if memory usage is high
        if self.performance_stats.memory_usage_mb > 100.0 {
            log::warn!("High memory usage detected: {:.1} MB", self.performance_stats.memory_usage_mb);
        }
    }
    
    fn optimize_performance(&mut self) {
        // Run performance optimizations
        self.check_memory_limits();
        
        // Clear old status messages
        if let Some((_, timestamp)) = &self.state.status_message {
            let age = chrono::Utc::now().signed_duration_since(*timestamp);
            if age.num_seconds() > 10 {
                self.state.status_message = None;
            }
        }
        
        // Rebuild filtered entries if they're significantly different from main entries
        let filter_ratio = self.state.filtered_log_entries.len() as f64 / self.state.log_entries.len().max(1) as f64;
        if filter_ratio < 0.1 && self.state.log_entries.len() > 100 {
            // If we're showing less than 10% of entries and have many entries, 
            // consider if filters are too restrictive
            log::debug!("Filter showing {:.1}% of entries - consider adjusting filters", filter_ratio * 100.0);
        }
    }
    
    // Lazy loading helper methods for performance optimization
    
    fn load_jail_data(&mut self) {
        match self.fail2ban_client.get_jails() {
            Ok(jail_names) => {
                // Convert Vec<String> to HashMap<String, JailState>
                let mut jails = HashMap::new();
                for jail_name in jail_names {
                    // Get detailed jail status
                    if let Ok(jail_status) = self.fail2ban_client.get_jail_status(&jail_name) {
                        jails.insert(jail_name.clone(), jail_status);
                    } else {
                        // Create basic jail entry if detailed status fails
                        jails.insert(jail_name.clone(), JailState {
                            name: jail_name.clone(),
                            enabled: true, // assume enabled if in list
                            banned_count: 0,
                            filter: "unknown".to_string(),
                            action: "unknown".to_string(),
                        });
                    }
                }
                self.state.jails = jails;
                log::debug!("Loaded {} jails", self.state.jails.len());
            },
            Err(e) => {
                log::error!("Failed to get jail list: {}", e);
                self.set_status_message(&format!("⚠ Failed to load jails: {}", e));
            }
        }
    }
    
    /// Get the configured bantime for a specific jail
    fn get_jail_bantime(&self, jail_name: &str) -> String {
        // First check if we have the jail in available_jails (from config files)
        if let Some(jail_config) = self.state.available_jails.iter().find(|j| j.name == jail_name) {
            jail_config.ban_time.clone()
        } else {
            // Fallback: return default bantime
            "1h".to_string()
        }
    }
    
    fn format_duration(&self, duration: chrono::Duration) -> String {
        let total_seconds = duration.num_seconds();
        if total_seconds <= 0 {
            return "00s".to_string();
        }
        
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;
        
        let mut parts = Vec::new();
        
        if days > 0 {
            parts.push(format!("{}d", days));
        }
        if hours > 0 {
            parts.push(format!("{}h", hours));
        }
        if minutes > 0 {
            parts.push(format!("{}m", minutes));
        }
        
        // Always show seconds, formatted as 00s when seconds is 0 but other parts exist
        if parts.is_empty() {
            parts.push(format!("{}s", seconds));
        } else {
            parts.push(format!("{:02}s", seconds));
        }
        
        parts.join(" ")
    }
    
    
    /// Validate if the input is a valid IP address or CIDR range
    fn is_valid_ip_or_range(&self, input: &str) -> bool {
        // Check if it's a CIDR range (contains /)
        if input.contains('/') {
            let parts: Vec<&str> = input.split('/').collect();
            if parts.len() != 2 {
                return false;
            }
            
            // Validate IP part
            if !self.is_valid_ip(parts[0]) {
                return false;
            }
            
            // Validate prefix length
            if let Ok(prefix) = parts[1].parse::<u8>() {
                // For IPv4, prefix should be 0-32
                // For IPv6, prefix should be 0-128
                // We'll be permissive and allow 0-128
                prefix <= 128
            } else {
                false
            }
        } else {
            // Just a plain IP address
            self.is_valid_ip(input)
        }
    }
    
    /// Basic IP validation (IPv4 and IPv6)
    fn is_valid_ip(&self, ip: &str) -> bool {
        // Try to parse as IPv4
        if ip.parse::<std::net::Ipv4Addr>().is_ok() {
            return true;
        }
        
        // Try to parse as IPv6
        if ip.parse::<std::net::Ipv6Addr>().is_ok() {
            return true;
        }
        
        false
    }
    
    /// Load all available jails from configuration files
    fn load_available_jails(&mut self) {
        let client = Fail2banClient::new();
        match client.get_all_available_jails() {
            Ok(jails) => {
                // Update state directly instead of using recursive message handling
                self.state.available_jails = jails;
                // Reset selection if it's out of bounds
                if self.state.selected_jail_index >= self.state.available_jails.len() {
                    self.state.selected_jail_index = 0;
                    self.state.jail_scroll_offset = 0;
                }
                // Also reset dashboard jail selection if it's out of bounds
                let sorted_jails = self.get_sorted_jails_for_display();
                if self.state.dashboard_jail_selected_index >= sorted_jails.len() {
                    self.state.dashboard_jail_selected_index = 0;
                }
                // Set status message to show jails were loaded
                if self.state.available_jails.is_empty() {
                    self.set_status_message("⚠ No jail configurations found in fail2ban config files");
                } else {
                    self.set_status_message(&format!("✓ Loaded {} jail configurations", self.state.available_jails.len()));
                }
            },
            Err(e) => {
                log::error!("Failed to load available jails: {}", e);
                self.set_status_message(&format!("✗ Failed to load jails: {}", e));
            }
        }
    }
    
    
    /// Parse fail2ban error output to extract only ERROR messages, filtering out warnings
    fn extract_error_messages(error_output: &str) -> String {
        let error_lines: Vec<&str> = error_output
            .lines()
            .filter(|line| line.contains("ERROR"))
            .map(|line| {
                // Extract just the error message part after "ERROR"
                if let Some(error_part) = line.split("ERROR").nth(1) {
                    error_part.trim().trim_start_matches(':').trim()
                } else {
                    line.trim()
                }
            })
            .collect();
        
        if error_lines.is_empty() {
            // If no ERROR lines found, return a simplified version of the original
            error_output.lines()
                .filter(|line| !line.trim().is_empty() && !line.contains("WARNING"))
                .collect::<Vec<&str>>()
                .join("\n")
        } else {
            error_lines.join("\n")
        }
    }

    /// Toggle jail enabled status - PHASE 1: Show progress dialog
    fn toggle_jail_enabled(&mut self, jail_name: String) {
        if let Some(jail_config) = self.state.available_jails.iter().find(|j| j.name == jail_name) {
            let current_enabled = jail_config.enabled;
            let new_enabled = !current_enabled;
            let action = if new_enabled { "Enabling" } else { "Disabling" };
            
            // PHASE 1: Show progress dialog and defer actual work to next event cycle
            self.start_operation(OperationType::DataRefresh);
            self.update_operation_progress(30, Some(format!("⚙️ {} jail '{}'...", action, jail_name)));
            
            // Schedule the actual work for the next event cycle
            self.handle_message(AppMessage::PerformJailToggle(jail_name, new_enabled));
        } else {
            log::error!("Jail not found: {}", jail_name);
            self.state.error_dialog = Some(format!("Jail '{}' not found", jail_name));
        }
    }
    
    /// Toggle jail enabled status - PHASE 2: Perform actual operation
    fn perform_jail_toggle(&mut self, jail_name: String, new_enabled: bool) {
        self.update_operation_progress(60, Some("⚙️ Updating configuration and reloading fail2ban...".to_string()));
        
        let client = Fail2banClient::new();
        match client.set_jail_enabled(&jail_name, new_enabled) {
            Ok(()) => {
                let action_text = if new_enabled { "enabled" } else { "disabled" };
                self.complete_operation(true, Some(format!("✓ Jail '{}' {}", jail_name, action_text)));
                // Jail list will be refreshed by the automatic refresh system
            },
            Err(e) => {
                log::error!("Failed to toggle jail {}: {}", jail_name, e);
                
                // SMART AUTO-REMEDIATION: If we were enabling a jail and it caused a reload failure,
                // automatically disable it to fix the fail2ban service
                if new_enabled {
                    self.update_operation_progress(80, Some("Auto-disabling problematic jail...".to_string()));
                    log::info!("Auto-disabling problematic jail {} to fix fail2ban reload", jail_name);
                    // Attempt to disable the problematic jail
                    let client = Fail2banClient::new();
                    match client.set_jail_enabled(&jail_name, false) {
                        Ok(()) => {
                            self.complete_operation(false, Some("⚠ Jail auto-disabled due to errors".to_string()));
                            
                            let clean_error = Self::extract_error_messages(&e.to_string());
                            self.state.error_dialog = Some(format!(
                                "Jail Cannot Be Enabled\n\n\
                                The jail '{}' cannot be enabled because it causes fail2ban reload failures:\n\n\
                                {}\n\n\
                                We have automatically disabled this jail to keep fail2ban working properly.\n\n\
                                To fix this:\n\
                                • Check if the jail's log file exists\n\
                                • Verify the jail configuration is correct\n\
                                • Install the required service if missing",
                                jail_name, clean_error
                            ));
                            return;
                        },
                        Err(disable_error) => {
                            log::error!("Failed to auto-disable problematic jail: {}", disable_error);
                            // Fall through to regular error handling
                        }
                    }
                }
                
                // Regular error handling for disable operations or failed auto-disable
                self.complete_operation(false, Some("✗ Jail operation failed".to_string()));
                log::info!("Reloaded jail list from file even though toggle had error");
                
                let clean_error = Self::extract_error_messages(&e.to_string());
                self.state.error_dialog = Some(format!(
                    "Jail Toggle Error\n\n\
                    The jail '{}' operation failed:\n\n\
                    {}\n\n\
                    This may indicate:\n\
                    • Configuration issues\n\
                    • fail2ban service problems\n\
                    • File permission issues\n\n\
                    Please check the jail configuration.",
                    jail_name, clean_error
                ));
            }
        }
    }
    
    /// Open jail editor for the specified jail
    fn open_jail_editor(&mut self, jail_name: String) {
        log::info!("Opening jail editor for: {}", jail_name);
        
        // First create backup
        let backup_path = self.create_jail_backup(&jail_name);
        
        // Load current jail configuration
        match self.load_jail_configuration(&jail_name) {
            Ok(content) => {
                self.state.jail_editor = JailEditorState {
                    is_open: true,
                    jail_name: jail_name.clone(),
                    original_content: content.clone(),
                    current_content: content,
                    backup_path,
                    cursor_position: 0,
                    scroll_offset: 0,
                    modified: false,
                };
                self.state.current_screen = Screen::JailEditor;
            },
            Err(e) => {
                log::error!("Failed to load jail configuration for {}: {}", jail_name, e);
                self.state.error_dialog = Some(format!(
                    "Failed to Load Jail Configuration\n\n\
                    Unable to load configuration for jail '{}':\n\n\
                    {}\n\n\
                    This may indicate:\n\
                    • Configuration file is missing or inaccessible\n\
                    • Permission issues with /etc/fail2ban/\n\
                    • Jail is not properly configured",
                    jail_name, e
                ));
            }
        }
    }
    
    /// Close jail editor
    fn close_jail_editor(&mut self) {
        if self.state.jail_editor.modified {
            // TODO: Show confirmation dialog for unsaved changes
            log::warn!("Closing jail editor with unsaved changes");
        }
        
        self.state.jail_editor = JailEditorState::default();
        self.state.current_screen = Screen::Dashboard;
        
        // Refresh jail data to reflect any changes made in the editor
        self.load_available_jails();
        self.initialize_dashboard_states();
    }
    
    /// Save jail configuration with rollback support
    fn save_jail_configuration(&mut self) {
        if !self.state.jail_editor.is_open {
            return;
        }
        
        log::info!("Saving jail configuration for: {}", self.state.jail_editor.jail_name);
        
        // Save the configuration
        match self.write_jail_configuration(&self.state.jail_editor.jail_name, &self.state.jail_editor.current_content) {
            Ok(()) => {
                // Test fail2ban reload
                match self.test_fail2ban_reload() {
                    Ok(()) => {
                        log::info!("Jail configuration saved and fail2ban reloaded successfully");
                        self.handle_message(AppMessage::JailConfigSaved(true));
                    },
                    Err(e) => {
                        log::error!("fail2ban reload failed after configuration save: {}", e);
                        // Rollback the configuration
                        self.rollback_jail_configuration();
                        self.handle_message(AppMessage::JailConfigSaved(false));
                    }
                }
            },
            Err(e) => {
                log::error!("Failed to write jail configuration: {}", e);
                self.state.error_dialog = Some(format!(
                    "Failed to Save Configuration\n\n\
                    Unable to save configuration for jail '{}':\n\n\
                    {}\n\n\
                    This may indicate:\n\
                    • Permission denied to write /etc/fail2ban/jail.local\n\
                    • Disk space issues\n\
                    • File system errors",
                    self.state.jail_editor.jail_name, e
                ));
            }
        }
    }
    
    /// Handle jail configuration save result
    fn handle_jail_config_saved(&mut self, success: bool) {
        if success {
            self.state.jail_editor.original_content = self.state.jail_editor.current_content.clone();
            self.state.jail_editor.modified = false;
            self.set_status_message("✓ Jail configuration saved successfully");
            // Close editor after successful save
            self.close_jail_editor();
        } else {
            self.state.error_dialog = Some(format!(
                "Configuration Save Failed\n\n\
                The configuration for jail '{}' could not be saved because it caused fail2ban to fail reloading.\n\n\
                Your changes have been automatically reverted to maintain system stability.\n\n\
                Common issues:\n\
                • Invalid configuration syntax\n\
                • Missing log files or services\n\
                • Incorrect filter references\n\n\
                Please review your changes and try again.",
                self.state.jail_editor.jail_name
            ));
            
            // Reload the original content
            match self.load_jail_configuration(&self.state.jail_editor.jail_name) {
                Ok(content) => {
                    self.state.jail_editor.current_content = content.clone();
                    self.state.jail_editor.original_content = content;
                    self.state.jail_editor.modified = false;
                    self.state.jail_editor.cursor_position = 0;
                },
                Err(e) => {
                    log::error!("Failed to reload jail configuration after rollback: {}", e);
                }
            }
        }
    }
    
    /// Render jail editor screen
    fn render_jail_editor(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        if !self.state.jail_editor.is_open {
            return;
        }
        
        // Apply standard dialog clearing pattern for full-screen editor
        frame.render_widget(Clear, area);
        
        let solid_background = Paragraph::new(" ".repeat((area.width * area.height) as usize))
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(solid_background, area);
        
        // Main layout: editor area + status bar
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),      // Header
                Constraint::Min(0),         // Editor content
                Constraint::Length(3),      // Footer with shortcuts
            ])
            .split(area);
        
        // Header with jail name and status
        let title = format!(" Editing Jail: {} {}", 
            self.state.jail_editor.jail_name,
            if self.state.jail_editor.modified { "[MODIFIED]" } else { "" }
        );
        let header = Paragraph::new(title)
            .style(Style::default().fg(Color::Yellow).bg(Color::Black))
            .block(Block::default().borders(Borders::ALL).title(" Jail Configuration Editor "));
        frame.render_widget(header, chunks[0]);
        
        // Editor content area
        let editor_area = chunks[1].inner(&Margin { horizontal: 1, vertical: 1 });
        
        // Split content into lines for display and calculate cursor position
        let lines: Vec<String> = self.state.jail_editor.current_content.lines().map(|s| s.to_string()).collect();
        let visible_lines = editor_area.height as usize;
        
        // Calculate cursor line and column using helper method
        let (cursor_line, cursor_col) = self.get_jail_cursor_line_col();
        
        // Calculate scroll offset to keep cursor in view (this should be mutable)
        let scroll_offset = if cursor_line < self.state.jail_editor.scroll_offset {
            cursor_line
        } else if cursor_line >= self.state.jail_editor.scroll_offset + visible_lines {
            cursor_line.saturating_sub(visible_lines - 1)
        } else {
            self.state.jail_editor.scroll_offset
        };
        
        // Render visible lines with cursor
        let mut display_lines = Vec::new();
        let cursor_visible = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() / 500) % 2 == 0;
            
        for (i, line) in lines.iter().skip(scroll_offset).take(visible_lines).enumerate() {
            let line_num = scroll_offset + i + 1;
            let actual_line_idx = scroll_offset + i;
            
            // Check if this line contains the cursor
            if actual_line_idx == cursor_line {
                let cursor_pos = cursor_col.min(line.len());
                
                let mut line_spans = vec![
                    Span::styled(format!("{:4} │ ", line_num), Style::default().fg(Color::Gray)),
                ];
                
                // Add text before cursor
                if cursor_pos > 0 {
                    line_spans.push(Span::styled(
                        line[..cursor_pos].to_string(), 
                        Style::default().fg(Color::White)
                    ));
                }
                
                // Handle cursor rendering - either replace character at cursor or show at end
                if cursor_pos < line.len() {
                    // Cursor is on an existing character - replace it with styled version
                    let char_at_cursor = line.chars().nth(cursor_pos).unwrap_or(' ');
                    if cursor_visible {
                        line_spans.push(Span::styled(
                            "|".to_string(), 
                            Style::default().fg(Color::Blue).bg(Color::White)
                        ));
                    } else {
                        line_spans.push(Span::styled(
                            char_at_cursor.to_string(), 
                            Style::default().fg(Color::White)
                        ));
                    }
                    
                    // Add text after cursor (skip the character we just rendered)
                    if cursor_pos + 1 < line.len() {
                        line_spans.push(Span::styled(
                            line[cursor_pos + 1..].to_string(), 
                            Style::default().fg(Color::White)
                        ));
                    }
                } else {
                    // Cursor is at end of line - show pipe cursor
                    if cursor_visible {
                        line_spans.push(Span::styled(
                            "|".to_string(), 
                            Style::default().fg(Color::Blue).bg(Color::White)
                        ));
                    }
                }
                
                display_lines.push(Line::from(line_spans));
            } else {
                display_lines.push(Line::from(vec![
                    Span::styled(format!("{:4} │ ", line_num), Style::default().fg(Color::Gray)),
                    Span::styled(line.clone(), Style::default().fg(Color::White)),
                ]));
            }
        }
        
        let editor_content = Paragraph::new(display_lines)
            .style(Style::default().fg(Color::White))
            .block(Block::default().borders(Borders::ALL).title(" Configuration Content "));
        frame.render_widget(editor_content, chunks[1]);
        
        // Footer with shortcuts
        let shortcuts = Paragraph::new("Ctrl+S: Save and Close | Esc: Close | Arrow keys: Navigate")
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title(" Shortcuts "));
        frame.render_widget(shortcuts, chunks[2]);
    }
    
    /// Get cursor line and column from cursor position for jail editor
    fn get_jail_cursor_line_col(&self) -> (usize, usize) {
        let content = &self.state.jail_editor.current_content;
        let cursor_pos = self.state.jail_editor.cursor_position;
        let lines: Vec<&str> = content.lines().collect();
        
        if lines.is_empty() {
            return (0, 0);
        }
        
        let mut char_count = 0;
        for (line_idx, line) in lines.iter().enumerate() {
            let line_end = char_count + line.len();
            
            // Handle cursor at the exact position within or at end of this line
            if cursor_pos <= line_end {
                let col = cursor_pos - char_count;
                return (line_idx, col);
            }
            
            // Handle cursor at the newline character (beginning of next line)
            if cursor_pos == line_end + 1 && line_idx < lines.len() - 1 {
                return (line_idx + 1, 0);
            }
            
            char_count += line.len() + 1; // +1 for newline
        }
        
        // Cursor is beyond all content - put it at end of last line
        let last_line_idx = lines.len().saturating_sub(1);
        let last_line_len = lines.get(last_line_idx).map(|l| l.len()).unwrap_or(0);
        (last_line_idx, last_line_len)
    }
    
    /// Update scroll offset to keep cursor in view
    fn update_editor_scroll(&mut self) {
        if !self.state.jail_editor.is_open {
            return;
        }
        
        let content_before_cursor = &self.state.jail_editor.current_content[..self.state.jail_editor.cursor_position];
        let cursor_line = content_before_cursor.lines().count().saturating_sub(1);
        
        // Assume visible lines is around 20 (will be calculated properly in render)
        let visible_lines = 20;
        
        self.state.jail_editor.scroll_offset = if cursor_line < self.state.jail_editor.scroll_offset {
            cursor_line
        } else if cursor_line >= self.state.jail_editor.scroll_offset + visible_lines {
            cursor_line.saturating_sub(visible_lines - 1)
        } else {
            self.state.jail_editor.scroll_offset
        };
    }
    
    /// Move cursor up one line, maintaining column position when possible
    fn move_cursor_up(&self) -> usize {
        if !self.state.jail_editor.is_open {
            return self.state.jail_editor.cursor_position;
        }
        
        let content = &self.state.jail_editor.current_content;
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return 0;
        }
        
        // Get current position
        let (current_line, current_col) = self.get_jail_cursor_line_col();
        
        // If we're on the first line, can't move up
        if current_line == 0 {
            return self.state.jail_editor.cursor_position;
        }
        
        // Move to previous line
        let target_line_idx = current_line - 1;
        let target_line = lines[target_line_idx];
        let target_col = current_col.min(target_line.len());
        
        // Calculate new cursor position
        let mut new_pos = 0;
        for i in 0..target_line_idx {
            new_pos += lines[i].len() + 1; // +1 for newline
        }
        new_pos += target_col;
        
        new_pos.min(content.len())
    }
    
    /// Move cursor down one line, maintaining column position when possible
    fn move_cursor_down(&self) -> usize {
        if !self.state.jail_editor.is_open {
            return self.state.jail_editor.cursor_position;
        }
        
        let content = &self.state.jail_editor.current_content;
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return 0;
        }
        
        // Get current position
        let (current_line, current_col) = self.get_jail_cursor_line_col();
        
        // If we're on the last line, can't move down
        if current_line >= lines.len() - 1 {
            return self.state.jail_editor.cursor_position;
        }
        
        // Move to next line
        let target_line_idx = current_line + 1;
        let target_line = lines[target_line_idx];
        let target_col = current_col.min(target_line.len());
        
        // Calculate new cursor position
        let mut new_pos = 0;
        for i in 0..target_line_idx {
            new_pos += lines[i].len() + 1; // +1 for newline
        }
        new_pos += target_col;
        
        new_pos.min(content.len())
    }
    
    /// Move cursor left respecting line boundaries
    fn move_cursor_left(&self) -> usize {
        if !self.state.jail_editor.is_open {
            return self.state.jail_editor.cursor_position;
        }
        
        let cursor_pos = self.state.jail_editor.cursor_position;
        
        if cursor_pos == 0 {
            return 0;
        }
        
        // Check if the character to the left is a newline
        let content = &self.state.jail_editor.current_content;
        let chars: Vec<char> = content.chars().collect();
        
        // If moving left would cross a newline, don't move
        if cursor_pos > 0 && chars.get(cursor_pos - 1) == Some(&'\n') {
            return cursor_pos;
        }
        
        // Otherwise, move left one character
        cursor_pos - 1
    }
    
    /// Move cursor right respecting line boundaries  
    fn move_cursor_right(&self) -> usize {
        if !self.state.jail_editor.is_open {
            return self.state.jail_editor.cursor_position;
        }
        
        let content = &self.state.jail_editor.current_content;
        let cursor_pos = self.state.jail_editor.cursor_position;
        
        if cursor_pos >= content.len() {
            return cursor_pos;
        }
        
        // Check if the current character is a newline
        let chars: Vec<char> = content.chars().collect();
        
        // If moving right would cross a newline, don't move
        if chars.get(cursor_pos) == Some(&'\n') {
            return cursor_pos;
        }
        
        // Otherwise, move right one character
        cursor_pos + 1
    }
    
    /// Create backup of jail configuration before editing
    fn create_jail_backup(&self, jail_name: &str) -> Option<String> {
        use std::fs;
        use chrono::Utc;
        
        let jail_local_path = "/etc/fail2ban/jail.local";
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = format!("/tmp/jail_backup_{}_{}.conf", jail_name, timestamp);
        
        match fs::copy(jail_local_path, &backup_path) {
            Ok(_) => {
                log::info!("Created backup of jail.local at: {}", backup_path);
                Some(backup_path)
            },
            Err(e) => {
                log::error!("Failed to create backup of jail.local: {}", e);
                None
            }
        }
    }
    
    /// Load jail configuration content for editing
    fn load_jail_configuration(&self, jail_name: &str) -> Result<String> {
        use std::fs;
        
        // First try to load from jail.local
        let jail_local_path = "/etc/fail2ban/jail.local";
        let content = fs::read_to_string(jail_local_path)
            .map_err(|e| anyhow::anyhow!("Failed to read jail.local: {}", e))?;
        
        // Extract the specific jail section
        self.extract_jail_section(&content, jail_name)
    }
    
    /// Extract specific jail section from configuration file
    fn extract_jail_section(&self, content: &str, jail_name: &str) -> Result<String> {
        let lines: Vec<&str> = content.lines().collect();
        let section_header = format!("[{}]", jail_name);
        
        // Find the start of the jail section
        let start_idx = lines.iter().position(|&line| line.trim() == section_header)
            .ok_or_else(|| anyhow::anyhow!("Jail section '{}' not found in configuration", jail_name))?;
        
        // Find the end of the section (next section or end of file)
        let end_idx = lines.iter().skip(start_idx + 1).position(|&line| {
            line.trim().starts_with('[') && line.trim().ends_with(']')
        }).map(|i| i + start_idx + 1).unwrap_or(lines.len());
        
        // Extract the section content (skip the section header)
        let section_lines = &lines[start_idx + 1..end_idx];
        Ok(section_lines.join("\n"))
    }
    
    /// Write jail configuration back to jail.local
    fn write_jail_configuration(&self, jail_name: &str, new_content: &str) -> Result<()> {
        use std::fs;
        
        let jail_local_path = "/etc/fail2ban/jail.local";
        
        // Read the current jail.local file
        let current_content = fs::read_to_string(jail_local_path)
            .map_err(|e| anyhow::anyhow!("Failed to read jail.local: {}", e))?;
        
        // Replace the jail section with new content
        let updated_content = self.replace_jail_section(&current_content, jail_name, new_content)?;
        
        // Write back to jail.local
        fs::write(jail_local_path, updated_content)
            .map_err(|e| anyhow::anyhow!("Failed to write jail.local: {}", e))?;
        
        log::info!("Successfully updated jail configuration for: {}", jail_name);
        Ok(())
    }
    
    /// Replace jail section in configuration content
    fn replace_jail_section(&self, content: &str, jail_name: &str, new_section: &str) -> Result<String> {
        let lines: Vec<&str> = content.lines().collect();
        let section_header = format!("[{}]", jail_name);
        
        // Find the start of the jail section
        let start_idx = lines.iter().position(|&line| line.trim() == section_header)
            .ok_or_else(|| anyhow::anyhow!("Jail section '{}' not found in configuration", jail_name))?;
        
        // Find the end of the section
        let end_idx = lines.iter().skip(start_idx + 1).position(|&line| {
            line.trim().starts_with('[') && line.trim().ends_with(']')
        }).map(|i| i + start_idx + 1).unwrap_or(lines.len());
        
        // Build new content
        let mut new_lines = Vec::new();
        new_lines.extend_from_slice(&lines[..start_idx]);
        
        // Add the section header back (it was removed during extraction)
        new_lines.push(&section_header);
        
        // Add the new section content
        new_lines.extend(new_section.lines());
        
        if end_idx < lines.len() {
            new_lines.push(""); // Add empty line before next section
            new_lines.extend_from_slice(&lines[end_idx..]);
        }
        
        Ok(new_lines.join("\n"))
    }
    
    /// Test fail2ban reload to ensure configuration is valid
    fn test_fail2ban_reload(&self) -> Result<()> {
        use std::process::Command;
        
        log::info!("Testing fail2ban reload...");
        
        let output = Command::new("fail2ban-client")
            .args(&["reload"])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute fail2ban-client: {}", e))?;
        
        if output.status.success() {
            log::info!("fail2ban reload successful");
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("fail2ban reload failed: {}", error_msg))
        }
    }
    
    /// Rollback jail configuration to backup
    fn rollback_jail_configuration(&mut self) {
        if let Some(ref backup_path) = self.state.jail_editor.backup_path {
            use std::fs;
            
            let jail_local_path = "/etc/fail2ban/jail.local";
            
            match fs::copy(backup_path, jail_local_path) {
                Ok(_) => {
                    log::info!("Successfully rolled back jail configuration from backup: {}", backup_path);
                    // Try to reload fail2ban again
                    if let Err(e) = self.test_fail2ban_reload() {
                        log::error!("fail2ban reload failed even after rollback: {}", e);
                    }
                },
                Err(e) => {
                    log::error!("Failed to rollback jail configuration: {}", e);
                }
            }
        } else {
            log::error!("No backup available for rollback");
        }
    }

    /// Render error dialog for critical failures that require user attention
    fn render_error_dialog(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        if let Some(ref error_message) = self.state.error_dialog {
            // Apply standard dialog clearing pattern
            frame.render_widget(Clear, area);
            
            // Create a completely solid background using filled text to ensure no bleed-through
            let overlay = " ".repeat((area.width * area.height) as usize);
            let solid_background = Paragraph::new(overlay)
                .style(Style::default().bg(Color::Black))
                .wrap(Wrap { trim: false });
            frame.render_widget(solid_background, area);
            
            // Create a centered popup (larger than normal for error details)
            let popup_area = centered_rect(80, 60, area);
            
            // Then render the dialog border with red styling for errors
            let dialog_border = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .title(" ⚠ Critical Error ");
            frame.render_widget(dialog_border, popup_area);
            
            let inner = popup_area.inner(&Margin { horizontal: 2, vertical: 1 });
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(0),     // Error message content
                    Constraint::Length(3),  // Instructions
                ])
                .split(inner);
            
            // Error message content with proper line wrapping
            let error_text: Vec<Line> = error_message.lines()
                .map(|line| Line::from(line.to_string()))
                .collect();
            
            let error_content = Paragraph::new(error_text)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: false });
            frame.render_widget(error_content, chunks[0]);
            
            // Instructions
            let instructions = Paragraph::new("Press [Esc] to close this dialog")
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::TOP));
            frame.render_widget(instructions, chunks[1]);
        }
    }
    
    fn render_loading_modal(&self, frame: &mut Frame, area: ratatui::layout::Rect, modal: &LoadingModalState) {
        // Full-screen modal overlay using the mandatory Clear pattern
        frame.render_widget(Clear, area);
        
        // Create completely solid background to block everything
        let overlay = " ".repeat((area.width * area.height) as usize);
        let solid_background = Paragraph::new(overlay)
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(solid_background, area);
        
        // Create a large, centered popup that's impossible to miss
        let popup_area = centered_rect(70, 50, area);
        
        // Main dialog border with bright blue styling to grab attention
        let dialog_border = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan).add_modifier(ratatui::style::Modifier::BOLD))
            .title(format!(" {} {} ", modal.title, modal.animated_dots));
        frame.render_widget(dialog_border, popup_area);
        
        let inner = popup_area.inner(&Margin { horizontal: 3, vertical: 2 });
        
        // Create layout for content and progress bar
        let chunks = if modal.progress.is_some() {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(0),      // Message content
                    Constraint::Length(3),   // Progress bar
                    Constraint::Length(2),   // Elapsed time
                ])
                .split(inner)
        } else {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(0),      // Message content
                    Constraint::Length(2),   // Elapsed time
                ])
                .split(inner)
        };
        
        // Message content with emphasis styling
        let message_lines: Vec<Line> = modal.message.lines()
            .map(|line| Line::from(Span::styled(line.to_string(), Style::default().fg(Color::White))))
            .collect();
        
        let message_content = Paragraph::new(message_lines)
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false });
        frame.render_widget(message_content, chunks[0]);
        
        // Progress bar if available
        if let Some(progress) = modal.progress {
            let progress_bar = ratatui::widgets::Gauge::default()
                .block(Block::default().borders(Borders::ALL).title("Progress"))
                .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
                .percent(progress as u16)
                .label(format!("{}%", progress));
            frame.render_widget(progress_bar, chunks[1]);
            
            // Elapsed time
            let elapsed = modal.started_at.elapsed();
            let elapsed_text = format!("Elapsed: {:.1}s", elapsed.as_secs_f32());
            let elapsed_widget = Paragraph::new(elapsed_text)
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center);
            frame.render_widget(elapsed_widget, chunks[2]);
        } else {
            // Just elapsed time without progress bar
            let elapsed = modal.started_at.elapsed();
            let elapsed_text = format!("Elapsed: {:.1}s", elapsed.as_secs_f32());
            let elapsed_widget = Paragraph::new(elapsed_text)
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center);
            frame.render_widget(elapsed_widget, chunks[1]);
        }
    }
    
    // Configuration management helper methods
    fn open_config_editor(&mut self, file_path: String) {
        match std::fs::read_to_string(&file_path) {
            Ok(content) => {
                self.state.config_management.editor_open = true;
                self.state.config_management.current_file_path = file_path;
                self.state.config_management.current_file_content = content.clone();
                self.state.config_management.original_content = content;
                self.state.config_management.cursor_position = 0;
                self.state.config_management.scroll_offset = 0;
                self.state.config_management.modified = false;
                self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                self.state.config_management.cursor_visible = true;
                self.set_status_message("✓ Configuration file opened for editing");
            },
            Err(e) => {
                self.set_status_message(&format!("⚠ Failed to open file: {}", e));
                log::error!("Failed to read config file {}: {}", file_path, e);
            }
        }
    }
    
    fn close_config_editor(&mut self) {
        if self.state.config_management.modified {
            // TODO: Add confirmation dialog for unsaved changes
            self.set_status_message("⚠ Unsaved changes discarded");
        }
        self.state.config_management.editor_open = false;
        self.state.config_management.current_file_path.clear();
        self.state.config_management.current_file_content.clear();
        self.state.config_management.original_content.clear();
        self.state.config_management.cursor_position = 0;
        self.state.config_management.scroll_offset = 0;
        self.state.config_management.modified = false;
        self.state.config_management.cursor_blink_timer = std::time::Instant::now();
        self.state.config_management.cursor_visible = true;
        
        // Return to Configuration screen
        self.state.current_screen = Screen::Configuration;
    }
    
    fn save_config_file(&mut self) {
        let file_path = self.state.config_management.current_file_path.clone();
        let content = self.state.config_management.current_file_content.clone();
        
        match std::fs::write(&file_path, &content) {
            Ok(()) => {
                self.state.config_management.original_content = content;
                self.state.config_management.modified = false;
                self.set_status_message(&format!("✓ Configuration saved and reloaded: {}", file_path));
                log::info!("Configuration file saved: {}", file_path);
                
                // Reload fail2ban configuration
                self.reload_fail2ban_configuration();
                
                // Close editor and return to config page
                self.state.config_management.editor_open = false;
                self.state.config_management.current_file_path.clear();
                self.state.config_management.current_file_content.clear();
                self.state.config_management.original_content.clear();
                self.state.config_management.cursor_position = 0;
                self.state.config_management.scroll_offset = 0;
                self.state.config_management.cursor_blink_timer = std::time::Instant::now();
                self.state.config_management.cursor_visible = true;
                
                // Return to Configuration screen
                self.state.current_screen = Screen::Configuration;
            },
            Err(e) => {
                self.set_status_message(&format!("⚠ Failed to save file: {}", e));
                log::error!("Failed to save config file {}: {}", file_path, e);
            }
        }
    }
    
    fn reload_fail2ban_configuration(&mut self) {
        // Use fail2ban-client to reload the configuration
        match std::process::Command::new("sudo")
            .args(["fail2ban-client", "reload"])
            .output() {
            Ok(output) => {
                if output.status.success() {
                    log::info!("fail2ban configuration reloaded successfully");
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    log::warn!("fail2ban reload had warnings: {}", error_msg);
                }
            },
            Err(e) => {
                log::error!("Failed to reload fail2ban configuration: {}", e);
            }
        }
    }
    
    fn backup_configuration(&mut self) {
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let backup_dir = "/etc/fail2ban/backups";
        
        // Create backup directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(backup_dir) {
            self.set_status_message(&format!("⚠ Failed to create backup directory: {}", e));
            return;
        }
        
        let mut backup_count = 0;
        let files_to_backup = [
            ("/etc/fail2ban/jail.local", "jail.local"),
            ("/etc/fail2ban/jail.conf", "jail.conf"),
            ("/etc/fail2ban/fail2ban.local", "fail2ban.local"),
            ("/etc/fail2ban/fail2ban.conf", "fail2ban.conf"),
        ];
        
        for (source_path, filename) in &files_to_backup {
            if std::path::Path::new(source_path).exists() {
                let backup_path = format!("{}/{}_{}", backup_dir, filename, timestamp);
                match std::fs::copy(source_path, &backup_path) {
                    Ok(_) => {
                        backup_count += 1;
                        log::info!("Backed up {} to {}", source_path, backup_path);
                    },
                    Err(e) => {
                        log::error!("Failed to backup {} to {}: {}", source_path, backup_path, e);
                    }
                }
            }
        }
        
        if backup_count > 0 {
            self.set_status_message(&format!("✓ {} configuration files backed up to {}", backup_count, backup_dir));
        } else {
            self.set_status_message("⚠ No configuration files found to backup");
        }
    }
    
    fn restore_configuration(&mut self) {
        // TODO: Implement configuration restore from backup
        self.set_status_message("⚠ Configuration restore not yet implemented");
    }
    
    fn test_configuration(&mut self) {
        match self.test_fail2ban_reload() {
            Ok(()) => {
                self.set_status_message("✓ Configuration test passed - fail2ban reload successful");
            },
            Err(e) => {
                self.set_status_message(&format!("⚠ Configuration test failed: {}", e));
                log::error!("Configuration test failed: {}", e);
            }
        }
    }
    
    fn render_config_editor(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        if !self.state.config_management.editor_open {
            return;
        }
        
        // Apply standard dialog clearing pattern for full-screen editor
        frame.render_widget(Clear, area);
        
        let solid_background = Paragraph::new(" ".repeat((area.width * area.height) as usize))
            .style(Style::default().bg(Color::Black))
            .wrap(Wrap { trim: false });
        frame.render_widget(solid_background, area);
        
        // Main layout: editor area + status bar
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),      // Header
                Constraint::Min(0),         // Editor content
                Constraint::Length(3),      // Footer with shortcuts
            ])
            .split(area);
        
        // Header with file name and status
        let title = format!(" Editing File: {} {}", 
            self.state.config_management.current_file_path,
            if self.state.config_management.modified { "[MODIFIED]" } else { "" }
        );
        let header = Paragraph::new(title)
            .style(Style::default().fg(Color::Yellow).bg(Color::Black))
            .block(Block::default().borders(Borders::ALL).title(" Configuration File Editor "));
        frame.render_widget(header, chunks[0]);
        
        // Editor content area
        let editor_area = chunks[1].inner(&Margin { horizontal: 1, vertical: 1 });
        
        // Split content into lines for display and calculate cursor position
        let lines: Vec<String> = self.state.config_management.current_file_content.lines().map(|s| s.to_string()).collect();
        let visible_lines = editor_area.height as usize;
        
        // Calculate cursor line and column using helper method
        let (cursor_line, cursor_col) = self.get_config_cursor_line_col();
        
        // Calculate scroll offset to keep cursor in view
        let scroll_offset = if cursor_line < self.state.config_management.scroll_offset {
            cursor_line
        } else if cursor_line >= self.state.config_management.scroll_offset + visible_lines {
            cursor_line.saturating_sub(visible_lines - 1)
        } else {
            self.state.config_management.scroll_offset
        };
        
        // Render visible lines with cursor
        let mut display_lines = Vec::new();
        let cursor_visible = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() / 500) % 2 == 0;
            
        for (i, line) in lines.iter().skip(scroll_offset).take(visible_lines).enumerate() {
            let line_num = scroll_offset + i + 1;
            let actual_line_idx = scroll_offset + i;
            
            // Check if this line contains the cursor
            if actual_line_idx == cursor_line {
                let cursor_pos = cursor_col.min(line.len());
                
                let mut line_spans = vec![
                    Span::styled(format!("{:4} │ ", line_num), Style::default().fg(Color::Gray)),
                ];
                
                // Add text before cursor
                if cursor_pos > 0 {
                    line_spans.push(Span::styled(
                        line[..cursor_pos].to_string(), 
                        Style::default().fg(Color::White)
                    ));
                }
                
                // Handle cursor rendering - either replace character at cursor or show at end
                if cursor_pos < line.len() {
                    // Cursor is on an existing character - replace it with styled version
                    let char_at_cursor = line.chars().nth(cursor_pos).unwrap_or(' ');
                    if cursor_visible {
                        line_spans.push(Span::styled(
                            "|".to_string(), 
                            Style::default().fg(Color::Blue).bg(Color::White)
                        ));
                    } else {
                        line_spans.push(Span::styled(
                            char_at_cursor.to_string(), 
                            Style::default().fg(Color::White)
                        ));
                    }
                    
                    // Add text after cursor (skip the character we just rendered)
                    if cursor_pos + 1 < line.len() {
                        line_spans.push(Span::styled(
                            line[cursor_pos + 1..].to_string(), 
                            Style::default().fg(Color::White)
                        ));
                    }
                } else {
                    // Cursor is at end of line - show pipe cursor
                    if cursor_visible {
                        line_spans.push(Span::styled(
                            "|".to_string(), 
                            Style::default().fg(Color::Blue).bg(Color::White)
                        ));
                    }
                }
                
                display_lines.push(Line::from(line_spans));
            } else {
                display_lines.push(Line::from(vec![
                    Span::styled(format!("{:4} │ ", line_num), Style::default().fg(Color::Gray)),
                    Span::styled(line.clone(), Style::default().fg(Color::White)),
                ]));
            }
        }
        
        let editor_widget = Paragraph::new(display_lines)
            .block(Block::default().borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        
        frame.render_widget(editor_widget, chunks[1]);
        
        // Footer with shortcuts and cursor position
        let (cursor_line, cursor_col) = self.get_config_cursor_line_col();
        let footer_text = format!(" Line {}, Col {} | {} lines total | Ctrl+S:Save | Esc:Close ", 
            cursor_line + 1, cursor_col + 1, lines.len());
        
        let footer = Paragraph::new(footer_text)
            .style(Style::default().fg(Color::Gray).bg(Color::Black))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, chunks[2]);
    }
    
    // Configuration editor cursor movement methods
    fn move_config_cursor_left(&self) -> usize {
        if self.state.config_management.cursor_position > 0 {
            self.state.config_management.cursor_position - 1
        } else {
            0
        }
    }
    
    fn move_config_cursor_right(&self) -> usize {
        let max_pos = self.state.config_management.current_file_content.len();
        if self.state.config_management.cursor_position < max_pos {
            self.state.config_management.cursor_position + 1
        } else {
            max_pos
        }
    }
    
    fn move_config_cursor_up(&self) -> usize {
        let content = &self.state.config_management.current_file_content;
        let lines: Vec<&str> = content.lines().collect();
        let current_pos = self.state.config_management.cursor_position;
        
        // Find current line and column
        let mut pos = 0;
        for (line_idx, line) in lines.iter().enumerate() {
            let line_end = pos + line.len() + if line_idx < lines.len() - 1 { 1 } else { 0 }; // +1 for \n
            if current_pos <= line_end {
                if line_idx > 0 {
                    let col = current_pos - pos;
                    let prev_line = lines[line_idx - 1];
                    let prev_line_start = pos - prev_line.len() - 1;
                    return (prev_line_start + col.min(prev_line.len())).max(0);
                }
                break;
            }
            pos = line_end;
        }
        current_pos
    }
    
    fn move_config_cursor_down(&self) -> usize {
        let content = &self.state.config_management.current_file_content;
        let lines: Vec<&str> = content.lines().collect();
        let current_pos = self.state.config_management.cursor_position;
        
        // Find current line and column
        let mut pos = 0;
        for (line_idx, line) in lines.iter().enumerate() {
            let line_end = pos + line.len() + if line_idx < lines.len() - 1 { 1 } else { 0 }; // +1 for \n
            if current_pos <= line_end {
                if line_idx < lines.len() - 1 {
                    let col = current_pos - pos;
                    let next_line = lines[line_idx + 1];
                    let next_line_start = line_end;
                    return next_line_start + col.min(next_line.len());
                }
                break;
            }
            pos = line_end;
        }
        current_pos
    }
    
    fn update_config_editor_scroll(&mut self) {
        let content = &self.state.config_management.current_file_content;
        let lines: Vec<&str> = content.lines().collect();
        let current_pos = self.state.config_management.cursor_position;
        
        // Find current line
        let mut pos = 0;
        let mut current_line = 0;
        for (line_idx, line) in lines.iter().enumerate() {
            let line_end = pos + line.len() + if line_idx < lines.len() - 1 { 1 } else { 0 };
            if current_pos <= line_end {
                current_line = line_idx;
                break;
            }
            pos = line_end;
        }
        
        let visible_lines = 20; // Approximate visible lines
        if current_line < self.state.config_management.scroll_offset {
            self.state.config_management.scroll_offset = current_line;
        } else if current_line >= self.state.config_management.scroll_offset + visible_lines {
            self.state.config_management.scroll_offset = current_line - visible_lines + 1;
        }
    }
    
    fn get_config_cursor_line_col(&self) -> (usize, usize) {
        let content = &self.state.config_management.current_file_content;
        let cursor_pos = self.state.config_management.cursor_position;
        let lines: Vec<&str> = content.lines().collect();
        
        if lines.is_empty() {
            return (0, 0);
        }
        
        let mut char_count = 0;
        for (line_idx, line) in lines.iter().enumerate() {
            let line_end = char_count + line.len();
            
            // Handle cursor at the exact position within or at end of this line
            if cursor_pos <= line_end {
                let col = cursor_pos - char_count;
                return (line_idx, col);
            }
            
            // Handle cursor at the newline character (beginning of next line)
            if cursor_pos == line_end + 1 && line_idx < lines.len() - 1 {
                return (line_idx + 1, 0);
            }
            
            char_count += line.len() + 1; // +1 for newline
        }
        
        // Cursor is beyond all content - put it at end of last line
        let last_line_idx = lines.len().saturating_sub(1);
        let last_line_len = lines.get(last_line_idx).map(|l| l.len()).unwrap_or(0);
        (last_line_idx, last_line_len)
    }
}

/// helper function to create a centered rect using up certain percentage of the available rect `r`
fn centered_rect(percent_x: u16, percent_y: u16, r: ratatui::layout::Rect) -> ratatui::layout::Rect {
    use ratatui::layout::{Constraint, Layout, Direction};
    
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}