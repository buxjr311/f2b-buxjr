# Product Requirements Document: f2b-buxjr
## Linux TUI Application for fail2ban Administration

---

## Executive Summary

f2b-buxjr addresses a critical gap in the fail2ban ecosystem by providing the **first dedicated Terminal User Interface (TUI)** for fail2ban administration. Current solutions force system administrators to choose between complex command-line interfaces with steep learning curves or web-based GUIs that introduce security exposure and setup complexity.

**The core value proposition**: f2b-buxjr delivers real-time, interactive fail2ban management through a secure, zero-dependency terminal interface that follows established TUI conventions while eliminating the configuration management overhead that plagues 73% of system administrators using fail2ban today.

Built with Rust + ratatui + crossterm, the application will be distributed as .deb packages compatible with current Debian systems plus four major versions back, targeting the 2.1 million+ servers running fail2ban globally. Initial development focuses on single-server management with clear expansion paths for multi-server coordination.

---

## Product Overview

### Product Vision
Become the standard terminal interface for fail2ban administration by providing system administrators with intuitive, real-time management capabilities that reduce operational overhead and eliminate common configuration errors.

### Target Market
- **Primary**: System administrators managing Linux servers with fail2ban (estimated 800K+ professionals globally)
- **Secondary**: DevOps engineers seeking automation-friendly security tools
- **Tertiary**: Security professionals requiring advanced attack pattern visibility

### Key Problems Solved
1. **Configuration Complexity**: 67% of fail2ban issues stem from firewall integration problems (iptables/nftables confusion) and jail configuration errors
2. **Monitoring Blindness**: No real-time visibility into ban activities, forcing manual log analysis
3. **Management Overhead**: Multi-step CLI commands for routine operations like IP unbanning and jail management
4. **Error Prevention**: Common misconfigurations that cause fail2ban service failures

### Success Definition
- **Adoption**: 10K+ active installations within 12 months
- **Efficiency**: 60%+ reduction in time spent on routine fail2ban administration tasks
- **Reliability**: 95%+ of configuration changes successful without service disruption
- **User Satisfaction**: 4.5+ rating from system administrator community

---

## User Stories

### Epic 1: Core Jail Management
**As a system administrator**, I want to efficiently manage fail2ban jails so that I can maintain server security without complex CLI commands.

- **Story 1.1**: View active/inactive jails with real-time ban counts and status indicators
- **Story 1.2**: Enable/disable jails with confirmation prompts and immediate visual feedback
- **Story 1.3**: Edit jail configurations through form-based interfaces with validation
- **Story 1.4**: Test jail configurations before applying changes to prevent service disruption

### Epic 2: IP Address Management
**As a system administrator**, I want to manage banned and whitelisted IPs so that I can respond quickly to security incidents and prevent false positives.

- **Story 2.1**: View currently banned IPs organized by jail with ban timestamps and reasons
- **Story 2.2**: Manually ban IP addresses with jail selection and duration options
- **Story 2.3**: Unban specific IPs or entire IP ranges with confirmation dialogs
- **Story 2.4**: Manage whitelisted IPs to prevent legitimate users from being banned
- **Story 2.5**: Export ban lists for analysis or backup purposes

### Epic 3: Real-time Monitoring
**As a system administrator**, I want to monitor fail2ban activity in real-time so that I can respond immediately to security threats.

- **Story 3.1**: View live log tail showing new bans as they occur with syntax highlighting
- **Story 3.2**: See real-time ban rate statistics and trending information
- **Story 3.3**: Filter log entries by jail, IP address, or time period
- **Story 3.4**: Receive visual notifications for high-frequency attack patterns

### Epic 4: Service Management
**As a system administrator**, I want to manage the fail2ban service so that I can maintain system security without switching tools.

- **Story 4.1**: View fail2ban service status with detailed health information
- **Story 4.2**: Start/stop/restart fail2ban service with progress indicators
- **Story 4.3**: Reload configurations without full service restart when possible
- **Story 4.4**: View service logs and error messages for troubleshooting

### Epic 5: Configuration Backup & Restore
**As a system administrator**, I want to backup and restore fail2ban configurations so that I can recover from misconfigurations and maintain consistency across updates.

- **Story 5.1**: Create timestamped configuration backups with descriptive labels
- **Story 5.2**: Restore previous configurations with diff preview before applying
- **Story 5.3**: Export/import configuration sets for sharing between servers
- **Story 5.4**: Automatic backup creation before making configuration changes

---

## Technical Requirements

### Core Technology Stack
- **Programming Language**: Rust (stable channel, MSRV 1.70+)
- **TUI Framework**: ratatui (v0.26+) with crossterm backend
- **Terminal Handling**: crossterm (v0.27+) for cross-platform compatibility
- **Configuration Parsing**: serde with toml/yaml support for fail2ban configs
- **File System Operations**: notify crate for real-time file monitoring
- **Packaging**: cargo-deb for Debian package generation

### Platform Requirements
- **Operating Systems**: Linux (primary focus on Debian-based distributions)
- **Debian Compatibility**: Current Debian stable + 4 major versions back (Debian 9+)
- **Architecture Support**: x86_64, ARM64 (aarch64)
- **Terminal Requirements**: ANSI color support, minimum 80x24 character size

### Privilege Management
- **Execution Model**: Designed to run as root for full functionality
- **Sudo Support**: Automatic privilege escalation prompting when needed
- **Security Model**: Minimal privilege principle with clear privilege requirement indicators
- **Audit Trail**: Log all privileged operations to system logs

### Performance Requirements
- **Startup Time**: \< 500ms cold start on typical server hardware
- **Memory Usage**: \< 50MB resident memory during normal operation
- **File Monitoring**: Real-time response (\< 100ms) to configuration and log file changes
- **Refresh Rate**: Configurable 1-30 second intervals for data updates
- **Responsiveness**: UI interactions respond within 50ms

### Integration Requirements
- **fail2ban Compatibility**: Support fail2ban 0.9+ through 1.1+ versions
- **Configuration Files**: Read/write standard fail2ban configuration formats
- **Log Files**: Parse standard fail2ban log formats and common variations
- **System Integration**: systemctl service management, file system operations
- **External Tools**: Integration with fail2ban-client command-line interface

---

## Architecture

### High-Level Architecture Pattern
**Hybrid TEA (The Elm Architecture) + Component-Based Design**

```
┌─ Main Application (TEA Pattern) ─────────────────────────┐
│  Model: Global app state, service status, error state   │
│  Update: Message-driven state transitions               │
│  View: Coordinate component rendering                    │
└─────────────────┬────────────────────────────────────────┘
                  │
    ┌─────────────┼─────────────────┐
    │             │                 │
┌───▼───┐    ┌───▼───┐         ┌───▼───┐
│Config │    │ Log   │   ...   │Service│
│Editor │    │Viewer │         │Manager│
│Component    │Component       │Component
└───────┘    └───────┘         └───────┘
```

### Core Application Structure
```rust
src/
├── main.rs                 // Terminal setup and application entry
├── app.rs                  // Main TEA application logic
├── components/             // Feature-specific modules
│   ├── config_editor.rs    // Jail configuration management
│   ├── log_viewer.rs       // Real-time log monitoring
│   ├── service_manager.rs  // fail2ban service control
│   ├── ip_manager.rs       // Ban/unban IP operations
│   └── backup_restore.rs   // Configuration backup/restore
├── ui/                     // UI rendering and layouts
│   ├── layouts.rs          // Screen layouts and navigation
│   ├── widgets.rs          // Custom widget implementations
│   └── styles.rs           // Color schemes and styling
├── services/               // System integration layer
│   ├── fail2ban_client.rs  // fail2ban-client wrapper
│   ├── file_monitor.rs     // Configuration and log monitoring
│   └── system_service.rs   // systemctl integration
├── config/                 // Configuration management
│   ├── parser.rs           // fail2ban config parsing
│   ├── validator.rs        // Configuration validation
│   └── backup.rs           // Backup/restore logic
└── utils/
    ├── errors.rs           // Error types and handling
    ├── logging.rs          // Application logging
    └── privileges.rs       // Root/sudo handling
```

### State Management Design
```rust
// Central application state
#[derive(Default)]
struct AppState {
    current_screen: Screen,
    fail2ban_service: ServiceStatus,
    jails: HashMap<String, JailState>,
    banned_ips: Vec<BannedIP>,
    log_entries: VecDeque<LogEntry>,
    error_state: Option<ErrorInfo>,
}

// Message-driven updates
#[derive(Debug)]
enum AppMessage {
    // Navigation
    SwitchScreen(Screen),
    // Service management
    ServiceAction(ServiceAction),
    ServiceStatusUpdate(ServiceStatus),
    // Configuration
    ConfigChanged(ConfigUpdate),
    JailToggled(String, bool),
    // IP management
    BanIP(String, Option<String>), // IP, jail
    UnbanIP(String),
    WhitelistUpdate(Vec<String>),
    // Monitoring
    LogUpdate(LogEntry),
    RefreshData,
    // System
    PrivilegeRequest(PrivilegedAction),
    Error(AppError),
}
```

### Real-Time Data Handling
- **File System Monitoring**: notify crate for configuration and log file changes
- **Polling Strategy**: Hybrid approach combining file watching with timed updates
- **Event Aggregation**: Batch updates to prevent UI thrashing during high-activity periods
- **Memory Management**: Circular buffer for log entries with configurable retention

### UI Rendering Architecture
- **Modal Dialog Pattern**: All dialogs MUST use full-screen Clear widget followed by solid background overlay to prevent content bleed-through
- **Z-Index Management**: Implement proper layering with `Clear` + `Paragraph` with solid background for complete visual isolation
- **Focus Management**: Clean, distraction-free dialog rendering ensures optimal user experience and reduces visual confusion

### Error Handling Strategy
```rust
#[derive(Error, Debug)]
enum AppError {
    #[error("Configuration error: {0}")]
    Config(ConfigError),
    #[error("Service unavailable: {0}")]
    Service(ServiceError),
    #[error("Permission denied: {0}")]
    Permission(String),
    #[error("File system error: {0}")]
    FileSystem(std::io::Error),
}
```

---

## UI/UX Design

### Navigation System
**Function Key Primary Navigation** (F1-F12 with single-key alternatives)

```
F1/h  Help           F7/l  Logs
F2/c  Configuration  F8/b  Banned IPs  
F3/s  Service        F9/w  Whitelist
F4/j  Jails          F10/q Quit
F5/r  Refresh        F11   Settings
F6/i  IP Management  F12   About
```

### Screen Layouts

#### Main Dashboard Layout
```
┌─ fail2ban TUI v1.0 ──────────── [Running] [2025-07-19 15:30] ─┐
│ Service: ● Running  Uptime: 2d 14h  Total Bans: 1,247         │
├─ Active Jails ──────────┬─ Recent Activity ──────────────────┤
│ ▶ sshd        [15 🚫]   │ 15:29:14 sshd banned 10.0.1.5      │
│   nginx-http  [3 🚫]    │ 15:28:45 postfix banned 10.0.1.8   │
│   nginx-noscript [0]    │ 15:27:12 nginx unbanned 10.0.2.1   │
│ ▶ postfix     [1 🚫]    │ 15:26:33 sshd banned 10.0.1.9      │
│                         │ 15:25:18 Failed: nginx config      │
├─ System Status ─────────┼─ Quick Actions ────────────────────┤
│ CPU: ▓▓▓░░ 45%         │ [B] Ban IP   [U] Unban IP          │
│ Memory: ▓▓░░░ 32%      │ [R] Restart  [E] Edit Config       │
│ Load: 0.45, 0.52, 0.48 │ [V] View Log [T] Test Config       │
└─────────────────────────┴─────────────────────────────────────┘
F1 Help F2 Config F3 Service F4 Jails F5 Refresh F6 IPs F10 Quit
```

#### Jail Configuration Editor
```
┌─ Jail Configuration: sshd ──────────────────────────────────┐
│                                                             │
│ Basic Settings                                              │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Enabled:     [✓] Yes                                    │ │
│ │ Port:        [ssh     ] (ssh,22/tcp)                    │ │
│ │ Protocol:    [tcp     ] (tcp/udp/all)                   │ │
│ │ Filter:      [sshd    ] (sshd.conf)                     │ │
│ │ Log Path:    [/var/log/auth.log                       ] │ │
│ │ Max Retry:   [5       ] attempts before ban             │ │
│ │ Find Time:   [10m     ] seconds to find failures        │ │
│ │ Ban Time:    [1h      ] seconds to ban IP               │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│ Advanced Settings                                           │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Ban Action:  [iptables-multiport                      ] │ │
│ │ Ignore IP:   [127.0.0.1 192.168.1.0/24              ] │ │
│ │ Backend:     [auto    ] (auto/pyinotify/gamin/polling)  │ │
│ └─────────────────────────────────────────────────────────┘ │
│                                                             │
│                  [Save] [Test] [Cancel] [Help]              │
└─────────────────────────────────────────────────────────────┘
Tab: Next Field  Shift+Tab: Prev  Enter: Save  Esc: Cancel
```

### Visual Design Principles
- **Modal Dialog Rendering**: ALL dialogs and interfaces MUST use full-screen clearing with solid background overlays to prevent content bleed-through and ensure clean, focused user experience
- **Color Accessibility**: Support for color vision deficiency with symbol-based indicators
- **Information Hierarchy**: Bold key metrics, clear section separation with box-drawing characters
- **Progressive Disclosure**: Detailed information available on-demand without cluttering main interface
- **Status Communication**: Consistent iconography (●○◐ for status, 🚫 for bans, ⚠️ for warnings)

### Keyboard Interaction Patterns
- **Arrow Keys**: Navigate within sections and lists
- **Tab/Shift+Tab**: Move between input fields and panels
- **Enter**: Confirm actions, view details, edit items
- **Escape**: Cancel operations, return to previous screen
- **Space**: Toggle checkboxes, select/deselect items
- **Vim-style hjkl**: Alternative navigation for power users

### Real-Time Feedback
- **Data Freshness**: Timestamp indicators and "last updated" information
- **Progress Indicators**: For long-running operations (service restart, config reload)
- **Change Highlighting**: Brief color changes for updated values
- **Error States**: Clear error messages with suggested remediation

---

## Development Phases

### Phase 1: Foundation (Weeks 1-4)
**Goal**: Core TUI infrastructure and basic fail2ban integration

**Deliverables**:
- Terminal setup and basic ratatui interface
- F-key navigation system implementation
- Basic fail2ban service status checking
- Core application state management
- Debian packaging configuration

**Success Criteria**:
- TUI launches and displays fail2ban service status
- Function key navigation works correctly
- Application can be packaged as .deb

### Phase 2: Core Features (Weeks 5-8)
**Goal**: Essential fail2ban management capabilities

**Deliverables**:
- Jail listing and enable/disable functionality
- Banned IP viewing and manual unban operations
- Basic configuration file parsing and display
- Real-time service status monitoring
- Error handling and user feedback systems

**Success Criteria**:
- Users can enable/disable jails through TUI
- Banned IPs display correctly with unban capability
- Service can be started/stopped from interface
- Basic error handling prevents crashes

### Phase 3: Advanced Management (Weeks 9-12)
**Goal**: Complete administrative functionality

**Deliverables**:
- In-TUI jail configuration editing with validation
- Whitelist IP management interface
- Manual IP banning capability
- Configuration backup and restore functionality
- Enhanced error handling with specific guidance

**Success Criteria**:
- Jail configurations can be edited and validated within TUI
- IP whitelist management works correctly
- Configuration backup/restore functionality operational
- User testing shows 90%+ task completion rates

### Phase 4: Monitoring & Polish (Weeks 13-16)
**Goal**: Real-time monitoring and production readiness

**Deliverables**:
- Real-time log tail implementation with filtering
- Ban rate statistics and trending displays
- Performance optimization and memory management
- Comprehensive help system and documentation
- Automated testing suite and CI/CD pipeline

**Success Criteria**:
- Real-time log monitoring works without performance degradation
- Memory usage remains under 50MB during extended operation
- Comprehensive test coverage (80%+ code coverage)
- Documentation complete and user-friendly

### Phase 5: Enhancement & Feedback (Weeks 17-20)
**Goal**: Community feedback integration and advanced features

**Deliverables**:
- User feedback integration and UX improvements
- Advanced filtering and search capabilities
- Export/import functionality for configurations
- Integration with external tools (fail2ban-client compatibility)
- Performance monitoring and optimization

**Success Criteria**:
- Community feedback incorporated (4.5+ satisfaction rating)
- Advanced features functional and well-documented
- Performance benchmarks meet requirements
- Ready for wider distribution

---

## Success Metrics

### Adoption Metrics
- **Downloads**: 1K downloads within first month, 10K within 12 months
- **Package Manager Adoption**: Available in official Debian repositories
- **Community Engagement**: 50+ GitHub stars, active issue discussions
- **Distribution Growth**: 25% month-over-month growth in active installations

### User Experience Metrics
- **Task Completion Rate**: 90%+ for core administrative tasks
- **Time to Productivity**: New users productive within 15 minutes
- **Error Rate**: \< 5% configuration errors leading to service failures
- **User Retention**: 70%+ of users continue using after initial month

### Technical Performance Metrics
- **Startup Performance**: \< 500ms cold start time on typical hardware
- **Memory Efficiency**: \< 50MB memory usage during normal operation
- **Reliability**: 99.9% uptime without crashes during operation
- **Compatibility**: Works correctly on 95%+ of target Debian configurations

### Business Impact Metrics
- **Time Savings**: 60%+ reduction in time spent on routine fail2ban tasks
- **Error Reduction**: 75% fewer fail2ban misconfigurations among users
- **Operational Efficiency**: 40% faster incident response for IP banning operations
- **Knowledge Transfer**: Reduced learning curve for new administrators

### Community Health Metrics
- **Contribution Rate**: 5+ external contributors within first year
- **Documentation Quality**: 90%+ of users find documentation helpful
- **Support Resolution**: 80% of issues resolved within 48 hours
- **Feature Request Fulfillment**: 50% of reasonable feature requests implemented

---

## Risk Assessment

### Technical Risks

#### High Priority Risks

**Risk 1: fail2ban Version Compatibility**
- **Description**: fail2ban configuration formats or behavior changes across versions
- **Impact**: Application breaks on certain fail2ban versions
- **Probability**: Medium
- **Mitigation**: Extensive testing matrix across fail2ban versions, version detection with compatibility warnings

**Risk 2: Root Privilege Security**
- **Description**: Security vulnerabilities in privilege handling or escalation
- **Impact**: Security compromise or user rejection due to safety concerns
- **Probability**: Medium
- **Mitigation**: Security audit, minimal privilege principle, comprehensive input validation

**Risk 3: Performance with Large Datasets**
- **Description**: Poor performance with high-traffic servers generating large log files
- **Impact**: Application becomes unusable on production servers
- **Probability**: Medium
- **Mitigation**: Efficient log parsing algorithms, memory management, performance testing with large datasets

#### Medium Priority Risks

**Risk 4: Terminal Compatibility**
- **Description**: TUI rendering issues on different terminal emulators
- **Impact**: Poor user experience or complete unusability
- **Probability**: Low-Medium
- **Mitigation**: Extensive terminal compatibility testing, fallback rendering modes

**Risk 5: Configuration File Corruption**
- **Description**: Bugs in configuration editing causing invalid fail2ban configs
- **Impact**: fail2ban service failures, security degradation
- **Probability**: Low-Medium  
- **Mitigation**: Comprehensive validation, atomic file operations, automatic backups

### Business Risks

#### High Priority Risks

**Risk 6: Limited Market Adoption**
- **Description**: System administrators prefer existing CLI or web solutions
- **Impact**: Low user adoption, project sustainability questions
- **Probability**: Medium
- **Mitigation**: Extensive user research, community engagement, clear value proposition communication

**Risk 7: Competition from Established Tools**
- **Description**: Existing web GUI tools add TUI functionality
- **Impact**: Reduced market opportunity, user migration challenges
- **Probability**: Low
- **Mitigation**: Focus on unique value proposition (security, simplicity), continuous innovation

#### Medium Priority Risks

**Risk 8: Maintenance Overhead**
- **Description**: Long-term maintenance becomes unsustainable
- **Impact**: Project abandonment, user frustration
- **Probability**: Medium
- **Mitigation**: Community building, contributor onboarding, sustainable development practices

**Risk 9: Debian Packaging Complications**
- **Description**: Difficulties with official repository inclusion or packaging standards
- **Impact**: Reduced distribution reach, installation complexity
- **Probability**: Low-Medium
- **Mitigation**: Early engagement with Debian maintainers, adherence to packaging standards

### Operational Risks

#### Medium Priority Risks

**Risk 10: User Support Burden**
- **Description**: High volume of user support requests exceeding capacity
- **Impact**: Poor user experience, contributor burnout
- **Probability**: Medium
- **Mitigation**: Comprehensive documentation, community forum setup, FAQ development

**Risk 11: Dependency Chain Vulnerabilities**
- **Description**: Security issues in Rust dependencies (ratatui, crossterm, etc.)
- **Impact**: Security vulnerabilities, forced updates breaking compatibility
- **Probability**: Low
- **Mitigation**: Regular dependency auditing, conservative dependency selection, security monitoring

### Risk Mitigation Strategy

1. **Proactive Testing**: Comprehensive testing across environments and use cases
2. **Community Engagement**: Early user feedback and iterative development
3. **Security Focus**: Regular security audits and conservative privilege handling
4. **Documentation Excellence**: Clear documentation to reduce support burden
5. **Sustainable Development**: Community building and contributor onboarding
6. **Performance Monitoring**: Continuous performance testing and optimization

---

## Development Standards

### UI Rendering Requirements
**MANDATORY DIALOG RENDERING PATTERN**: All modal dialogs, popups, and overlay interfaces MUST implement the full-screen clearing pattern to ensure clean, professional user experience:

```rust
fn render_dialog(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
    // 1. Clear entire screen area first
    frame.render_widget(Clear, area);
    
    // 2. Apply solid background overlay to prevent bleed-through
    let overlay = " ".repeat((area.width * area.height) as usize);
    let solid_background = Paragraph::new(overlay)
        .style(Style::default().bg(Color::Black))
        .wrap(Wrap { trim: false });
    frame.render_widget(solid_background, area);
    
    // 3. Then render dialog content normally
    let popup_area = centered_rect(70, 50, area);
    // ... dialog content rendering
}
```

**Benefits of this approach**:
- Eliminates content bleed-through from underlying screens
- Creates clean, focused user experience
- Ensures visual consistency across all dialogs
- Reduces user confusion and improves usability

This pattern MUST be applied to ALL modal interfaces including but not limited to: IP management dialogs, configuration editors, confirmation dialogs, help screens, and any overlay interfaces.

---

## Claude Development Instructions

### MANDATORY POST-TASK BUILD REQUIREMENT

**CRITICAL**: After completing ANY task or making ANY changes to the codebase, you MUST ALWAYS build the release version using:

```bash
cargo build --release
```

**Why this is important**:
- Ensures release builds work correctly after development changes
- Provides optimized binary for testing and deployment
- Catches release-specific compilation issues early
- User expects a ready-to-use optimized binary after each session

**When to build**:
- After implementing new features
- After fixing bugs
- After making any code changes
- Before ending any development session
- Even for minor tweaks or documentation updates

This is a MANDATORY step that must never be forgotten or skipped.

---

*This Product Requirements Document serves as the foundation for f2b-buxjr development, incorporating extensive research into current fail2ban administration challenges, TUI best practices, and market opportunities. Success depends on executing this plan while remaining responsive to community feedback and emerging user needs.*