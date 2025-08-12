#!/bin/bash

# test_banned_ips.sh - Generate random banned IPs for testing f2b-buxjr performance
# Usage: ./test_banned_ips.sh <number_of_ips> [cleanup]
#
# Examples:
#   ./test_banned_ips.sh 1000        # Add 1000 random public IPs to fail2ban
#   ./test_banned_ips.sh 5000        # Add 5000 random public IPs to fail2ban
#   ./test_banned_ips.sh 0 cleanup   # Remove ALL currently banned IPs (use with caution!)

# Note: Removed 'set -e' to handle errors gracefully

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BANTIME_SECONDS=3600      # 1 hour ban time for test IPs

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if fail2ban is running
check_fail2ban_status() {
    if ! systemctl is-active --quiet fail2ban; then
        print_error "fail2ban service is not running!"
        print_status "Please start fail2ban: sudo systemctl start fail2ban"
        exit 1
    fi
    print_success "fail2ban service is running"
}

# Function to get enabled jails
get_enabled_jails() {
    # Get all jails and check which ones are enabled (no colored output here)
    local jails
    jails=$(fail2ban-client status | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | sed 's/^\s*//;s/\s*$//')
    
    local enabled_jails=()
    while IFS= read -r jail; do
        if [[ -n "$jail" ]]; then
            # Check if jail is actually enabled by trying to get its status
            if fail2ban-client status "$jail" >/dev/null 2>&1; then
                enabled_jails+=("$jail")
            fi
        fi
    done <<< "$jails"
    
    if [[ ${#enabled_jails[@]} -eq 0 ]]; then
        return 1
    fi
    
    # Only output the jail names, no colored status messages
    printf '%s\n' "${enabled_jails[@]}"
}

# Function to generate truly random public IP addresses
generate_random_test_ip() {
    local ip
    local attempts=0
    local max_attempts=50
    
    while [[ $attempts -lt $max_attempts ]]; do
        # Generate completely random IP
        local octet1=$((RANDOM % 254 + 1))   # 1-254 (avoid 0 and 255)
        local octet2=$((RANDOM % 256))       # 0-255
        local octet3=$((RANDOM % 256))       # 0-255  
        local octet4=$((RANDOM % 254 + 1))   # 1-254 (avoid 0 and 255)
        
        ip="${octet1}.${octet2}.${octet3}.${octet4}"
        
        # Skip reserved/private IP ranges
        if is_valid_public_ip "$ip"; then
            echo "$ip"
            return 0
        fi
        
        ((attempts++))
    done
    
    # Fallback to a known good range if we can't generate a valid IP
    echo "203.0.113.$((RANDOM % 254 + 1))"  # TEST-NET-3 (RFC 5737)
}

# Function to check if IP is a valid public IP (not reserved/private)
is_valid_public_ip() {
    local ip="$1"
    local octets
    IFS='.' read -ra octets <<< "$ip"
    
    local o1="${octets[0]}"
    local o2="${octets[1]}"
    local o3="${octets[2]}"
    local o4="${octets[3]}"
    
    # Skip invalid ranges
    # 0.x.x.x - Current network
    [[ $o1 -eq 0 ]] && return 1
    
    # 10.x.x.x - Private
    [[ $o1 -eq 10 ]] && return 1
    
    # 127.x.x.x - Loopback
    [[ $o1 -eq 127 ]] && return 1
    
    # 169.254.x.x - Link-local
    [[ $o1 -eq 169 && $o2 -eq 254 ]] && return 1
    
    # 172.16-31.x.x - Private
    [[ $o1 -eq 172 && $o2 -ge 16 && $o2 -le 31 ]] && return 1
    
    # 192.168.x.x - Private
    [[ $o1 -eq 192 && $o2 -eq 168 ]] && return 1
    
    # 224-255.x.x.x - Multicast and reserved
    [[ $o1 -ge 224 ]] && return 1
    
    # Valid public IP
    return 0
}

# Function to check if IP is already banned in a jail
is_ip_banned() {
    local jail="$1"
    local ip="$2"
    fail2ban-client get "$jail" banip 2>/dev/null | grep -q "^$ip$" 2>/dev/null
}

# Function to ban an IP in a specific jail
ban_ip_in_jail() {
    local jail="$1"
    local ip="$2"
    
    # Try to ban the IP - fail2ban-client set doesn't support custom bantime for banip
    local result
    result=$(fail2ban-client set "$jail" banip "$ip" 2>&1)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        return 0
    else
        # Debug: print the error if it's not a simple "already banned" case
        if [[ ! "$result" =~ "already banned" ]]; then
            print_warning "Failed to ban $ip in $jail: $result"
        fi
        return 1
    fi
}

# Function to add test banned IPs
add_test_banned_ips() {
    local num_ips="$1"
    local enabled_jails=()
    
    print_status "Getting list of enabled jails..."
    
    # Read enabled jails into array
    while IFS= read -r jail; do
        enabled_jails+=("$jail")
        print_status "  ✓ Found enabled jail: $jail"
    done < <(get_enabled_jails)
    
    if [[ ${#enabled_jails[@]} -eq 0 ]]; then
        print_error "No enabled jails found!"
        print_status "Please check your fail2ban configuration"
        exit 1
    fi
    
    print_success "Found ${#enabled_jails[@]} enabled jail(s)"
    print_status "Adding $num_ips random banned IPs across ${#enabled_jails[@]} enabled jail(s)..."
    
    local added_count=0
    local attempt=0
    local max_attempts=$((num_ips * 3))  # Allow some retries for duplicates
    
    while [[ $added_count -lt $num_ips && $attempt -lt $max_attempts ]]; do
        # Select random jail
        local jail_index=$((RANDOM % ${#enabled_jails[@]}))
        local selected_jail="${enabled_jails[$jail_index]}"
        
        # Generate random IP
        local test_ip
        test_ip=$(generate_random_test_ip)
        
        ((attempt++))
        
        # Check if IP is already banned
        if is_ip_banned "$selected_jail" "$test_ip"; then
            continue  # Skip already banned IPs
        fi
        
        # Try to ban the IP
        if ban_ip_in_jail "$selected_jail" "$test_ip"; then
            ((added_count++))
            if [[ $((added_count % 100)) -eq 0 ]] || [[ $added_count -le 10 ]] || [[ $((added_count % 500)) -eq 0 ]]; then
                print_status "  [$added_count/$num_ips] Banned $test_ip in jail '$selected_jail'"
            fi
        else
            # Continue trying with other IPs
            continue
        fi
        
        # Show progress for every 10% on large operations
        if [[ $num_ips -gt 100 && $((added_count * 10 / num_ips)) -gt $(((added_count - 1) * 10 / num_ips)) ]]; then
            print_status "  Progress: $((added_count * 100 / num_ips))% complete ($added_count/$num_ips)"
        fi
    done
    
    print_success "Successfully added $added_count test banned IPs"
    
    # Show summary
    print_status "Summary of total banned IPs per jail:"
    for jail in "${enabled_jails[@]}"; do
        local count
        count=$(fail2ban-client get "$jail" banip | wc -l 2>/dev/null || echo "0")
        print_status "  $jail: $count total IPs"
    done
}

# Function to cleanup test IPs (removes ALL banned IPs - use with caution!)
cleanup_test_ips() {
    print_status "Cleaning up ALL banned IPs from all jails..."
    print_warning "WARNING: This will remove ALL currently banned IPs, not just test IPs!"
    read -p "Are you sure you want to continue? This cannot be undone! (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Cleanup aborted by user"
        exit 0
    fi
    
    local enabled_jails=()
    while IFS= read -r jail; do
        enabled_jails+=("$jail")
    done < <(get_enabled_jails)
    
    if [[ ${#enabled_jails[@]} -eq 0 ]]; then
        print_error "No enabled jails found!"
        exit 1
    fi
    
    local total_removed=0
    
    for jail in "${enabled_jails[@]}"; do
        print_status "Cleaning jail '$jail'..."
        local removed_count=0
        
        # Get all banned IPs for this jail
        local banned_ips
        banned_ips=$(fail2ban-client get "$jail" banip 2>/dev/null || echo "")
        
        while IFS= read -r ip; do
            if [[ -n "$ip" ]]; then
                if fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
                    ((removed_count++))
                    ((total_removed++))
                    print_status "    Unbanned: $ip"
                fi
            fi
        done <<< "$banned_ips"
        
        if [[ $removed_count -gt 0 ]]; then
            print_success "  Removed $removed_count IPs from jail '$jail'"
        else
            print_status "  No banned IPs found in jail '$jail'"
        fi
    done
    
    print_success "Cleanup complete! Removed $total_removed banned IPs total"
}

# Main script logic
main() {
    print_status "f2b-buxjr Test Banned IP Generator"
    print_status "=================================="
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (or with sudo)"
        print_status "Usage: sudo $0 <number_of_ips> [cleanup]"
        exit 1
    fi
    
    # Check arguments
    if [[ $# -eq 0 ]]; then
        print_error "Missing argument!"
        echo ""
        echo "Usage: $0 <number_of_ips> [cleanup]"
        echo ""
        echo "Examples:"
        echo "  $0 1000        # Add 1000 random public IPs to fail2ban"
        echo "  $0 5000        # Add 5000 random public IPs to fail2ban" 
        echo "  $0 0 cleanup   # Remove ALL currently banned IPs (use with caution!)"
        echo ""
        echo "IPs are randomly generated from valid public IP ranges"
        exit 1
    fi
    
    local num_ips="$1"
    local cleanup_mode="${2:-}"
    
    # Validate number
    if ! [[ "$num_ips" =~ ^[0-9]+$ ]]; then
        print_error "Number of IPs must be a positive integer"
        exit 1
    fi
    
    # Check fail2ban status
    check_fail2ban_status
    
    # Cleanup mode
    if [[ "$cleanup_mode" == "cleanup" ]]; then
        cleanup_test_ips
        exit 0
    fi
    
    # Validate reasonable limits
    if [[ $num_ips -gt 50000 ]]; then
        print_warning "Requesting $num_ips IPs - this might take a while and impact system performance"
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Aborted by user"
            exit 0
        fi
    fi
    
    if [[ $num_ips -eq 0 ]]; then
        print_status "Zero IPs requested - nothing to do"
        exit 0
    fi
    
    # Add test IPs
    local start_time=$(date +%s)
    add_test_banned_ips "$num_ips"
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    print_success "Operation completed in ${duration} seconds"
    print_status "You can now test f2b-buxjr with the generated banned IPs"
    print_status "To cleanup all banned IPs: $0 0 cleanup"
}

# Run main function
main "$@"