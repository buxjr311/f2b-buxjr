#!/bin/bash

echo "Adding random banned IPs for testing filtering functionality..."
echo

# Check if running as root/sudo
if [[ $EUID -ne 0 ]]; then
   echo "This script needs to be run with sudo to modify fail2ban"
   echo "Usage: sudo ./add_smart_test_bans.sh"
   exit 1
fi

# Get list of currently active jails
echo "Checking active jails..."
active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' ' | tr ',' '\n' | grep -v '^$')

if [[ -z "$active_jails" ]]; then
    echo "⚠ No active jails found. Starting some common jails first..."
    
    # Try to start some common jails
    for jail in sshd nginx-http postfix; do
        echo "Trying to start jail: $jail"
        fail2ban-client start "$jail" 2>/dev/null && echo "  ✓ Started $jail" || echo "  ⚠ Could not start $jail"
    done
    
    # Re-check active jails
    active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' ' | tr ',' '\n' | grep -v '^$')
fi

if [[ -z "$active_jails" ]]; then
    echo "❌ No jails are active. Please configure fail2ban first."
    exit 1
fi

echo "Active jails found:"
echo "$active_jails" | sed 's/^/  - /'
echo

# Convert to array
jails_array=($active_jails)
jail_count=${#jails_array[@]}

echo "Adding 100 random banned IPs across $jail_count active jails..."
echo

# Function to generate random IP (avoiding common private ranges)
generate_random_ip() {
    # Generate IPs that look realistic for fail2ban testing
    local first_octet=$((RANDOM % 223 + 1))
    
    # Avoid private ranges (10.x, 172.16-31.x, 192.168.x) to make it more realistic
    while [[ $first_octet -eq 10 ]] || [[ $first_octet -eq 172 ]] || [[ $first_octet -eq 192 ]]; do
        first_octet=$((RANDOM % 223 + 1))
    done
    
    echo "$first_octet.$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 254 + 1))"
}

# Add random bans
success_count=0
for i in {1..100}; do
    ip=$(generate_random_ip)
    jail=${jails_array[$((RANDOM % jail_count))]}
    
    printf "Banning IP %-15s in jail %-15s (%3d/100) " "$ip" "$jail" "$i"
    
    # Try to ban the IP
    if fail2ban-client set "$jail" banip "$ip" >/dev/null 2>&1; then
        echo "✓"
        ((success_count++))
    else
        echo "⚠ failed"
    fi
    
    # Small delay to avoid overwhelming
    sleep 0.02
done

echo
echo "✅ Finished! Successfully added $success_count banned IPs out of 100 attempts"
echo
echo "Test the filtering functionality:"
echo "  1. Run: sudo ./target/release/f2b-buxjr"
echo "  2. Press TAB to focus on banned IPs section" 
echo "  3. Use filtering keys:"
echo "     - 0: Clear all filters"
echo "     - 1: Filter by IP starting digit (1-9)"
echo "     - 2: Filter by jail (cycles through: $(echo "$active_jails" | tr '\n' ' '))"
echo "     - 3: Filter by ban age (1h → 24h → 1w → all)"
echo
echo "To clean up later: sudo fail2ban-client reload"