#!/bin/bash

echo "Adding 100 random banned IPs for testing filtering functionality..."

# Common jails to use
jails=("sshd" "nginx-http" "postfix" "dovecot" "nginx-noscript")

# Function to generate random IP
generate_random_ip() {
    echo "$((RANDOM % 223 + 1)).$((RANDOM % 255)).$((RANDOM % 255)).$((RANDOM % 254 + 1))"
}

# Function to get random jail
get_random_jail() {
    echo "${jails[$((RANDOM % ${#jails[@]}))]}"
}

# Add 100 random bans
for i in {1..100}; do
    ip=$(generate_random_ip)
    jail=$(get_random_jail)
    
    echo "Banning IP $ip in jail $jail ($i/100)"
    
    # Try to ban the IP
    if ! fail2ban-client set "$jail" banip "$ip" 2>/dev/null; then
        echo "  ⚠ Failed to ban $ip in jail $jail (jail might not exist or be enabled)"
    fi
    
    # Small delay to avoid overwhelming
    sleep 0.05
done

echo
echo "✓ Finished adding test banned IPs!"
echo "Now you can test the filtering functionality:"
echo "  - Run: sudo ./target/release/f2b-buxjr"
echo "  - Focus on banned IPs section with TAB"
echo "  - Use keys 0,1,2,3 to test different filters"
echo
echo "To remove test bans later, run: sudo fail2ban-client reload"