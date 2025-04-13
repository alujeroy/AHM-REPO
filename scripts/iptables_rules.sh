#!/bin/bash
# Flush existing rules
iptables -F
iptables -X

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from whitelist (replace with your IP)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow honeypot ports
for port in 22 80 443 3306 8080; do
    iptables -A INPUT -p tcp --dport $port -j ACCEPT
done

# Log all other incoming traffic
iptables -A INPUT -j LOG --log-prefix "HONEYPOT-DROPPED: " --log-level 4

# Save rules
iptables-save > /etc/iptables/rules.v4
