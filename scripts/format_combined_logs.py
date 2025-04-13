import json
import csv
import os
from datetime import datetime

# File paths
cowrie_log = "/opt/honeypot/COWRIE/cowrie/var/log/cowrie.json"
simple_log = "/opt/honeypot/logs/commands.log"
combined_csv = "/opt/honeypot/logs/combined_logs_clean.csv"

# Output fields
fields = ["Timestamp", "Source IP", "Port", "Attack Type", "Message", "Source"]
rows = []

# ----------------- Cowrie Log Parser -----------------
if os.path.exists(cowrie_log):
    with open(cowrie_log, 'r') as cowrie_file:
        for line in cowrie_file:
            try:
                entry = json.loads(line.strip())
                if entry.get("eventid") in ["cowrie.command.input", "cowrie.login.failed", "cowrie.login.success"]:
                    rows.append({
                        "Timestamp": entry.get("timestamp", ""),
                        "Source IP": entry.get("src_ip", "unknown"),
                        "Port": 22,
                        "Attack Type": "SSH Command" if "command" in entry.get("eventid") else "SSH Login",
                        "Message": entry.get("input") or f"{entry.get('username')}:{entry.get('password')}",
                        "Source": "ahm-ssh-honey"  # or rename to whatever you want
                    })
            except json.JSONDecodeError:
                continue

# ----------------- Simple Honeypot Log Parser -----------------
if os.path.exists(simple_log):
    with open(simple_log, 'r') as simple_file:
        for line in simple_file:
            parts = line.strip().split(" - ", 4)  # Split into 5 parts max
            if len(parts) == 5:
                rows.append({
                    "Timestamp": parts[0],
                    "Source IP": parts[1],
                    "Port": parts[2],
                    "Attack Type": parts[3],
                    "Message": parts[4],
                    "Source": "simple"
                })
            else:
                print(f"[!] Skipped malformed line in commands.log:\n    {line.strip()}")

# ----------------- Write to CSV -----------------
os.makedirs(os.path.dirname(combined_csv), exist_ok=True)

with open(combined_csv, 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print(f"\n✅ Combined and formatted log written to:\n{combined_csv}")
