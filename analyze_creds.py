import re

with open('/opt/honeypot/logs/commands.log', 'rb') as f:
    data = f.read().decode('ascii', errors='ignore')
    
creds = re.findall(r'(?i)(user(name)?|pass(word)?|login|auth)=?([^&\s]+)', data)
for match in creds:
    print(f"Found: {match[0]}={match[3]}")
