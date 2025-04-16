import socket
import json
import time
import os
import threading
import geoip2.database
from datetime import datetime


# --------------------- Kibana Additions Start -------------------------
import logging
from logging.handlers import RotatingFileHandler

# Set up JSON logging for Logstash
kibana_logger = logging.getLogger('honeypot_kibana')
kibana_logger.setLevel(logging.INFO)
handler = RotatingFileHandler(
    '/opt/honeypot/logs/kibana_connections.json',
    maxBytes=10*1024*1024,
    backupCount=5
)
handler.setFormatter(logging.Formatter('{"@timestamp": "%(asctime)s", "message": %(message)s}'))
kibana_logger.addHandler(handler)

# --------------------- Configuration -------------------------
CONFIG_PATH = '/opt/honeypot/config/config.json'
GEOIP_DB_PATH = '/opt/honeypot/data/GeoLite2-City.mmdb'

with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)

# --------------------- Attack Type Detection -------------------------
def detect_attack(data, ip):
    decoded = data.decode('utf-8', errors='ignore').lower()

    if "wget" in decoded or "curl" in decoded:
        return "Downloader/Recon"

    elif b"\x16\x03" in data[:2] or b"\x15\x03" in data[:2]:
        return "SSL/TLS Probe"

    elif "nmap" in decoded or decoded.startswith("get /") or "user-agent:" in decoded:
        return "Scanning"

    elif "root" in decoded or "admin" in decoded or "password" in decoded:
        return "Brute-force/Password Probe"

    elif "select" in decoded or "union" in decoded or "--" in decoded or "or 1=1" in decoded or "sqlmap" in decoded:
        return "SQL Injection Attempt"

    elif "<script>" in decoded or "alert(" in decoded or "onerror=" in decoded or "onload=" in decoded:
        return "XSS Attempt"

    elif "post /" in decoded or "phpmyadmin" in decoded:
        return "Web Exploit Attempt"

    elif "ls" in decoded or "whoami" in decoded or "cat /etc/passwd" in decoded or "uname -a" in decoded:
        return "Command Injection"

    elif "system(" in decoded or "eval(" in decoded or "exec(" in decoded or "shell_exec(" in decoded:
        return "RCE Attempt"

    elif "../" in decoded or "..\\" in decoded:
        return "Path Traversal"

    elif "etc/passwd" in decoded or "/bin/sh" in decoded or "cmd.exe" in decoded:
        return "Local File Inclusion (LFI)"

    elif "http://" in decoded or "https://" in decoded:
        return "SSRF Attempt"

    elif "<?xml" in decoded or "<!doctype" in decoded or "system identifier" in decoded:
        return "XXE/Entity Injection"

    elif "powershell" in decoded or "iex(" in decoded or "invoke-expression" in decoded:
        return "PowerShell Payload"

    elif "bash -i" in decoded or "/dev/tcp/" in decoded or "nc -e" in decoded:
        return "Reverse Shell Attempt"

    elif "metasploit" in decoded or "msf" in decoded:
        return "Metasploit Payload"

    elif "cmd.exe" in decoded or "powershell.exe" in decoded:
        return "Windows Command Probe"

    elif "dir" in decoded or "type" in decoded or "copy con" in decoded:
        return "Windows Command Injection"

    elif decoded.strip().isalnum():
        return "Probe/Idle Scan"

    else:
        return "Unknown/Generic Probe"


# --------------------- Log Connection -------------------------
def log_connection(ip, port, attack_type=None, payload=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        response = geoip_reader.city(ip)
        location = f"{response.city.name}, {response.country.name}"
    except:
        location = "Unknown Location"

    log_entry = f"{timestamp} - Connection from {ip} ({location}) on port {port}"
    if attack_type:
        log_entry += f" - Type: {attack_type}"
    print(log_entry)

    try:
        os.makedirs(config['log_location'], exist_ok=True)
        log_path = os.path.join(config['log_location'], 'connections.log')
        with open(log_path, 'a') as log_file:
            log_file.write(log_entry + '\n')
    except Exception as e:
        print(f"Failed to write text log: {str(e)}")

    try:
        json_log_path = os.path.join(config['log_location'], 'connections.json')
        log_data = {
            "timestamp": timestamp,
            "ip": ip,
            "port": port,
            "location": location,
            "attack_type": attack_type,
            "payload": payload
        }
        with open(json_log_path, 'a') as json_file:
            json.dump(log_data, json_file)
            json_file.write('\n')
        kibana_data = {
            "@timestamp": datetime.now().isoformat(),
            "source": {
                "ip": ip,
                "port": port,
                "geo": {
                    "location": location
                }
            },
            "event": {
                "kind": "event",
                "category": attack_type or "network",
                "type": "connection"
            },
            "honeypot": {
                "type": attack_type or "connection",
                "payload": payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else payload
            }
        }
        kibana_logger.info(json.dumps(kibana_data))

    except Exception as e:
        print(f"Failed to write JSON log: {str(e)}")

# --------------------- Handle Each Connection -------------------------
def handle_connection(client_socket, port):
    try:
        if port == 23:
            client_socket.send(b"Welcome to AHM - Now you can Leave\r\nlogin: ")
        elif port == 80:
            client_socket.send(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><body>Supp attacker</body></html>")
        elif port == 443:
            client_socket.send(b"\x15\x03\x01\x00\x02\x02\x28")
        elif port == 3306:
            client_socket.send(b"\x0a5.7.29-log\x00\x00\x00\x00")
        elif port == 8080:
            client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\nForbidden")
        elif port == 2223:
            client_socket.send(b"SSH-2.0-Twisted_22.4.0\r\n")
        else:
            client_socket.send(b"Welcomeeeeeeeee attacker!\n")

        data = client_socket.recv(1024)
        if data:
            ip = client_socket.getpeername()[0]
            decoded_payload = data.decode('utf-8', errors='ignore')
            attack_type = detect_attack(data, ip)

            log_connection(ip, port, attack_type, decoded_payload)

            commands_log = os.path.join(config['log_location'], 'commands.log')
            with open(commands_log, 'a') as cmd_file:
                cmd_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {port} - {attack_type} - {decoded_payload}\n")

    except Exception as e:
        print(f"Error handling connection on port {port}: {str(e)}")
    finally:
        client_socket.close()

# --------------------- Start Listening on Each Port -------------------------
def start_honeypot(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        print(f"Honeypot listening on port {port}")
    except Exception as e:
        print(f"Failed to bind on port {port}: {str(e)}")
        return

    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_connection, args=(client, port))
        thread.daemon = True
        thread.start()

# --------------------- Main Runner -------------------------
if __name__ == "__main__":
    for port in config.get("listen_ports", [23, 80, 443, 3306, 8080, 2223]):
        try:
            t = threading.Thread(target=start_honeypot, args=(port,))
            t.daemon = True
            t.start()
        except Exception as e:
            print(f"Failed to start honeypot on port {port}: {str(e)}")

    while True:
        time.sleep(1)
