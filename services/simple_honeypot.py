import socket
import json
import time
import os
import threading
import geoip2.database
from datetime import datetime

# Load configuration
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
    elif "nmap" in decoded or decoded.startswith("get /") or "user-agent:" in decoded:
        return "Scanning"
    elif "root" in decoded or "admin" in decoded or "password" in decoded:
        return "Brute-force/Password Probe"
    elif "select" in decoded or "union" in decoded or "--" in decoded:
        return "SQL Injection Attempt"
    elif "<script>" in decoded or "alert(" in decoded:
        return "XSS Attempt"
    elif "post /" in decoded:
        return "Web Exploit Attempt"
    elif "ls" in decoded or "whoami" in decoded:
        return "Command Injection"
    elif decoded.strip().isalnum():
        return "Probe/Idle Scan"
    else:
        return "Unknown/Generic Probe"

# --------------------- Log Connection with GeoIP -------------------------
def log_connection(ip, port):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        response = geoip_reader.city(ip)
        location = f"{response.city.name}, {response.country.name}"
    except:
        location = "Unknown Location"

    log_entry = f"{timestamp} - Connection from {ip} ({location}) on port {port}\n"

    try:
        os.makedirs(config['log_location'], exist_ok=True)
        log_path = os.path.join(config['log_location'], 'connections.log')
        with open(log_path, 'a') as log_file:
            log_file.write(log_entry)
        print(log_entry.strip())
    except Exception as e:
        print(f"Failed to log connection: {str(e)}")

# --------------------- Handle Each Connection -------------------------
def handle_connection(client_socket, port):
    try:
        client_socket.send(b"Welcome to the service!\n")

        if port == 22:
            client_socket.send(b"SSH-2.0-OpenSSH_7.9p1 Debian-10\n")
        elif port == 80:
            client_socket.send(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")

        data = client_socket.recv(1024)
        if data:
            ip = client_socket.getpeername()[0]
            attack_type = detect_attack(data, ip)

            log_connection(ip, port)

            commands_log = os.path.join(config['log_location'], 'commands.log')
            with open(commands_log, 'a') as cmd_file:
                cmd_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {ip} - {port}- {attack_type} - {data.decode('utf-8', errors='ignore')}\n")

    except Exception as e:
        print(f"Error handling connection: {str(e)}")
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
    for port in config.get("listen_ports", []):
        try:
            t = threading.Thread(target=start_honeypot, args=(port,))
            t.daemon = True
            t.start()
        except Exception as e:
            print(f"Failed to start honeypot on port {port}: {str(e)}")

    while True:
        time.sleep(1)
