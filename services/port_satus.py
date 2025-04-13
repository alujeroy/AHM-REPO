import socket

ports = [22, 80, 443, 3306, 8080, 2223]

print("Checking open ports on localhost:")
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex(('127.0.0.1', port))
    if result == 0:
        print(f"✅ Port {port} is open.")
    else:
        print(f"❌ Port {port} is closed.")
    s.close()
