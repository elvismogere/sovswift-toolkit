# SovSwift Security Toolkit v3.0
# Recon + Port Scanner + Banner Grabbing + PDF Report Generator
# Author: Elvis Mogere

import socket
import datetime
from pdf_report import generate_pdf

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else "No banner"
    except:
        return "Could not grab banner"

def run_scan(target):
    try:
        ip = socket.gethostbyname(target) if not target.replace('.','').isdigit() else target
    except socket.gaierror:
        print("Could not resolve target.")
        return

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Target     : {target}")
    print(f"IP Address : {ip}")
    print(f"Scan Time  : {scan_time}")
    print("-" * 50)

    common_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt"}
    results = []
    open_ports = []

    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(ip, port)
            results.append({"status": "OPEN", "port": port, "service": service, "banner": banner})
            open_ports.append(f"{port}/{service}")
            print(f"  [OPEN]    Port {port} - {service}")
            print(f"            Banner: {banner[:100]}")
        else:
            results.append({"status": "closed", "port": port, "service": service})
            print(f"  [closed]  Port {port} - {service}")
        sock.close()

    print("-" * 50)
    print(f"Open ports found: {len(open_ports)}")
    print("Generating PDF report...")
    generate_pdf(target, ip, scan_time, results, open_ports)

target = input("Enter target domain or IP: ")
print("--- SovSwift Security Toolkit v3.0 ---")
run_scan(target)
