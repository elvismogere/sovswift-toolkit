from flask import Flask, render_template, request, send_file, jsonify
import socket
import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pdf_report import generate_pdf

app = Flask(__name__)

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        lines = [l.strip() for l in banner.split("\n") if l.strip() and any(k in l for k in ["Server", "SSH", "HTTP", "200", "400"])]
        return lines[0][:100] if lines else banner[:80]
    except:
        return "Could not grab banner"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})

    try:
        ip = socket.gethostbyname(target) if not target.replace('.','').isdigit() else target
    except:
        return jsonify({"error": "Could not resolve target"})

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
        else:
            results.append({"status": "closed", "port": port, "service": service})
        sock.close()

    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    filename = generate_pdf(target, ip, scan_time, results, open_ports)

    return jsonify({
        "target": target,
        "ip": ip,
        "scan_time": scan_time,
        "results": results,
        "open_ports": open_ports,
        "pdf": filename
    })

@app.route("/download/<filename>")
def download(filename):
    filepath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), filename)
    return send_file(filepath, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
