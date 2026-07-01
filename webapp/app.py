from flask import Flask, render_template, request, send_file, jsonify
import socket
import datetime
import sys
import os
import ssl
import json
import subprocess

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

@app.route("/dns", methods=["POST"])
def dns_lookup():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    try:
        results = {}
        import socket as s
        results["A"] = []
        try:
            answers = s.getaddrinfo(target, None, s.AF_INET)
            results["A"] = list(set([r[4][0] for r in answers]))
        except:
            results["A"] = ["Not found"]

        results["AAAA"] = []
        try:
            answers = s.getaddrinfo(target, None, s.AF_INET6)
            results["AAAA"] = list(set([r[4][0] for r in answers]))
        except:
            results["AAAA"] = ["Not found"]

        try:
            hostname = s.gethostbyaddr(results["A"][0])[0] if results["A"][0] != "Not found" else "Not found"
            results["PTR"] = hostname
        except:
            results["PTR"] = "Not found"

        return jsonify({"target": target, "records": results})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/headers", methods=["POST"])
def http_headers():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    try:
        import urllib.request
        import urllib.error
        url = target if target.startswith("http") else f"http://{target}"
        req = urllib.request.Request(url, headers={"User-Agent": "SovSwift-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = dict(response.headers)
            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "MISSING ⚠️"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "MISSING ⚠️"),
                "X-Frame-Options": headers.get("X-Frame-Options", "MISSING ⚠️"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "MISSING ⚠️"),
                "X-XSS-Protection": headers.get("X-XSS-Protection", "MISSING ⚠️"),
                "Referrer-Policy": headers.get("Referrer-Policy", "MISSING ⚠️"),
                "Server": headers.get("Server", "Hidden"),
                "X-Powered-By": headers.get("X-Powered-By", "Hidden")
            }
            missing = sum(1 for v in security_headers.values() if "MISSING" in str(v))
            return jsonify({
                "target": target,
                "headers": security_headers,
                "missing_count": missing,
                "risk": "HIGH" if missing >= 4 else "MEDIUM" if missing >= 2 else "LOW"
            })
    except Exception as e:
        return jsonify({"error": f"Could not connect: {str(e)}"})

@app.route("/ssl", methods=["POST"])
def ssl_check():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            expiry = cert.get("notAfter", "Unknown")
            issued_to = dict(x[0] for x in cert.get("subject", []))
            issued_by = dict(x[0] for x in cert.get("issuer", []))
            from datetime import datetime as dt
            try:
                expiry_date = dt.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - dt.utcnow()).days
                status = "VALID ✅" if days_left > 30 else "EXPIRING SOON ⚠️" if days_left > 0 else "EXPIRED ❌"
            except:
                days_left = "Unknown"
                status = "Unknown"
            return jsonify({
                "target": target,
                "status": status,
                "days_left": days_left,
                "expiry": expiry,
                "issued_to": issued_to.get("commonName", "Unknown"),
                "issued_by": issued_by.get("organizationName", "Unknown"),
                "version": s.version()
            })
    except ssl.SSLCertVerificationError:
        return jsonify({"target": target, "status": "INVALID CERTIFICATE ❌", "error": "Certificate verification failed"})
    except Exception as e:
        return jsonify({"error": f"Could not check SSL: {str(e)}"})

@app.route("/whois", methods=["POST"])
def whois_lookup():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        import urllib.request
        url = f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={target}&apiKey=free"
        try:
            with urllib.request.urlopen(f"https://rdap.org/domain/{target}", timeout=5) as r:
                data = json.loads(r.read().decode())
                registrar = "Unknown"
                created = "Unknown"
                expires = "Unknown"
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        created = event.get("eventDate", "Unknown")[:10]
                    if event.get("eventAction") == "expiration":
                        expires = event.get("eventDate", "Unknown")[:10]
                for entity in data.get("entities", []):
                    for role in entity.get("roles", []):
                        if role == "registrar":
                            vcard = entity.get("vcardArray", [])
                            if vcard:
                                for v in vcard[1]:
                                    if v[0] == "fn":
                                        registrar = v[3]
                return jsonify({
                    "target": target,
                    "registrar": registrar,
                    "created": created,
                    "expires": expires,
                    "status": data.get("status", ["Unknown"])[0] if data.get("status") else "Unknown",
                    "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])][:4]
                })
        except:
            return jsonify({
                "target": target,
                "registrar": "Could not fetch",
                "created": "Unknown",
                "expires": "Unknown",
                "status": "Unknown",
                "nameservers": []
            })
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/download/<path:filename>")
def download(filename):
    filepath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), filename)
    return send_file(filepath, as_attachment=True)

if __name__ == "__main__":
    import os
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

@app.route("/ipgeo", methods=["POST"])
def ip_geo():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    try:
        import urllib.request
        ip = socket.gethostbyname(target) if not target.replace(".","").isdigit() else target
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,query", timeout=5) as r:
            data = json.loads(r.read().decode())
            return jsonify({"target": target, "ip": ip, "country": data.get("country","Unknown"), "region": data.get("regionName","Unknown"), "city": data.get("city","Unknown"), "isp": data.get("isp","Unknown"), "org": data.get("org","Unknown")})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/subdomains", methods=["POST"])
def subdomain_finder():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    target = target.replace("https://","").replace("http://","").split("/")[0]
    try:
        found = []
        common_subs = ["www","mail","ftp","admin","webmail","smtp","blog","dev","staging","api","shop","portal","vpn","test","demo","beta","app","mobile","cdn","static","media","secure","login","dashboard","cpanel","forum","support","help","wiki"]
        for sub in common_subs:
            try:
                full = f"{sub}.{target}"
                ip = socket.gethostbyname(full)
                found.append({"subdomain": full, "ip": ip})
            except:
                pass
        return jsonify({"target": target, "found": found, "count": len(found)})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/techdetect", methods=["POST"])
def tech_detect():
    target = request.form.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    try:
        import urllib.request
        url = target if target.startswith("http") else f"http://{target}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            headers = dict(r.headers)
            body = r.read(5000).decode(errors="ignore").lower()
        tech = []
        server = headers.get("Server","")
        if server:
            tech.append({"name": server, "category": "Web Server"})
        powered = headers.get("X-Powered-By","")
        if powered:
            tech.append({"name": powered, "category": "Framework"})
        cms_signatures = {
            "WordPress": ["wp-content","wp-includes"],
            "Joomla": ["joomla","/components/com_"],
            "Drupal": ["drupal","sites/default/files"],
            "Shopify": ["cdn.shopify.com"],
            "Wix": ["wix.com"],
            "Squarespace": ["squarespace.com"],
            "Laravel": ["laravel_session"],
            "Django": ["csrfmiddlewaretoken"],
            "React": ["react","__react"],
            "Vue.js": ["vue.js"],
            "Angular": ["ng-version"],
            "Bootstrap": ["bootstrap.min.css"],
            "jQuery": ["jquery.min.js"],
        }
        for cms, sigs in cms_signatures.items():
            for sig in sigs:
                if sig in body:
                    tech.append({"name": cms, "category": "CMS/Framework"})
                    break
        cookies = headers.get("Set-Cookie","")
        if "PHPSESSID" in cookies:
            tech.append({"name": "PHP", "category": "Language"})
        seen = set()
        unique_tech = []
        for t in tech:
            if t["name"] not in seen:
                seen.add(t["name"])
                unique_tech.append(t)
        return jsonify({"target": target, "technologies": unique_tech, "count": len(unique_tech)})
    except Exception as e:
        return jsonify({"error": f"Could not detect: {str(e)}"})
