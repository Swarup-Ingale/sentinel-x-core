import sys
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def analyze_target(target_url):
    findings = []
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    target_url = target_url.rstrip('/')

    try:
        response = requests.get(target_url, timeout=5, verify=False)
        headers = response.headers

        # 1. CSP
        if 'Content-Security-Policy' not in headers:
            findings.append({"vulnerability_type": "Content-Security-Policy (CSP)", "status": "Vulnerable", "explanation": "Missing CSP header. Susceptible to XSS.", "vulnerable_code": "Content-Security-Policy: <MISSING>", "remediation_code_generated": "Content-Security-Policy: default-src 'self';"})
        else:
            findings.append({"vulnerability_type": "Content-Security-Policy (CSP)", "status": "Secure"})

        # 2. HSTS
        if target_url.startswith('https') and 'Strict-Transport-Security' not in headers:
            findings.append({"vulnerability_type": "HTTP Strict Transport Security (HSTS)", "status": "Vulnerable", "explanation": "Missing HSTS header. Vulnerable to downgrade attacks.", "vulnerable_code": "Strict-Transport-Security: <MISSING>", "remediation_code_generated": "Strict-Transport-Security: max-age=31536000"})
        elif target_url.startswith('http://'):
            findings.append({"vulnerability_type": "HTTP Strict Transport Security (HSTS)", "status": "Secure", "explanation": "Not applicable for HTTP."})
        else:
            findings.append({"vulnerability_type": "HTTP Strict Transport Security (HSTS)", "status": "Secure"})

        # 3. Clickjacking
        if 'X-Frame-Options' not in headers:
            findings.append({"vulnerability_type": "Clickjacking Protection", "status": "Vulnerable", "explanation": "Missing X-Frame-Options. UI redressing possible.", "vulnerable_code": "X-Frame-Options: <MISSING>", "remediation_code_generated": "X-Frame-Options: DENY"})
        else:
            findings.append({"vulnerability_type": "Clickjacking Protection", "status": "Secure"})

        # 4. MIME-Sniffing
        if headers.get('X-Content-Type-Options', '').lower() != 'nosniff':
            findings.append({"vulnerability_type": "MIME-Sniffing", "status": "Vulnerable", "explanation": "Allows browsers to guess file types. Script execution risk.", "vulnerable_code": "X-Content-Type-Options: <MISSING>", "remediation_code_generated": "X-Content-Type-Options: nosniff"})
        else:
            findings.append({"vulnerability_type": "MIME-Sniffing", "status": "Secure"})

        # 5. Server Version
        server_header = headers.get('Server', '')
        if any(char.isdigit() for char in server_header) or headers.get('X-Powered-By'):
            findings.append({"vulnerability_type": "Information Disclosure (Server Version)", "status": "Warning", "explanation": "Server broadcasts its version, enabling targeted CVE attacks.", "vulnerable_code": f"Server: {server_header}", "remediation_code_generated": "server_tokens off;"})
        else:
            findings.append({"vulnerability_type": "Information Disclosure (Server Version)", "status": "Secure"})

        # 6. CORS
        if headers.get('Access-Control-Allow-Origin') == '*':
            findings.append({"vulnerability_type": "Insecure CORS Policy", "status": "Vulnerable", "explanation": "Wildcard CORS allows any site to read data.", "vulnerable_code": "Access-Control-Allow-Origin: *", "remediation_code_generated": "Access-Control-Allow-Origin: https://trusted.com"})
        else:
            findings.append({"vulnerability_type": "Insecure CORS Policy", "status": "Secure"})

        # 7. Referrer-Policy
        if 'Referrer-Policy' not in headers:
            findings.append({"vulnerability_type": "Referrer-Policy", "status": "Warning", "explanation": "URL data (tokens/hashes) leaks to external sites.", "vulnerable_code": "Referrer-Policy: <MISSING>", "remediation_code_generated": "Referrer-Policy: strict-origin-when-cross-origin"})
        else:
            findings.append({"vulnerability_type": "Referrer-Policy", "status": "Secure"})

        # 8. Insecure Cookies
        cookies = headers.get('Set-Cookie', '')
        if cookies and ('Secure' not in cookies or 'HttpOnly' not in cookies):
            findings.append({"vulnerability_type": "Insecure Session Cookies", "status": "CRITICAL", "explanation": "Cookies lack Secure/HttpOnly flags. Susceptible to XSS theft.", "vulnerable_code": f"Set-Cookie: {cookies.split(';')[0]}", "remediation_code_generated": "Set-Cookie: token; Secure; HttpOnly; SameSite=Strict"})
        else:
            findings.append({"vulnerability_type": "Session Cookies", "status": "Secure"})

        # 9. Exposed .env
        try:
            env_resp = requests.get(target_url + '/.env', timeout=3, verify=False)
            if env_resp.status_code == 200 and 'SECRET' in env_resp.text.upper():
                findings.append({"vulnerability_type": "Exposed .env File", "status": "CRITICAL", "explanation": "Root .env file is public. High risk of secret leakage.", "vulnerable_code": "HTTP 200 OK: /.env", "remediation_code_generated": "location ~ /\\.env { deny all; }"})
            else:
                findings.append({"vulnerability_type": "Exposed .env File", "status": "Secure"})
        except:
            findings.append({"vulnerability_type": "Exposed .env File", "status": "Secure"})

        # 10. Exposed .git
        try:
            git_resp = requests.get(target_url + '/.git/config', timeout=3, verify=False)
            if git_resp.status_code == 200 and '[core]' in git_resp.text:
                findings.append({"vulnerability_type": "Source Code Exposure (.git)", "status": "CRITICAL", "explanation": "Git folder is public. Source code leak risk.", "vulnerable_code": "HTTP 200 OK: /.git/config", "remediation_code_generated": "location ~ /\\.git { deny all; }"})
            else:
                findings.append({"vulnerability_type": "Source Code Exposure (.git)", "status": "Secure"})
        except:
            findings.append({"vulnerability_type": "Source Code Exposure (.git)", "status": "Secure"})

    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

    return {"target": target_url, "status": "Online", "findings": findings}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    print(json.dumps(analyze_target(sys.argv[1])))