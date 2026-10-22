"""
merged_scanner.py
=================
Single-file Vulnerability Scanner.
Database, crawler, checks, orchestrator and Flask API are all in this file.

    pip install -r requirements.txt
    python merged_scanner.py

Then open http://127.0.0.1:5000

FOR EDUCATIONAL AND AUTHORISED TESTING ONLY.
Only scan systems you own or have explicit written permission to test.

Sections (in order):
  1. Imports
  2. Database layer
  3. Crawler
  4. XSS check
  5. SQLi check
  6. Headers check
  7. Scan orchestrator
  8. Flask API + dashboard
  9. Entry point
"""

# =============================================================================
# 1. IMPORTS
# =============================================================================

import os
import time
import sqlite3
from datetime import datetime
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template_string


# =============================================================================
# 2. DATABASE LAYER
# =============================================================================

# Always store the DB next to this file, no matter where the script is run from
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_results.db")

# Severity mapping - assigns risk level based on finding type
SEVERITY_MAP = {
    "Reflected XSS": "High",
    "SQL Injection": "High",
    "Missing Security Header": "Medium",  # default; refined per-header below
}

# Some headers are more critical than others - override the default above
HEADER_SEVERITY_OVERRIDE = {
    "Content-Security-Policy": "High",
    "X-Frame-Options": "Medium",
    "Strict-Transport-Security": "Medium",
    "X-Content-Type-Options": "Medium",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low",
}


@contextmanager
def get_connection():
    """Context manager so every caller gets a connection that is always closed properly."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name, not just index
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Creates the tables if they don't already exist. Safe to call every run."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                started_at TIMESTAMP NOT NULL,
                finished_at TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'running'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                page TEXT NOT NULL,
                evidence TEXT,
                payload TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)


def create_scan(target_url):
    """Creates a new scan record with status 'running'. Returns the new scan_id."""
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO scans (target_url, started_at, status) VALUES (?, ?, ?)",
            (target_url, datetime.now().isoformat(), "running")
        )
        return cursor.lastrowid


def finish_scan(scan_id, status="completed"):
    """Marks a scan as finished (or failed) with a timestamp."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, datetime.now().isoformat(), scan_id)
        )


def get_severity(finding_type, header_name=None):
    """
    Determines severity for a finding.
    For header findings, we check the specific header override first.
    """
    if finding_type == "Missing Security Header" and header_name:
        return HEADER_SEVERITY_OVERRIDE.get(header_name, "Medium")
    return SEVERITY_MAP.get(finding_type, "Medium")


def save_findings(scan_id, findings):
    """
    Saves a list of finding dicts to the database, linked to scan_id.
    Handles the slightly different shapes of XSS/SQLi findings (have 'payload')
    vs header findings (have 'header' instead, no payload).
    """
    with get_connection() as conn:
        for f in findings:
            header_name = f.get("header")
            severity = get_severity(f["type"], header_name=header_name)
            conn.execute(
                """INSERT INTO findings (scan_id, type, severity, page, evidence, payload)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    f["type"],
                    severity,
                    f["page"],
                    f.get("evidence", ""),
                    f.get("payload"),
                )
            )


def get_scan_summary(scan_id):
    """Returns scan metadata + all its findings (High first, then Medium, then Low)."""
    with get_connection() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            return None
        findings = conn.execute(
            """SELECT * FROM findings WHERE scan_id = ?
               ORDER BY CASE severity WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, id""",
            (scan_id,)
        ).fetchall()
        return {
            "scan": dict(scan),
            "findings": [dict(f) for f in findings]
        }


def get_all_scans():
    """Returns a list of all past scans, most recent first."""
    with get_connection() as conn:
        scans = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [dict(s) for s in scans]


# =============================================================================
# 3. CRAWLER
# =============================================================================

class Crawler:
    def __init__(self, base_url, max_pages=30):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_pages = max_pages

        self.visited = set()
        self.to_visit = [base_url]

        self.found_links = set()
        self.found_forms = []  # list of dicts: {page, action, method, inputs}

        # session keeps cookies alive across requests - needed for authenticated crawling
        self.session = requests.Session()

    def login_dvwa(self, login_url, username="admin", password="password"):
        """
        Logs into DVWA by:
        1. GET the login page to grab the CSRF token (user_token)
        2. POST username/password/token together
        3. Session cookies are now authenticated for all future requests
        """
        try:
            resp = self.session.get(login_url, timeout=8)
        except requests.RequestException as e:
            print(f"[!] Could not reach login page: {e}")
            return False

        soup = BeautifulSoup(resp.text, "html.parser")

        token_input = soup.find("input", {"name": "user_token"})
        if not token_input:
            print("[!] Could not find CSRF token - login page structure may differ")
            return False

        token = token_input.get("value")
        payload = {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": token
        }

        try:
            login_resp = self.session.post(login_url, data=payload, timeout=8)
        except requests.RequestException as e:
            print(f"[!] Login request failed: {e}")
            return False

        if "login.php" not in login_resp.url:
            print(f"[+] Logged in successfully as {username}")
            return True
        else:
            print("[!] Login failed - check credentials")
            return False

    def is_internal(self, url):
        """Only follow links on the same domain."""
        return urlparse(url).netloc == self.domain or urlparse(url).netloc == ""

    def extract_forms(self, soup, page_url):
        """Find all forms on a page and record their fields."""
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action") or page_url
            action_url = urljoin(page_url, action)
            method = form.get("method", "get").lower()

            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                input_type = tag.get("type", "text")
                if name:
                    inputs.append({"name": name, "type": input_type})

            self.found_forms.append({
                "page": page_url,
                "action": action_url,
                "method": method,
                "inputs": inputs
            })

    def crawl(self):
        """Main crawl loop - breadth-first traversal up to max_pages."""
        while self.to_visit and len(self.visited) < self.max_pages:
            url = self.to_visit.pop(0)

            if url in self.visited:
                continue

            try:
                response = self.session.get(url, timeout=5)
            except requests.RequestException as e:
                print(f"[!] Failed to fetch {url}: {e}")
                continue

            self.visited.add(url)
            self.found_links.add(url)

            if "text/html" not in response.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            self.extract_forms(soup, url)

            for a_tag in soup.find_all("a", href=True):
                link = urljoin(url, a_tag["href"])
                link = link.split("#")[0]

                if self.is_internal(link) and link not in self.visited:
                    self.to_visit.append(link)

        return {
            "pages_crawled": list(self.visited),
            "forms_found": self.found_forms
        }


# =============================================================================
# 4. XSS CHECK
# =============================================================================

XSS_PAYLOADS = [
    "<script>alert('XSS_TEST_1')</script>",
    "<img src=x onerror=alert('XSS_TEST_2')>",
    "\"><script>alert('XSS_TEST_3')</script>",
]


def test_form_for_xss(form, session=None):
    """
    Takes a single form dict (from the crawler) and tests each text-like
    input field with each XSS payload.
    Returns a list of findings (empty list if nothing found).
    """
    findings = []
    req = session if session else requests

    testable_types = {"text", "search", "email", "url", "textarea"}
    testable_inputs = [i for i in form["inputs"] if i["type"] in testable_types]

    if not testable_inputs:
        return findings

    for payload in XSS_PAYLOADS:
        data = {}
        for inp in form["inputs"]:
            if inp in testable_inputs:
                data[inp["name"]] = payload
            elif inp["type"] == "hidden":
                data[inp["name"]] = ""
            else:
                data[inp["name"]] = "test"

        try:
            if form["method"] == "post":
                response = req.post(form["action"], data=data, timeout=8)
            else:
                response = req.get(form["action"], params=data, timeout=8)
        except requests.RequestException as e:
            print(f"[!] Request failed for {form['action']}: {e}")
            continue

        if payload in response.text:
            findings.append({
                "type": "Reflected XSS",
                "page": form["page"],
                "action": form["action"],
                "payload": payload,
                "evidence": f"Payload '{payload}' reflected unescaped in response"
            })

    return findings


def run_xss_checks(forms, session=None):
    """Runs XSS checks across all discovered forms."""
    all_findings = []
    for form in forms:
        all_findings.extend(test_form_for_xss(form, session=session))
    return all_findings


# =============================================================================
# 5. SQLI CHECK
# =============================================================================

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "1' AND '1'='2",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "sqlstate",
    "pg_query()",
    "sqlite3.operationalerror",
    "odbc sql server driver",
]


def looks_like_sql_error(response_text):
    """Check response body for known database error signatures (case-insensitive)."""
    lowered = response_text.lower()
    for signature in ERROR_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def test_form_for_sqli(form, session=None):
    """
    Takes a single form dict and tests each text-like input with SQLi payloads.
    Returns a list of findings.
    """
    findings = []
    req = session if session else requests

    testable_types = {"text", "search", "email", "url", "textarea"}
    testable_inputs = [i for i in form["inputs"] if i["type"] in testable_types]

    if not testable_inputs:
        return findings

    for payload in SQLI_PAYLOADS:
        data = {}
        for inp in form["inputs"]:
            if inp in testable_inputs:
                data[inp["name"]] = payload
            elif inp["type"] == "hidden":
                data[inp["name"]] = ""
            else:
                data[inp["name"]] = "test"

        try:
            if form["method"] == "post":
                response = req.post(form["action"], data=data, timeout=8)
            else:
                response = req.get(form["action"], params=data, timeout=8)
        except requests.exceptions.Timeout:
            print(f"[!] Timeout on {form['action']} - skipping payload")
            continue
        except requests.RequestException as e:
            print(f"[!] Request failed for {form['action']}: {e}")
            continue

        error_match = looks_like_sql_error(response.text)
        if error_match:
            findings.append({
                "type": "SQL Injection",
                "page": form["page"],
                "action": form["action"],
                "payload": payload,
                "evidence": f"Database error signature detected: '{error_match}'"
            })

    return findings


def run_sqli_checks(forms, session=None):
    """Runs SQLi checks across all discovered forms."""
    all_findings = []
    for form in forms:
        all_findings.extend(test_form_for_sqli(form, session=session))
    return all_findings


# =============================================================================
# 6. HEADERS CHECK
# =============================================================================

SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS/data injection by restricting sources of scripts, styles, etc.",
    "X-Frame-Options": "Prevents clickjacking by blocking the page from being loaded in an <iframe>",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks (should be 'nosniff')",
    "Strict-Transport-Security": "Forces HTTPS connections (HSTS) - prevents downgrade/MITM attacks",
    "Referrer-Policy": "Controls how much referrer info is leaked to other sites",
    "Permissions-Policy": "Restricts which browser features (camera, mic, geolocation) the page can use",
}


def check_headers(url, session=None):
    """
    Fetches the given URL and checks which recommended security
    headers are missing from the response.
    Returns a list of findings (one per missing header).
    """
    findings = []
    req = session if session else requests

    try:
        response = req.get(url, timeout=8)
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}")
        return findings

    present_headers = {h.lower(): v for h, v in response.headers.items()}

    for header, description in SECURITY_HEADERS.items():
        if header.lower() not in present_headers:
            findings.append({
                "type": "Missing Security Header",
                "page": url,
                "header": header,
                "evidence": f"'{header}' not present in response - {description}"
            })

    return findings


def run_header_checks(pages, session=None):
    """Runs header checks across a list of page URLs (each unique page checked once)."""
    all_findings = []
    checked = set()

    for page in pages:
        if page in checked:
            continue
        checked.add(page)
        all_findings.extend(check_headers(page, session=session))

    return all_findings


# =============================================================================
# 7. SCAN ORCHESTRATOR
# =============================================================================

def run_full_scan(target_url, login_url=None, username="admin", password="password"):
    """
    Runs a complete scan against target_url and saves results to the database.
    Returns the scan_id so the caller can look up results.

    Steps:
      1. Crawl (sequential - must happen first)
      2. XSS + SQLi + Header checks CONCURRENTLY (I/O-bound, ThreadPoolExecutor)
      3. Save all findings to SQLite

    If anything crashes, the scan is marked 'failed' instead of staying 'running'.
    """
    init_db()
    scan_id = create_scan(target_url)
    print(f"[+] Scan #{scan_id} started for {target_url}")

    start_time = time.time()

    try:
        # Step 1: Crawl
        crawler = Crawler(target_url, max_pages=15)
        if login_url:
            crawler.login_dvwa(login_url, username=username, password=password)

        crawl_results = crawler.crawl()
        pages = crawl_results["pages_crawled"]
        forms = crawl_results["forms_found"]
        print(f"[+] Crawled {len(pages)} pages, found {len(forms)} forms")

        # Step 2: Concurrent checks
        all_findings = []

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(run_xss_checks, forms, crawler.session): "XSS",
                executor.submit(run_sqli_checks, forms, crawler.session): "SQLi",
                executor.submit(run_header_checks, pages, crawler.session): "Headers",
            }

            for future in as_completed(futures):
                check_name = futures[future]
                try:
                    results = future.result()
                    print(f"[+] {check_name} check completed: {len(results)} findings")
                    all_findings.extend(results)
                except Exception as e:
                    print(f"[!] {check_name} check failed: {e}")

        # Step 3: Save
        save_findings(scan_id, all_findings)
        finish_scan(scan_id, status="completed")

    except Exception:
        finish_scan(scan_id, status="failed")
        raise

    elapsed = time.time() - start_time
    print(f"\n[+] Scan #{scan_id} completed in {elapsed:.2f}s")
    print(f"[+] Total findings: {len(all_findings)}")

    return scan_id


# =============================================================================
# 8. FLASK API + DASHBOARD
# =============================================================================

# Dashboard HTML is inlined so this file stays truly single-file.
# All database values are passed through esc() before being put into the page,
# because findings contain attack payloads (otherwise the dashboard itself
# would be vulnerable to XSS when displaying them).
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerability Scanner Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, Segoe UI, Roboto, sans-serif;
    background: #0f1117;
    color: #e4e6eb;
    margin: 0;
    padding: 2rem;
  }
  h1 { font-size: 1.4rem; margin-bottom: 1.5rem; }
  .panel {
    background: #1a1d27;
    border: 1px solid #2a2e3a;
    border-radius: 8px;
    padding: 1.25rem;
    margin-bottom: 1.5rem;
  }
  .scan-form { display: flex; gap: 0.75rem; }
  input[type="text"] {
    flex: 1;
    padding: 0.6rem 0.8rem;
    background: #0f1117;
    border: 1px solid #2a2e3a;
    border-radius: 6px;
    color: #e4e6eb;
    font-size: 0.9rem;
  }
  button {
    padding: 0.6rem 1.2rem;
    background: #4f7cff;
    border: none;
    border-radius: 6px;
    color: white;
    font-weight: 600;
    cursor: pointer;
    font-size: 0.9rem;
  }
  button:hover { background: #3d68eb; }
  button:disabled { background: #444; cursor: not-allowed; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.6rem 0.5rem; border-bottom: 1px solid #2a2e3a; }
  th { color: #9aa0ac; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
  tr:hover { background: #20232f; cursor: pointer; }
  .badge {
    display: inline-block;
    padding: 0.15rem 0.6rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .badge.High { background: #4a1620; color: #ff6b7a; }
  .badge.Medium { background: #4a3a16; color: #ffb84d; }
  .badge.Low { background: #16354a; color: #5db8ff; }
  .badge.completed { background: #163f2a; color: #4ade80; }
  .badge.running { background: #3a3a16; color: #eab308; }
  .badge.failed { background: #4a1620; color: #ff6b7a; }
  .status-line { color: #9aa0ac; font-size: 0.85rem; margin-top: 0.75rem; }
  .findings-detail { margin-top: 1rem; }
  .evidence { color: #9aa0ac; font-size: 0.8rem; word-break: break-all; }
</style>
</head>
<body>
<h1>&#x1F6E1;&#xFE0F; Vulnerability Scanner Dashboard</h1>
<div class="panel">
  <div class="scan-form">
    <input type="text" id="targetUrl" placeholder="http://localhost:8080" value="http://localhost:8080">
    <button id="scanBtn" onclick="startScan()">Start Scan</button>
  </div>
  <div class="status-line" id="statusLine">Only scan systems you own or have written permission to test.</div>
</div>
<div class="panel">
  <h2 style="font-size:1rem; margin-top:0;">Scan History</h2>
  <table id="scansTable">
    <thead>
      <tr><th>ID</th><th>Target</th><th>Started</th><th>Status</th></tr>
    </thead>
    <tbody id="scansBody"></tbody>
  </table>
</div>
<div class="panel findings-detail" id="findingsPanel" style="display:none;">
  <h2 style="font-size:1rem; margin-top:0;" id="findingsTitle">Findings</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Type</th><th>Page</th><th>Evidence</th></tr>
    </thead>
    <tbody id="findingsBody"></tbody>
  </table>
</div>
<script>
// Escape anything that came from the database before inserting it as HTML
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => (
    {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]
  ));
}

async function loadScans() {
  const res = await fetch("/api/scans");
  const scans = await res.json();
  const body = document.getElementById("scansBody");
  body.innerHTML = "";
  scans.forEach(scan => {
    const row = document.createElement("tr");
    row.onclick = () => loadFindings(scan.id, scan.target_url);
    row.innerHTML = `<td>#${esc(scan.id)}</td><td>${esc(scan.target_url)}</td>
      <td>${esc(new Date(scan.started_at).toLocaleString())}</td>
      <td><span class="badge ${esc(scan.status)}">${esc(scan.status)}</span></td>`;
    body.appendChild(row);
  });
}

async function loadFindings(scanId, targetUrl) {
  const res = await fetch(`/api/scans/${scanId}`);
  const data = await res.json();
  document.getElementById("findingsPanel").style.display = "block";
  document.getElementById("findingsTitle").textContent =
    `Findings for Scan #${scanId} - ${targetUrl} (${data.findings.length} total)`;
  const body = document.getElementById("findingsBody");
  body.innerHTML = "";
  data.findings.forEach(f => {
    const row = document.createElement("tr");
    row.innerHTML = `<td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td>${esc(f.type)}</td><td>${esc(f.page)}</td>
      <td class="evidence">${esc(f.evidence)}</td>`;
    body.appendChild(row);
  });
}

async function startScan() {
  const targetUrl = document.getElementById("targetUrl").value.trim();
  const btn = document.getElementById("scanBtn");
  const statusLine = document.getElementById("statusLine");
  if (!targetUrl) return;
  btn.disabled = true;
  btn.textContent = "Scanning...";
  statusLine.textContent = "Scan in progress - crawling + running XSS/SQLi/Header checks...";
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: targetUrl })
    });
    const data = await res.json();
    if (!res.ok) {
      statusLine.textContent = `Error: ${data.error}`;
    } else {
      statusLine.textContent = `Scan #${data.scan.id} completed - ${data.findings.length} findings.`;
    }
    await loadScans();
    if (res.ok) loadFindings(data.scan.id, data.scan.target_url);
  } catch (err) {
    statusLine.textContent = `Request failed: ${err}`;
  }
  btn.disabled = false;
  btn.textContent = "Start Scan";
}

loadScans();
</script>
</body>
</html>"""

app = Flask(__name__)


def normalize_target(target_url):
    """
    Ensures the URL has a scheme (http/https), and returns both
    the cleaned target and its base URL (scheme + domain only).
    Returns (None, None) if the URL has no usable host.
    """
    target_url = target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    parsed = urlparse(target_url)
    if not parsed.netloc:
        return None, None
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    return target_url, base_url


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Triggers a new scan. Expects JSON body: {"target_url": "http://localhost:8080"}
    Runs synchronously (~15-30s). A production version would use a background job.
    """
    data = request.get_json(silent=True) or {}
    raw_target = (data.get("target_url") or "").strip()

    if not raw_target:
        return jsonify({"error": "target_url is required"}), 400

    target_url, base_url = normalize_target(raw_target)
    if not target_url:
        return jsonify({"error": "Invalid target URL"}), 400

    # DVWA login is only attempted for a local DVWA instance on port 8080
    login_url = None
    if "localhost:8080" in base_url or "127.0.0.1:8080" in base_url:
        login_url = base_url + "/login.php"

    try:
        scan_id = run_full_scan(target_url, login_url=login_url)
        summary = get_scan_summary(scan_id)
        return jsonify(summary), 201
    except Exception as e:
        # Log details on the server only; don't leak internals to the browser
        print(f"[!] Scan failed: {e}")
        return jsonify({"error": "Scan failed. See the server console for details."}), 500


@app.route("/api/scans", methods=["GET"])
def list_scans():
    """Returns all past scans, most recent first."""
    return jsonify(get_all_scans())


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Returns full details + findings for one scan."""
    summary = get_scan_summary(scan_id)
    if not summary:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(summary)


# =============================================================================
# 9. ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    init_db()
    # Bind to localhost only and keep debug OFF: Flask's debug mode exposes an
    # interactive console, and this API can make the server send requests to any
    # URL, so it must never be reachable from other machines.
    app.run(host="127.0.0.1", port=5000, debug=False)