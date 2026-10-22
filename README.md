\# 🛡️ Vulnerability Scanner



A lightweight web vulnerability scanner built in Python. It crawls a target website, then concurrently tests for \*\*Reflected XSS\*\*, \*\*SQL Injection\*\*, and \*\*missing HTTP security headers\*\*. Results are stored in SQLite and displayed in a dark-mode web dashboard.



> ⚠️ \*\*For educational and authorised testing only.\*\* Only scan systems you own or have explicit written permission to test. Unauthorised scanning is illegal.



\---



\## Features



\- 🕷️ \*\*BFS Web Crawler\*\* — discovers internal pages and forms automatically

\- 🔐 \*\*DVWA Authentication\*\* — handles CSRF-token login when scanning a local DVWA instance on port 8080

\- 💉 \*\*XSS Detection\*\* — injects payloads into form fields and detects unescaped reflection

\- 🗄️ \*\*SQL Injection Detection\*\* — checks responses for database error signatures across multiple engines

\- 🔒 \*\*Security Header Audit\*\* — checks 6 OWASP-recommended response headers

\- ⚡ \*\*Concurrent Scanning\*\* — XSS, SQLi, and header checks run in parallel threads

\- 📊 \*\*Web Dashboard\*\* — scan history, per-scan findings, severity badges

\- 🗃️ \*\*SQLite Persistence\*\* — all scan results saved and queryable via a REST API



\---



\## Project Structure



```

vuln-scanner/

├── merged\_scanner.py     # Complete scanner: DB, crawler, checks, orchestrator, Flask API, dashboard

├── requirements.txt

├── LICENSE

└── README.md

```



\---



\## Quick Start



\### Prerequisites



\- Python 3.8+

\- pip



\### 1. Clone and install



```bash

git clone https://github.com/Jashureddy8284/vuln-scanner.git

cd vuln-scanner

python3 -m venv venv

source venv/bin/activate        # Windows: venv\\Scripts\\activate

pip install -r requirements.txt

```



\### 2. Run



```bash

python merged\_scanner.py

```



Then open \*\*http://127.0.0.1:5000\*\* in your browser. The server only listens on localhost.



\---



\## Testing Against DVWA (Recommended)



\[DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application) is the intended test target. Run it with Docker:



```bash

docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa

```



Open `http://localhost:8080`, log in with `admin` / `password`, click \*\*Create / Reset Database\*\*, then set \*\*DVWA Security\*\* to \*\*Low\*\*.



Point the scanner at `http://localhost:8080`. For a local DVWA on port 8080 the scanner logs in automatically (default credentials `admin` / `password`).



\### Other public test targets



| Target | URL |

|---|---|

| Acunetix test site | `http://testphp.vulnweb.com` |

| IBM demo bank | `http://demo.testfire.net` |



> These are maintained for security testing and need no login — enter the URL and click \*\*Start Scan\*\*.



\---



\## REST API



| Method | Endpoint | Description |

|---|---|---|

| `GET` | `/` | Serves the dashboard |

| `POST` | `/api/scan` | Start a new scan |

| `GET` | `/api/scans` | List all past scans |

| `GET` | `/api/scans/<id>` | Get full details + findings for one scan |



\### Example: start a scan via curl



```bash

curl -X POST http://127.0.0.1:5000/api/scan \\

&#x20; -H "Content-Type: application/json" \\

&#x20; -d '{"target\_url": "http://testphp.vulnweb.com"}'

```



\---



\## Severity Levels



| Finding | Severity |

|---|---|

| Reflected XSS | 🔴 High |

| SQL Injection | 🔴 High |

| Missing `Content-Security-Policy` | 🔴 High |

| Missing `X-Frame-Options` | 🟡 Medium |

| Missing `Strict-Transport-Security` | 🟡 Medium |

| Missing `X-Content-Type-Options` | 🟡 Medium |

| Missing `Referrer-Policy` | 🔵 Low |

| Missing `Permissions-Policy` | 🔵 Low |



\---



\## How It Works



```

Browser / curl

&#x20;    │

&#x20;    ▼

&#x20; Flask API  (/api/scan)

&#x20;    │

&#x20;    ▼

&#x20; run\_full\_scan()

&#x20;    │

&#x20;    ├── 1. Crawler (BFS, up to 15 pages)

&#x20;    │        └── collects pages + forms

&#x20;    │

&#x20;    └── 2. ThreadPoolExecutor (3 workers, concurrent)

&#x20;             ├── XSS check     → tests every form field

&#x20;             ├── SQLi check    → tests every form field

&#x20;             └── Header check  → inspects every page's response headers

&#x20;                      │

&#x20;                      ▼

&#x20;             3. Save all findings to SQLite

```



\---



\## Security Notes



\- The server binds to `127.0.0.1` with Flask debug mode \*\*off\*\*. Do not expose it to a network: the scan endpoint makes the server send requests to any URL it is given.

\- Scan results are stored in a local `scanner\_results.db` file, which is excluded from Git.

\- The dashboard HTML-escapes all stored values, since findings contain attack payload strings.



\---



\## Known Limitations



\- \*\*Synchronous scan endpoint\*\* — `POST /api/scan` blocks until the scan finishes (\~15–30s). A production version would use a background task queue (Celery, RQ).

\- \*\*CSRF tokens\*\* — hidden form fields (like CSRF tokens) are sent blank during XSS/SQLi tests. This may cause false negatives on heavily CSRF-protected forms.

\- \*\*JavaScript-rendered pages\*\* — the crawler uses `requests` + BeautifulSoup, so it cannot crawl SPAs or pages that need JavaScript to render. A Playwright/Selenium crawler would be needed for those.

\- \*\*Scope\*\* — covers reflected XSS (not stored/DOM), error-based SQLi (not blind/time-based), and header presence (not misconfiguration).

\- \*\*Concurrent load\*\* — running three checks at once can cause read timeouts on small targets such as a single DVWA container.



\---



\## Tech Stack



| Layer | Technology |

|---|---|

| Web framework | Flask |

| HTTP client | requests |

| HTML parsing | BeautifulSoup4 |

| Concurrency | `concurrent.futures.ThreadPoolExecutor` |

| Database | SQLite3 (stdlib) |

| Frontend | Vanilla JS + CSS |



\---



\## License



MIT — see \[LICENSE](LICENSE) for details.

