# PhishGuard 🛡️

> **A lightweight, rule-based phishing URL detection and security analysis web application.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask%203.x-green.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2F%20SQLAlchemy-orange.svg)](https://www.sqlalchemy.org/)
[![Security](https://img.shields.io/badge/Security-CSRF%20%7C%20Heuristics%20%7C%20Zero--Network-red.svg)](#security--privacy)

---

## 📑 Table of Contents

- [Overview](#-overview)
  - [The Problem](#the-problem)
  - [The Solution](#the-solution)
- [Key Features](#-key-features)
- [How It Works](#-how-it-works)
  - [Heuristic Detection Engine](#heuristic-detection-engine)
  - [Risk Scoring & Thresholds](#risk-scoring--thresholds)
  - [Zero-Network Guarantee](#zero-network-guarantee)
- [Technologies Used](#-technologies-used)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
  - [Prerequisites](#prerequisites)
  - [Step-by-Step Setup (Windows)](#step-by-step-setup-windows)
- [Application Screenshots](#-application-screenshots)
- [Security & Privacy](#-security--privacy)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🔍 Overview

### The Problem
Phishing remains one of the primary delivery vectors for malware, credential harvesting, and identity theft. Attackers frequently craft deceptive URLs—employing brand lookalikes, multi-level subdomains, IP address hosts, link shorteners, and obfuscated paths—to trick users into surrendering sensitive credentials and financial data.

### The Solution
**PhishGuard** is an open, transparent web application designed to evaluate suspicious links before a user visits them. By analyzing the structural, lexical, and architectural properties of a submitted URL, PhishGuard computes a weighted risk score (0 to 100), categorizes the threat level, and provides actionable recommendations.

Importantly, PhishGuard performs **purely static heuristic inspection**: it never resolves, opens, or executes the submitted URL, guaranteeing that neither the server nor the user is exposed to malware payloads during analysis.

---

## ✨ Key Features

- **🔍 Heuristic Phishing Detection:** Evaluates URLs against 9 structural security checks, pinpointing malicious indicators with granular point values.
- **📊 0–100 Weighted Risk Scoring:** Transparent scoring model that maps directly into **Low Risk** (0–29), **Medium Risk** (30–69), and **High Risk** (70–100) tiers.
- **🛡️ Zero-Network URL Processing:** URLs are parsed exclusively using standard library string and component parsers (`urllib.parse`). The submitted site is never visited or downloaded.
- **👤 User Authentication & Accounts:** Secure registration and login powered by `Flask-Login` and salted password hashing (`werkzeug.security` using scrypt).
- **📋 Paginated Scan History:** Authenticated users can view their complete past scan history, filterable by date, complete with triggered indicators and a one-click clipboard copy feature.
- **📈 Personal Threat Analytics:** An interactive dashboard powered by `Chart.js` displaying:
  - Real-time stat counters (total scans, average risk score, risk level breakdown).
  - A risk distribution doughnut chart (Low vs. Medium vs. High).
  - A 7-day scanning volume bar chart.
- **🔒 Built-in Web Security:** Enforces custom synchronizer-token CSRF protection across all state-changing endpoints, strict HTTP security response headers (CSP, X-Frame-Options, X-Content-Type-Options), and hardened cookies.

---

## ⚙️ How It Works

The scanning pipeline operates in real time across [`detector.py`](detector.py) and [`app.py`](app.py):

```
User submits URL
      │
      ▼
1. Validation & Normalization (app.py / detector.py)
   ├── Reject control characters and whitespace
   ├── Length clamp (max 2048 characters)
   └── Scheme normalization (requires or adds http:// / https://)
      │
      ▼
2. Domain & Path Breakdown (detector.py)
   ├── Split registered domain and multi-part public suffixes
   └── Identify IP hosts vs. domain hosts
      │
      ▼
3. Multi-Check Heuristic Engine (detector.py)
   ├── 9 weighted rules run independently
   └── Collect point contributions and detailed findings
      │
      ▼
4. Score Clamping & Categorization (detector.py)
   ├── Total points clamped to [0, 100]
   ├── Category assignment: Low / Medium / High
   └── Actionable explanation and guidance generated
      │
      ▼
5. Persistence & Delivery (app.py)
   ├── Save record to SQLite database for authenticated user
   └── Return structured JSON payload to the frontend
```

### Heuristic Detection Engine

The 9 rules executed on each URL are:

| # | Heuristic Rule | Max Points | Technical Description |
| :-: | :--- | :-: | :--- |
| **1** | **Transport Security** | `+15` | Flags plain HTTP connections where credentials could be intercepted in transit. |
| **2** | **URL Length** | `+15` | Flags excessively padded URLs (`> 54` chars: `+8`, `> 75` chars: `+15`) often used to disguise malicious destinations. |
| **3** | **IP Address Host** | `+30` | Detects raw IPv4/IPv6 host addresses, a technique commonly used in phishing kits to bypass domain blocklists. |
| **4** | **Subdomain Depth** | `+15` | Counts subdomain depth using public suffix logic (2 subdomains: `+5`, 3 subdomains: `+10`, 4+ subdomains: `+15`). |
| **5** | **Suspicious Keywords** | `+18` | Scans host, path, and query parameters for credential harvesting terms (`login`, `verify`, `banking`, `wallet`, etc.). |
| **6** | **`@` Symbol Obfuscation** | `+25` | Detects the `@` character in the authority portion, which browsers ignore while treating preceding text as user info. |
| **7** | **Host Hyphen Count** | `+15` | Flags repeated hyphens in domain names (e.g. `secure-bank-login-verify.com`) (2–3 hyphens: `+8`, 4+ hyphens: `+15`). |
| **8** | **URL Shorteners** | `+12` | Matches against known URL shortener services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) that conceal the target destination. |
| **9** | **Suspicious Patterns** | `+20` | Identifies Punycode domains (`xn--`), digit-substitution brand lookalikes (e.g., `paypa1`, `g00gle`), risky TLDs, and non-standard web ports. |

### Risk Scoring & Thresholds

Scores from all matching heuristics are summed and clamped to an inclusive range of **0 to 100**:

- **🟢 Low Risk (0–29):** Minimal to no suspicious characteristics detected. Standard browsing caution applies.
- **🟡 Medium Risk (30–69):** Multiple heuristic flags triggered. Users are advised not to enter credentials or download files.
- **🔴 High Risk (70–100):** Strong structural indicators of a phishing campaign. Users are advised to avoid opening the link.

### Zero-Network Guarantee
Unlike sandboxed URL detonators or scraping bots, PhishGuard **never opens a socket connection to the submitted URL**. It does not perform DNS resolution, HTTP GET/POST requests, or headless browser rendering on target links. This makes the tool safe to run without exposure to drive-by downloads or malicious web assets.

---

## 🛠️ Technologies Used

### Backend
- **[Python](https://www.python.org/)** (v3.10+) – Core language
- **[Flask](https://flask.palletsprojects.com/)** (v3.x) – Lightweight web framework, routing, and session management
- **[Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/)** – ORM layer for user and scan data
- **[Flask-Login](https://flask-login.readthedocs.io/)** – User session management and route authorization
- **[Werkzeug](https://palletsprojects.com/p/werkzeug/)** – Security utilities (`generate_password_hash`, `check_password_hash` with scrypt)

### Database
- **[SQLite](https://www.sqlite.org/)** – Embedded relational database for development and single-instance deployments

### Frontend
- **HTML5** – Semantic, accessible page layouts and templates
- **CSS3** – Custom responsive styles, dark modern theme, CSS variables, and keyframe animations
- **JavaScript (ES6+)** – Asynchronous `fetch` calls, dynamic DOM manipulation, form validation, and event handling
- **[Chart.js](https://www.chartjs.org/)** (v4 UMD bundle) – Responsive canvas rendering for personal risk analytics

---

## 📁 Project Structure

```text
PhishGuard/
├── .env.example              # Template for environment variables (PHISHGUARD_SECRET_KEY, FLASK_DEBUG)
├── .gitignore                # Excludes SQLite database, caches, virtual environments, and secrets
├── requirements.txt          # Python package dependencies
├── app.py                    # Flask application, routing, auth, APIs, and security config
├── detector.py               # Rule-based phishing detection engine and scoring algorithms
├── models.py                 # SQLAlchemy database models (User, Scan)
│
├── instance/                 # Local data directory (excluded from git)
│   └── phishguard.db         # Local SQLite database (created on first run)
│
├── static/
│   ├── css/
│   │   └── style.css         # Complete UI stylesheet and animations
│   └── js/
│       ├── analytics.js      # Chart.js rendering for analytics dashboard
│       ├── auth.js           # Password visibility toggles
│       ├── history.js        # Copy-to-clipboard functionality
│       ├── script.js         # Interactive scanner, AJAX submission, animated metrics
│       └── vendor/
│           └── chart.umd.min.js  # Local vendor bundle of Chart.js
│
└── templates/
    ├── base.html             # Common navigation, footer, CSRF meta, and shell
    ├── index.html            # Main landing page and URL scanner
    ├── login.html            # User login view
    ├── register.html         # User registration view
    ├── history.html          # Scan history table view
    ├── analytics.html        # Interactive analytics dashboard view
    └── 404.html              # Custom 404 error page
```

---

## 🚀 Installation & Setup

Follow these instructions to run PhishGuard locally on **Windows**.

### Prerequisites
- **Python 3.10** or higher installed. (Ensure **"Add Python to PATH"** was selected during installation).
- **Git** installed on your system.

### Step-by-Step Setup (Windows)

#### 1. Clone the Repository
Open PowerShell or Command Prompt and clone the project:
```powershell
git clone https://github.com/Rashmi737/PhishGuard.git
cd PhishGuard
```

#### 2. Create a Python Virtual Environment
Creating a virtual environment ensures dependencies remain isolated:
```powershell
python -m venv venv
```

#### 3. Activate the Virtual Environment
Activate the environment in PowerShell:
```powershell
.\venv\Scripts\Activate.ps1
```
*(If PowerShell displays an execution policy error, run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` and retry).*

If using classic Command Prompt (`cmd.exe`), run:
```cmd
venv\Scripts\activate.bat
```

#### 4. Install Dependencies
Install all required packages from `requirements.txt`:
```powershell
pip install -r requirements.txt
```

#### 5. Configure Environment Variables (Optional for Local Dev)
PhishGuard generates a secure random secret key in-memory automatically for local development. However, you can explicitly configure one by copying `.env.example`:

```powershell
Copy-Item .env.example .env
```

Or set the environment variable directly in PowerShell:
```powershell
$env:PHISHGUARD_SECRET_KEY = "your-custom-random-secret-key"
$env:FLASK_DEBUG = "1"
```

#### 6. Run the Application
Launch the Flask development server:
```powershell
python app.py
```

On first startup, PhishGuard automatically initializes the SQLite database schema inside the `instance/` folder.

#### 7. Access in Your Browser
Open your browser and navigate to:
```
http://127.0.0.1:5000
```
- Click **"Create account"** to register a local user profile.
- Log in to begin scanning URLs, inspecting threat indicators, and tracking analytics.

---

## 📸 Application Screenshots

> *Tip: To display screenshots on GitHub, upload your images into a folder named `screenshots/` in this repository and replace the placeholders below.*

### 1. Home Page & Scanner
*The landing interface featuring the live URL submission form, threat landscape statistics, and heuristic engine explanation.*

```
[ Place Home Page Screenshot Here: screenshots/home-page.png ]
```

### 2. URL Scan Results
*Granular breakdown of detected risk indicators, weighted points, risk badge, and recommended action.*

```
[ Place Scan Results Screenshot Here: screenshots/scan-results.png ]
```

### 3. User Authentication (Login & Register)
*Secure sign-in and account registration screens.*

```
[ Place Login Screenshot Here: screenshots/login.png ]
```

### 4. Scan History
*Paginated, user-scoped table containing previous scans with timestamp and one-click copy buttons.*

```
[ Place History Screenshot Here: screenshots/history.png ]
```

### 5. Analytics Dashboard
*Personal threat dashboard showing risk distribution and 7-day scanning volume.*

```
[ Place Analytics Screenshot Here: screenshots/analytics.png ]
```

---

## 🔐 Security & Privacy

PhishGuard incorporates security best practices throughout its architecture:

- **🔒 Environment-Based Secret Keys:** `app.config["SECRET_KEY"]` is decoupled from source code. In production, a missing `PHISHGUARD_SECRET_KEY` halts application boot with a descriptive error.
- **🛡️ Synchronizer-Token CSRF Protection:** Every state-changing form submission (`/login`, `/register`, `/logout`) and AJAX API request (`/scan`) requires a validated CSRF token matching the user's active session.
- **🚫 Complete Database Isolation:** The `instance/` directory and all `.db` / `.sqlite` files are strictly excluded via `.gitignore`. Real user records and test scans are never tracked or committed to version control.
- **⚙️ Safe Debugging Defaults:** Flask's interactive debugger is disabled by default and requires explicit `FLASK_DEBUG=1` environment configuration. It is structurally blocked in production environments.
- **🔑 Password Security:** Passwords are never stored in plaintext. Passwords are validated for complexity and stored as salted hashes using `werkzeug.security` with the scrypt key derivation function.
- **🛡️ Hardened HTTP Headers:** Every response is served with `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and a restrictive `Content-Security-Policy`.
- **🛑 Input Sanitization:** Form input undergoes strict regex validation, URL length capping (max 2048 characters), and request body limits (max 16 KB) to prevent denial-of-service and injection vectors.

---

## 🔮 Future Enhancements

The following features represent realistic planned milestones for future iterations:

- **🤖 Machine Learning Classification:** Integrate a trained classification model (such as Random Forest or LightGBM) trained on PhishTank and Tranco datasets to supplement rule-based heuristics.
- **🌐 Threat Intelligence Feeds:** Incorporate optional, privacy-preserving API lookups (e.g., Google Safe Browsing, VirusTotal, or PhishTank) via server-side background workers.
- **🔒 Live SSL/TLS Certificate Analysis:** Inspect certificate validity, issuer authority, and domain age using an asynchronous worker queue.
- **🧩 Browser Extension:** Build a lightweight Chromium/Firefox extension that queries the PhishGuard API before navigating to newly discovered links.
- **📤 Export Capabilities:** Allow authenticated users to export their scan history as CSV or JSON reports.

---

## 🤝 Contributing

Contributions, feedback, and bug reports are welcome!

1. Fork the repository.
2. Create a new feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Commit your changes with clear messages:
   ```bash
   git commit -m "Add: describe your change"
   ```
4. Push to your branch:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a Pull Request on GitHub.

---

## 📄 License

This project does not currently have a predefined open-source license. A license (e.g., MIT, Apache 2.0) can be added separately by the project owner.

---

## 👩‍💻 Author

**Rashmi**
- GitHub: [@Rashmi737](https://github.com/Rashmi737)
- Project Repository: [PhishGuard on GitHub](https://github.com/Rashmi737/PhishGuard)
