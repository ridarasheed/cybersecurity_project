# 🛡️ PhishGuard AI — Phishing Email Detection System

A beginner-friendly, interactive web application that analyses email text for
phishing indicators and assigns a transparent, explainable risk score.
Built with Python and Streamlit.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement and Objectives](#2-problem-statement-and-objectives)
3. [Features](#3-features)
4. [Technology Stack](#4-technology-stack)
5. [Project Structure](#5-project-structure)
6. [Installation and Setup](#6-installation-and-setup)
7. [Running the Application](#7-running-the-application)
8. [How to Analyse an Email](#8-how-to-analyse-an-email)
9. [Interpreting the Risk Score](#9-interpreting-the-risk-score)
10. [Sample Email Dataset](#10-sample-email-dataset)
11. [Current Limitations](#11-current-limitations)
12. [Future Improvements](#12-future-improvements)

---

## 1. Project Overview

PhishGuard AI is a cybersecurity learning and awareness tool that lets users
paste the subject and body of any email and instantly receive a rule-based
risk assessment. The application shows:

- A **risk score** from 0 to 100.
- A **risk classification** — Low, Medium, or High Risk.
- **Detected indicators** — plain-English explanations of every suspicious
  pattern found in the text.
- A **disclaimer** making clear that the result is an estimate, not a guarantee.

The entire detection engine is written in plain Python with no machine-learning
library required. All analysis is read-only text pattern matching — no links
are visited, no attachments are opened, and no network requests are made.

---

## 2. Problem Statement and Objectives

**Problem:**  
Phishing emails remain the most common entry point for data breaches and
cyber-attacks. Many users cannot reliably identify phishing attempts, especially
when attackers impersonate trusted brands or use urgency and fear tactics.

**Objectives:**

- Provide a clear, interactive tool for identifying common phishing patterns.
- Make the detection logic fully **transparent and explainable** — every flagged
  indicator is shown alongside a plain-English description.
- Keep the codebase simple enough for beginners to read, understand, and extend.
- Serve as a practical cybersecurity awareness and educational resource.

---

## 3. Features

| Feature | Description |
|---|---|
| **Email Analyser** | Paste a subject and body, click Analyse, and see an instant risk result |
| **Risk Score** | Integer score 0–100 with a visual gauge bar |
| **Risk Classification** | Low / Medium / High Risk with colour coding |
| **Indicator Cards** | Each matched rule is shown with its name, point contribution, and explanation |
| **Risk Disclaimer** | Permanent notice that results are estimates, not guarantees |
| **Dashboard Cards** | Live counts of total, high-risk, medium-risk, and low-risk emails |
| **Visualisation Charts** | Donut chart (risk distribution) and bar chart (count per level) |
| **High Risk Alert Panel** | Dedicated alert section listing every High Risk email analysed this session |
| **Analysis History Table** | Full table of every email analysed, newest first, with score and indicators |
| **Clear History** | Two-step confirmed button to wipe the session history |
| **Sample Email Dataset** | 22 pre-written fictional emails (10 phishing, 5 suspicious, 7 safe) for testing |
| **Dark Theme** | Full dark cybersecurity dashboard aesthetic |

---

## 4. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Language | Python 3.9+ | Core application logic |
| Web Framework | [Streamlit](https://streamlit.io) | Interactive web UI, no HTML/JS required |
| Charts | [Plotly](https://plotly.com/python/) | Interactive donut and bar charts |
| Detection Engine | Python `re` (built-in) | Regex-based phishing rule matching |
| Styling | Custom CSS (injected via Streamlit) | Dark cybersecurity theme |

No database, no external API, no machine-learning framework is required.

---

## 5. Project Structure

```
cybersec_project/
│
├── app.py              ← Entire application (detection engine + UI)
└── requirements.txt    ← Python dependencies
```

The application is intentionally kept in a single file so beginners can read
from top to bottom and understand each section in order:

| Section in `app.py` | Contents |
|---|---|
| Module docstring | How-to-run instructions and design overview |
| **DETECTION ENGINE** | `RULES` list, `_check_brand_impersonation()`, `analyse_email()` |
| **SAMPLE EMAIL DATASET** | 22 fictional test emails and `CATEGORY_META` mapping |
| **CHART HELPERS** | `make_risk_distribution_chart()`, `make_risk_bar_chart()` |
| **STREAMLIT PAGE SETUP** | `set_page_config`, CSS, session state, and all page layout code |

---

## 6. Installation and Setup

### Prerequisites

- **Python 3.9 or newer** — download from [python.org](https://www.python.org/downloads/)
- **pip** — included with Python

### Step 1 — Clone or download the project

```bash
# If you have Git installed:
git clone <your-repository-url>
cd cybersec_project

# Or simply download and unzip the project folder, then open a terminal there.
```

### Step 2 — (Recommended) Create a virtual environment

A virtual environment keeps the project's packages separate from your system Python.

```bash
# Create the environment
python -m venv venv

# Activate it — Windows (Command Prompt / PowerShell):
venv\Scripts\activate

# Activate it — macOS / Linux:
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs exactly two packages: `streamlit` and `plotly`.

---

## 7. Running the Application

```bash
streamlit run app.py
```

Streamlit will print a local URL (usually `http://localhost:8501`) and open it
in your default browser automatically.

To stop the application press **Ctrl + C** in the terminal.

---

## 8. How to Analyse an Email

1. Open the app in your browser.
2. Scroll to the **📧 Analyse an Email** section.
3. Paste the email **subject line** into the *Email Subject* field.
4. Paste the full **email body** into the *Email Body* text area.
5. Click **🔍 Analyze Email**.

The page will reload and the results appear immediately in the
**📋 Analysis Results** section directly below.

> **Tip:** You can test with one of the 22 pre-written emails.  
> Click **⚡ Generate Sample Emails** at the bottom of the page and copy any
> subject and body into the input fields.

---

## 9. Interpreting the Risk Score

### Score thresholds

| Score | Risk Level | Meaning |
|---|---|---|
| 0 – 39 | 🟢 **Low Risk** | No strong phishing indicators found. The email appears safe, but always apply your own judgement. |
| 40 – 69 | 🟡 **Medium Risk** | Some suspicious patterns detected. Treat the email with caution. Do not click links or open attachments until you can verify the sender. |
| 70 – 100 | 🔴 **High Risk** | Multiple strong phishing indicators detected. Do not interact with this email. Report it to your IT or security team. |

### How the score is calculated

The engine checks the combined subject and body text against **9 independent rules**.
Each rule that matches adds a fixed number of points:

| Rule | Points |
|---|---|
| Urgency / pressure language | +15 |
| Account suspension threat | +20 |
| Requests sensitive credentials (password, OTP, SSN…) | +30 |
| Suspicious URL pattern (HTTP, IP address, lookalike domain…) | +25 |
| Unsolicited offer with unencrypted HTTP link | +20 |
| Prize or reward claim | +25 |
| Click-to-verify or update request | +15 |
| Unexpected attachment mentioned | +15 |
| Possible brand impersonation (brand name with no official domain) | +20 |

The total is **capped at 100**. A single rule match is usually not enough to
reach High Risk — multiple indicators must accumulate.

### Important disclaimer

The risk score is an automated estimate based on text patterns only.
Legitimate emails sometimes contain urgency language or verification links.
Sophisticated phishing emails may avoid all these patterns.
**Always apply your own judgement** and contact your organisation's security
team if you are unsure.

---

## 10. Sample Email Dataset

The **⚡ Generate Sample Emails** button loads 22 pre-written fictional emails
designed to represent realistic examples of each category.

| Category | Count | Examples |
|---|---|---|
| 🔴 **Phishing** | 10 | Bank account verification scams, prize scams, lookalike-domain credential harvesting, BEC payroll fraud, IRS impersonation, parcel fee scams |
| 🟡 **Suspicious** | 5 | Unsolicited marketing with HTTP links, unbranded login-alert emails, unrealistic investment offers, reward surveys, unknown service verification |
| 🟢 **Safe** | 7 | Order shipping confirmations, internal meeting notes, bank statements, GitHub password reset, newsletters, personal party invitations, flight bookings |

All email data is **entirely fabricated** for educational purposes.
No real people's information is used. No domain listed is a real phishing site.
The URLs in the sample bodies are fictional and have never been visited by the application.

Generating the sample data updates the **dashboard cards** and **charts** to
reflect the full dataset of 22 emails.

---

## 11. Current Limitations

- **Text patterns only** — the engine cannot follow or analyse URLs, so a
  convincing phishing email that avoids all keyword patterns will score 0.
- **No sender verification** — the app has no access to email headers, DKIM
  signatures, SPF records, or DMARC results, which are important real-world
  signals.
- **No machine learning** — the rules are hand-written. A trained classifier
  would generalise better to unseen phishing variants.
- **Session state only** — analysis history is stored in the browser session
  and is lost when the page is refreshed or the server is restarted.
- **English language only** — all rules are written for English text.
- **Single-user, local only** — the app runs locally for one user. It is not
  production-ready for multi-user or public deployment without additional
  security hardening.

---

## 12. Future Improvements

- **Machine learning model** — train a text classifier (e.g. a fine-tuned BERT
  or a Naive Bayes model) on a labelled phishing dataset for higher accuracy.
- **URL analysis** — safely extract and analyse URLs using a sandboxed tool or
  a threat-intelligence API (e.g. VirusTotal) without visiting them directly.
- **Email header parsing** — accept raw `.eml` files and inspect SPF, DKIM,
  DMARC, and `Received` headers for sender-authenticity signals.
- **Persistent history** — store analysis results in a local SQLite database so
  history survives page refreshes.
- **Export** — add a button to download the analysis history as a CSV or PDF
  report.
- **Multi-language support** — extend the rule set to cover phishing patterns in
  other languages.
- **Confidence intervals** — show a confidence range alongside the score rather
  than a single integer.
- **User feedback loop** — let users mark results as correct or incorrect to
  improve the rule set over time.

---

*PhishGuard AI · Built with Python & Streamlit · For educational purposes only*
