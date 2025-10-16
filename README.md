# 🕷️ jsrip — JavaScript Ripper & Analyzer

`jsrip` is a fast, modular **JavaScript Ripper** built for **bug hunters, red teamers, and researchers**.  
It automatically **crawls**, **downloads**, and **analyzes** JavaScript files to uncover:

- 🔐 Secrets (API keys, tokens, credentials)
- 🌐 API endpoints and URLs
- 📦 Metadata like hashes, sizes, and sources

---

## ✨ Features

- ⚙️ **Headless crawling** using Playwright (Chromium)
- 🌍 Discovers JS from DOM, inline scripts, and network responses
- 💅 Optional JS **beautification** for better regex and readability
- 🔎 Advanced secret-detection regex + entropy heuristics (for less noise/false positives)
- 🧠 Domain-scoped endpoint filtering (keeps in-scope items, unless defined otherwise)
- 🧾 Exports results in **Markdown**, **HTML**, **JSON**, **CSV**, and optional **PDF**
- 📁 Auto-timestamped output folders — no overwriting or clutter
- 🪶 Lightweight, async, and easily scriptable

---

## 🚀 Quick Start

```bash
git clone https://github.com/mouteee/jsrip.git
cd jsrip

# 1️⃣ Create & activate a virtualenv
python3 -m venv venv
source venv/bin/activate

# 2️⃣ Install dependencies
pip install -r requirements.txt

# 3️⃣ Install Chromium (once)
playwright install chromium

# 4️⃣ Run your first scan
python3 jsrip.py -u https://example.com

```

🧰 Example output directory:

```
jsrip_output_20251016_142233/
├─ javascript/
├─ reports/
│  ├─ report.md
│  ├─ report.json
│  ├─ report.html
│  ├─ secrets.csv
│  ├─ endpoints.csv
│  └─ js_files.csv
└─ jsrip.log
```

---

## 🧩 CLI Usage

### Scan a single target
```bash
python3 jsrip.py -u https://example.com
```

### Scan multiple targets from file
```bash
python3 jsrip.py -l targets.txt
```

### Save results to a custom folder
```bash
python3 jsrip.py -u https://example.com -o ./reports/example_scan
```

### Generate multiple report formats
```bash
python3 jsrip.py -u https://example.com -f md html json csv
```

### Run non-headless (see browser behavior)
```bash
python3 jsrip.py -u https://example.com --no-headless
```

### Add headers, cookies, and custom UA
```bash
python3 jsrip.py -u https://example.com   --headers headers.json   --cookies cookies.json   --user-agent "MyCustomScanner/1.0"
```

---

## ⚙️ Options Overview

| Flag | Description |
|------|--------------|
| **`-u, --url URL`** | Single target URL to analyze |
| **`-l, --list FILE`** | File with URLs (one per line) |
| **`-o, --output DIR`** | Custom output directory (default: auto timestamped) |
| **`-f, --format {json,md,html,csv,pdf}`** | Output report formats (default: `json md`) |
| **`--headless / --no-headless`** | Run browser in headless or visible mode |
| **`--max-depth N`** | Crawl depth (default: `2`) |
| **`--max-pages N`** | Max pages to visit (default: `500`) |
| **`--timeout SECONDS`** | Page load timeout (default: `30`) |
| **`--no-beautify`** | Skip JS beautification |
| **`--entropy-threshold F`** | Minimum entropy for random-looking secrets (default: `2.5`) |
| **`--min-secret-length N`** | Minimum secret length to flag (default: `8`) |
| **`--include-external-endpoints`** | Include endpoints outside target’s base domain |
| **`--headers FILE`** | JSON file of extra headers (e.g., `{ "Authorization": "Bearer ...", "Referer": "..." }`) |
| **`--cookies FILE`** | JSON file of cookies |
| **`--user-agent UA`** | Override default UA string |
| **`-v, --verbose`** | Verbose logging (prints detailed crawl + analysis info) |

> 🧩 Example: `python3 jsrip.py -u https://site.com -f html json --entropy-threshold 3.0 --include-external-endpoints`

---

## 🧠 How It Works

1. **Crawler (Playwright)**
   - Launches Chromium (headless by default)
   - Visits URLs recursively
   - Captures JS URLs from:
     - `<script src>` tags
     - Network requests (XHR, fetch, imports)
     - Inline script blocks
   - Saves all JS in `/javascript/`

2. **Analyzer**
   - Beautifies JS for consistent regex parsing
   - Removes base64 blobs and images
   - Scans with hundreds of regexes for:
     - Tokens, keys, credentials
     - API endpoints & URLs
   - Filters low-entropy or false positives
   - Deduplicates results globally

3. **Reporter**
   - Aggregates findings
   - Exports to Markdown, JSON, CSV, HTML (and PDF if `weasyprint` available)
   - Generates per-file and global summaries

---

## 📦 Requirements

- **Python ≥ 3.9**
- **Chromium** via Playwright

### Install manually
```bash
pip install -r requirements.txt
playwright install chromium
```

### Or use the provided installer
```bash
bash setup.sh
```

---

## 🧰 requirements.txt

```txt
playwright>=1.40.0
aiohttp>=3.9.0
jsbeautifier>=1.14.0
markdown>=3.5.0
weasyprint>=60.0
colorama>=0.4.6
```

---

## 🗂️ Project Structure

```
jsrip/
├─ core/
│  ├─ analyzer.py        # Secret & endpoint analysis
│  ├─ crawler.py         # Playwright-based crawler
│  └─ patterns.py        # Regex definitions for secret detection
│
├─ utils/
│  ├─ logger.py          # Logging helpers
│  └─ reporter.py        # Report generation (md, html, csv, pdf)
│
├─ jsrip.py              # CLI entry point
├─ requirements.txt
├─ setup.sh              # Optional installer
└─ README.md
```

---

## ⚠️ Troubleshooting

| Problem | Fix |
|----------|-----|
| `playwright install` errors | Try `python -m playwright install chromium` |
| Browser won’t start | Ensure `venv` is active and Chromium installed |
| PDF not generated | Install `weasyprint` or `pandoc` |
| Too few JS files found | Use `--no-headless` and manually interact with dynamic sites |
| False positives | Raise `--entropy-threshold` or skip beautify with `--no-beautify` |

---

## 🛡️ Legal & Ethics

Use `jsrip` **only on systems you have permission to test**.  
The author and contributors assume **no responsibility** for misuse or damage.

---

## 🙏 Acknowledgments

This project uses and builds upon the excellent **[Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db)** by [@mazen160](https://github.com/mazen160),  
which provides a comprehensive collection of regular expressions for detecting secrets and API keys.  
Huge thanks to his work for helping improve the accuracy of secret detection in `jsrip`.
