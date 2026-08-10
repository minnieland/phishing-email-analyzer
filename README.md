# Phishing Email Analyzer

A Python SOC triage tool that analyzes raw phishing email files (`.eml`) end-to-end: parse headers and IOCs, enrich with free threat-intel APIs, score risk, and print a Markdown report for analysts.

## What it does

1. **Parses** a raw `.eml` with Python’s built-in `email` + `re` libraries  
2. **Extracts** headers, auth results (SPF/DKIM/DMARC), originating IP, URLs, domains, IPv4s, and attachment SHA256 hashes  
3. **Enriches** IOCs via VirusTotal (hashes/URLs) and AbuseIPDB (origin IP)  
4. **Scores** risk from 0–100 and classifies as Low Risk / Suspicious / Malicious  
5. **Reports** a SOC-style Markdown summary to the console and writes `analysis_output.json`

## Project layout

```
phishing-email-analyzer/
├── main.py           # CLI entry point
├── config.py         # API key placeholders + scoring thresholds
├── parser.py         # .eml parsing + IOC extraction
├── enrichment.py     # VirusTotal + AbuseIPDB connectors
├── scorer.py         # Risk score engine
├── reporter.py       # Markdown + JSON output
├── samples/          # Demo .eml files for testing
├── requirements.txt
└── .env.example      # Copy to .env and add your keys
```

## Requirements

- Python 3.10+
- Optional API keys (free tiers work):
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey) → `VT_API_KEY`
  - [AbuseIPDB](https://www.abuseipdb.com/account/api) → `ABUSEIPDB_API_KEY`

## Setup

```bash
git clone https://github.com/<your-username>/phishing-email-analyzer.git
cd phishing-email-analyzer

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env and paste your API keys
```

## Usage

### Analyze a sample phishing email (offline, no API calls)

```bash
python main.py samples/sample_phish.eml --skip-enrichment
```

### Analyze with live VirusTotal + AbuseIPDB enrichment

```bash
python main.py samples/sample_phish.eml
```

### Analyze your own `.eml` (quote paths with spaces)

```bash
python main.py "/Users/you/Downloads/suspicious-message.eml"
python main.py "/Users/you/Downloads/suspicious-message.eml" -o my_report.json
```

### CLI options

| Option | Description |
| --- | --- |
| `eml_file` | Path to the `.eml` file (required) |
| `-o`, `--output` | JSON output path (default: `analysis_output.json`) |
| `--skip-enrichment` | Parse + score only; skip VT / AbuseIPDB |

## How to get a `.eml` from your inbox

- **Apple Mail:** select the message → drag to Desktop, or **File → Save As…** (raw/source)
- **Gmail:** open message → ⋮ → **Show original** → **Download original**, then rename/use as `.eml`
- **Outlook:** save/export as MIME / `.eml`, or drag the message to Finder when supported

## Risk scoring

| Condition | Points |
| --- | --- |
| SPF / DKIM / DMARC failure | +30 |
| AbuseIPDB confidence score > 50% | +25 |
| VirusTotal detections > 3 engines | +35 |
| From domain ≠ Return-Path domain | +15 |

| Score | Classification |
| --- | --- |
| 0–29 | Low Risk |
| 30–60 | Suspicious |
| 61–100 | Malicious |

## Example output

The tool prints a Markdown report with:

- Verdict + risk score  
- Header summary (From, Return-Path, auth, originating IP)  
- Score breakdown  
- Enriched IOC table  
- Recommended remediation steps  

Full structured results are saved to `analysis_output.json` (gitignored).

## Demo samples

| File | Expected offline result |
| --- | --- |
| `samples/sample_phish.eml` | Suspicious (~45) — auth fail + sender mismatch |
| `samples/sample_benign.eml` | Low Risk (0) — aligned sender, auth pass |

> Note: demo IOCs are synthetic (documentation IPs / fake domains), so VirusTotal and AbuseIPDB may return empty/zero even when API keys work. Use a real suspicious `.eml` to exercise enrichment.

## Safety notes

- Never commit your `.env` file (already in `.gitignore`)
- Treat unknown attachments as hostile; this tool hashes them but does not execute them
- API free tiers have rate limits; the client handles HTTP 429 responses gracefully

## License

Use and modify freely for personal / defensive security research.
