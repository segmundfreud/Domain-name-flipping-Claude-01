# Domain Research Tool

A local CLI for domain name flipping research. No API keys required.

## Features

- **Availability check** — DNS-based heuristic (no registrar API needed)
- **Value scoring** — 0–100 score based on length, TLD, keywords, pronounceability
- **WHOIS lookup** — parses registrar, expiry, name servers (requires system `whois`)
- **Bulk mode** — process a list of domains from a text file in parallel

## Usage

```bash
# Check a single domain
python domain_research.py check example.com

# Check multiple domains
python domain_research.py check example.com aitools.io smartpay.ai

# Check + WHOIS
python domain_research.py check example.com --whois

# Score only (no DNS lookup)
python domain_research.py score aitools.com

# Bulk check from file
python domain_research.py bulk domains_sample.txt

# JSON output
python domain_research.py check example.com --json
```

## Score Tiers

| Score  | Tier    |
|--------|---------|
| 60–100 | Premium |
| 40–59  | Good    |
| 20–39  | Average |
| 0–19   | Low     |

## Scoring Factors

| Factor          | Max pts | Notes                              |
|-----------------|---------|------------------------------------|
| Length          | 25      | Shorter SLD = higher score         |
| TLD             | 10      | .ai=9, .com=10, .io=8, .net=7 …   |
| Keywords        | 30      | Presence of high-value words       |
| Pronounceable   | 15      | Low consonant/vowel run lengths    |
| Hyphens         | −10 ea  | Each hyphen penalised              |
| Numbers         | −5      | Any digit penalised                |

## Notes

- Availability is checked via DNS resolution — a failed lookup suggests the domain **may** be available, but always confirm with a registrar (Namecheap, GoDaddy, etc.).
- WHOIS requires the `whois` binary (`apt install whois` / `brew install whois`).
