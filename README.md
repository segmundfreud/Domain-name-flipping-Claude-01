# Domain Research Tool

A local command-line tool for researching and flipping domain names.
No external packages required — runs on Python 3.10+ standard library only.

---

## Requirements

- Python 3.10 or newer
- No pip installs needed
- Optional: `whois` binary for WHOIS lookups (`apt install whois` / `brew install whois`)

---

## Setup

```bash
git clone https://github.com/segmundfreud/Domain-name-flipping-Claude-01.git
cd Domain-name-flipping-Claude-01
```

That's it. No virtual environment or installs needed.

---

## Generate Command (main workflow)

### With a market preset (recommended)

```bash
python domain_research.py generate --preset ai-saas --count 100 --tld .com --check true
```

**When `--check true` is used, the pipeline is:**
1. Generate all candidate domain names
2. Apply basic local filters (no hyphens, no numbers, max 15 chars, remove trademark-risk words)
3. **Check availability first** — via DNS or Spaceship API
4. **Score only available domains** — taken domains are never scored
5. Print available domains sorted by score
6. Optionally show taken domains as an unscored inspiration section

> **Note:** When availability checking is enabled, the tool scores only available domains.
> Scoring taken domains wastes time and produces misleading results.

---

### Available presets

| Preset | Buyer Intent |
|---|---|
| `ai-saas` | very high |
| `fintech` | very high |
| `cybersecurity` | high |
| `healthtech` | high |
| `legaltech` | high |
| `realestate-tech` | high |
| `hr-recruiting` | high |
| `sales-automation` | very high |
| `creator-tools` | medium |
| `analytics-data` | high |
| `ecommerce-tools` | high |
| `productivity` | medium |

---

### Show taken domains as inspiration

```bash
python domain_research.py generate --preset fintech --count 50 --tld .com --check true --show-taken
```

---

### Choose availability provider

```bash
# DNS (default, free, heuristic)
python domain_research.py generate --preset ai-saas --count 50 --tld .com --check true --availability-provider dns

# Spaceship API (accurate, requires credentials)
python domain_research.py generate --preset ai-saas --count 50 --tld .com --check true --availability-provider spaceship
```

To use the Spaceship provider, set these environment variables before running:

```bash
export SPACESHIP_API_KEY=your_key_here
export SPACESHIP_API_SECRET=your_secret_here
```

Get credentials at: https://www.spaceship.com/api/

If the credentials are missing, the tool automatically falls back to DNS.

---

### Without availability check (score all candidates)

```bash
python domain_research.py generate --preset ai-saas --count 50 --tld .com
```

Scores all generated candidates without checking availability. Faster but less useful for flipping.

---

### Manual mode (custom niche and market)

```bash
python domain_research.py generate --niche "fitness app" --market "US" --style "short brandable" --count 30 --tld .io --check true
```

---

## Other Commands

### Check a specific domain

```bash
python domain_research.py check example.com
python domain_research.py check aitools.com gofast.me smartpay.ai
```

### Score a domain offline (no DNS)

```bash
python domain_research.py score aitools.com
```

### Bulk check from a file (one domain per line)

```bash
python domain_research.py bulk domains_sample.txt
```

### WHOIS lookup

```bash
python domain_research.py whois example.com
python domain_research.py whois example.com --raw
```

---

## Saving Results

```bash
python domain_research.py generate --preset ai-saas --count 100 --tld .com --check true --no-color > results.txt
python domain_research.py generate --preset ai-saas --count 100 --tld .com --check true --json > results.json
```

---

## Understanding the Score

Domains are scored 0–100 based on:

| Factor | Max pts | Notes |
|---|---|---|
| Length | 25 | Shorter = higher |
| TLD | 10 | .com=10, .ai=9, .io=8, .net=7 |
| Keywords | 30 | Presence of high-value words |
| Pronounceability | 15 | Easy to say aloud |
| Hyphens | -10 each | Hurt resale value |
| Numbers | -5 | Hurt resale value |

| Score | Tier | Meaning |
|---|---|---|
| 60–100 | Premium | Strong resale candidate |
| 40–59 | Good | Worth registering if available |
| 20–39 | Average | Marginal |
| 0–19 | Low | Hard to flip |

---

## Trademark Filter

The generator automatically removes any domain containing high-risk trademark terms:
`gpt`, `openai`, `google`, `meta`, `apple`, `tesla`, `microsoft`, `amazon`, `nvidia`,
`anthropic`, `claude`, `chatgpt`, `copilot`, and others.

---

## Availability Note

DNS-based availability is a heuristic — a failed DNS lookup suggests a domain *may* be
available, but always confirm with a registrar (Namecheap, GoDaddy, Spaceship) before purchasing.
The Spaceship API provider gives more accurate results when credentials are configured.

---

## All Flags for `generate`

```
--preset              Market preset name (see list above)
--niche               Manual mode: niche description
--market              Manual mode: target market/city
--style               Manual mode: style hint (default: "premium short")
--count               Number of results to show (default: 20)
--tld                 TLD to append (default: .com)
--check               Check availability before scoring (true/false)
--availability-provider  dns (default) or spaceship
--show-taken          Show taken domains as unscored inspiration section
--json                Output as JSON
--no-color            Plain text output (useful when redirecting to a file)
```
