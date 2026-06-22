# Domain Research Tool

A local command-line tool for researching domain names before buying or flipping them.
No API keys or accounts required. Runs entirely on your machine.

---

## Requirements

- Python 3.10 or newer
- No external packages needed (uses Python standard library only)
- Optional: `whois` command-line binary for WHOIS lookups

---

## Setup

1. Download or clone this repository
2. Open a terminal and navigate to the folder:
   ```bash
   cd domain-name-flipping-claude-01
   ```
3. That's it — no install step needed.

---

## How to Run It

### Check if a domain is available (real DNS lookup)

```bash
python domain_research.py check example.com
```

Check multiple domains at once:

```bash
python domain_research.py check aitools.com gofast.me smartpay.ai
```

### Score a domain without checking availability (no internet needed)

Use this for quick offline scoring:

```bash
python domain_research.py score aitools.com
```

### Check a list of domains from a file

Put one domain per line in a text file (see `domains_sample.txt` for an example), then run:

```bash
python domain_research.py bulk domains_sample.txt
```

### WHOIS lookup (requires `whois` to be installed)

```bash
python domain_research.py whois example.com
```

Install `whois` if you don't have it:
- Mac: `brew install whois`
- Linux: `sudo apt install whois`
- Windows: use WSL or skip this command

---

## Saving Results to a File

By default, results print to your terminal. To save them, add `> filename.txt`:

```bash
python domain_research.py bulk domains_sample.txt > results.txt
```

For JSON format (useful for spreadsheets or scripting):

```bash
python domain_research.py bulk domains_sample.txt --json > results.json
```

---

## Understanding the Score

Every domain gets a score from 0 to 100 based on these factors:

| Factor          | Max points | What it measures                        |
|-----------------|------------|-----------------------------------------|
| Length          | 25         | Shorter names score higher              |
| TLD             | 10         | .com=10, .ai=9, .io=8, .net=7, .co=6  |
| Keywords        | 30         | Presence of high-demand words           |
| Pronounceability| 15         | Easy to say = higher score              |
| Hyphens         | -10 each   | Hyphens hurt resale value               |
| Numbers         | -5         | Digits hurt resale value                |

### Score tiers

| Score  | Tier    | What it means                          |
|--------|---------|----------------------------------------|
| 60-100 | Premium | Strong resale candidate                |
| 40-59  | Good    | Worth registering if available         |
| 20-39  | Average | Marginal — depends on niche            |
| 0-19   | Low     | Hard to flip                           |

---

## Availability Note

The availability check uses DNS resolution — if a domain has no DNS record, it is
**likely** available. This is a fast heuristic, not a guarantee. Always confirm
with a registrar (e.g. Namecheap, GoDaddy) before purchasing.

---

## All Commands

```
python domain_research.py check DOMAIN [DOMAIN ...]   # check availability + score
python domain_research.py score DOMAIN                # score only, no DNS
python domain_research.py whois DOMAIN                # WHOIS lookup
python domain_research.py bulk FILE                   # bulk check from file

Options (add to any command):
  --json        Output as JSON
  --no-color    Plain text output (useful when saving to a file)
```
