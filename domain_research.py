#!/usr/bin/env python3
"""Domain research CLI for domain name flipping."""

import argparse
import socket
import sys
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Value scoring
# ---------------------------------------------------------------------------

PREMIUM_TLDS = {".com": 10, ".net": 7, ".io": 8, ".ai": 9, ".co": 6, ".org": 5}
COMMON_TLDS = {".info": 2, ".biz": 2, ".us": 3, ".me": 4, ".app": 6, ".dev": 6}

HIGH_VALUE_KEYWORDS = {
    "ai", "app", "cloud", "shop", "pay", "buy", "sell", "market", "store",
    "trade", "tech", "lab", "hub", "link", "pro", "go", "get", "my",
    "smart", "fast", "easy", "best", "top", "now", "live", "data",
    "web", "net", "digital", "media", "news", "health", "fit", "edu",
    "finance", "money", "cash", "crypto", "nft", "meta", "auto", "bot",
}


def _split_sld(domain: str) -> tuple[str, str]:
    """Return (sld, tld) from a domain string."""
    parts = domain.lower().split(".", 1)
    sld = parts[0]
    tld = f".{parts[1]}" if len(parts) > 1 else ""
    return sld, tld


@dataclass
class ScoreBreakdown:
    length: int = 0
    tld: int = 0
    keywords: int = 0
    pronounceable: int = 0
    hyphens: int = 0
    numbers: int = 0
    total: int = 0
    tier: str = ""


def score_domain(domain: str) -> ScoreBreakdown:
    sld, tld = _split_sld(domain)
    b = ScoreBreakdown()

    # Length scoring (shorter = better)
    ln = len(sld)
    if ln <= 4:
        b.length = 25
    elif ln <= 6:
        b.length = 20
    elif ln <= 8:
        b.length = 15
    elif ln <= 12:
        b.length = 10
    else:
        b.length = max(0, 10 - (ln - 12))

    # TLD scoring
    b.tld = PREMIUM_TLDS.get(tld, COMMON_TLDS.get(tld, 1))

    # Keyword scoring
    for kw in HIGH_VALUE_KEYWORDS:
        if kw in sld:
            b.keywords = min(b.keywords + 8, 30)

    # Pronounceability heuristic (alternating consonant/vowel patterns score higher)
    vowels = set("aeiou")
    runs = 0
    max_run = 0
    cur_run = 0
    prev_is_vowel = None
    for ch in sld:
        is_vowel = ch in vowels
        if is_vowel == prev_is_vowel:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1
        prev_is_vowel = is_vowel
    if max_run <= 2:
        b.pronounceable = 15
    elif max_run == 3:
        b.pronounceable = 8
    else:
        b.pronounceable = 2

    # Penalties
    if "-" in sld:
        b.hyphens = -10 * sld.count("-")
    if any(c.isdigit() for c in sld):
        b.numbers = -5

    b.total = max(0, b.length + b.tld + b.keywords + b.pronounceable + b.hyphens + b.numbers)

    if b.total >= 60:
        b.tier = "Premium"
    elif b.total >= 40:
        b.tier = "Good"
    elif b.total >= 20:
        b.tier = "Average"
    else:
        b.tier = "Low"

    return b


# ---------------------------------------------------------------------------
# Availability check via DNS
# ---------------------------------------------------------------------------

def check_availability(domain: str) -> tuple[bool, str]:
    """
    Returns (available, note).
    Available means DNS resolution failed (NXDOMAIN-like) — the domain likely
    isn't registered. This is a heuristic; always verify with a registrar.
    """
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(domain, None)
        return False, "Registered (resolves via DNS)"
    except socket.gaierror as e:
        code = e.args[0]
        # NXDOMAIN / no such host
        if code in (socket.EAI_NONAME, -2, -3, 11001, 11004):
            return True, "Likely available (no DNS record found)"
        return False, f"Unknown DNS error ({e})"
    except OSError:
        return False, "Network error during DNS lookup"


# ---------------------------------------------------------------------------
# WHOIS via system whois binary (optional)
# ---------------------------------------------------------------------------

def whois_lookup(domain: str) -> Optional[str]:
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _parse_whois_fields(raw: str) -> dict:
    fields = {}
    patterns = {
        "Registrar": r"(?i)Registrar:\s*(.+)",
        "Expiry Date": r"(?i)(?:Registry Expiry Date|Expiration Date|paid-till):\s*(.+)",
        "Created": r"(?i)(?:Creation Date|Created On|created):\s*(.+)",
        "Name Servers": r"(?i)Name Server:\s*(.+)",
        "Status": r"(?i)Domain Status:\s*(.+)",
    }
    for label, pattern in patterns.items():
        matches = re.findall(pattern, raw)
        if matches:
            fields[label] = matches[0].strip() if len(matches) == 1 else [m.strip() for m in matches[:3]]
    return fields


# ---------------------------------------------------------------------------
# Bulk analysis
# ---------------------------------------------------------------------------

def analyze_domain(domain: str, whois: bool = False) -> dict:
    domain = domain.lower().strip()
    avail, avail_note = check_availability(domain)
    score = score_domain(domain)
    sld, tld = _split_sld(domain)

    result = {
        "domain": domain,
        "available": avail,
        "availability_note": avail_note,
        "sld": sld,
        "tld": tld,
        "length": len(sld),
        "score": score.total,
        "tier": score.tier,
        "score_breakdown": {
            "length": score.length,
            "tld": score.tld,
            "keywords": score.keywords,
            "pronounceable": score.pronounceable,
            "hyphens": score.hyphens,
            "numbers": score.numbers,
        },
    }

    if whois:
        raw = whois_lookup(domain)
        if raw:
            result["whois"] = _parse_whois_fields(raw)
            result["whois_raw"] = raw
        else:
            result["whois"] = None

    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

TIER_COLORS = {
    "Premium": "\033[92m",   # green
    "Good": "\033[93m",      # yellow
    "Average": "\033[94m",   # blue
    "Low": "\033[91m",       # red
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _tier_colored(tier: str) -> str:
    return f"{TIER_COLORS.get(tier, '')}{tier}{RESET}"


def print_single(result: dict, no_color: bool = False) -> None:
    def c(text, code=""):
        return text if no_color else f"{code}{text}{RESET}"

    print()
    print(c(f"  Domain : {result['domain']}", BOLD))
    avail_label = "YES (likely available)" if result["available"] else "NO (registered)"
    avail_color = "\033[92m" if result["available"] else "\033[91m"
    print(f"  Available : {c(avail_label, avail_color)}")
    print(f"  Note      : {result['availability_note']}")
    print()

    tier = result["tier"]
    score = result["score"]
    tier_str = tier if no_color else f"{TIER_COLORS.get(tier,'')}{tier}{RESET}"
    print(c(f"  Value Score : {score}/100  [{tier_str}]", BOLD))
    bd = result["score_breakdown"]
    print(f"    Length ({result['length']} chars) : +{bd['length']}")
    print(f"    TLD ({result['tld']})            : +{bd['tld']}")
    print(f"    Keywords                  : +{bd['keywords']}")
    print(f"    Pronounceability          : +{bd['pronounceable']}")
    if bd["hyphens"]:
        print(f"    Hyphens penalty           :  {bd['hyphens']}")
    if bd["numbers"]:
        print(f"    Numbers penalty           :  {bd['numbers']}")

    if "whois" in result and result["whois"]:
        print()
        print(c("  WHOIS Summary:", BOLD))
        for k, v in result["whois"].items():
            if isinstance(v, list):
                print(f"    {k}: {', '.join(v)}")
            else:
                print(f"    {k}: {v}")
    print()


def print_bulk_table(results: list[dict], no_color: bool = False) -> None:
    def c(text, code=""):
        return text if no_color else f"{code}{text}{RESET}"

    header = f"{'Domain':<35} {'Avail':<7} {'Score':<7} {'Tier':<10} {'TLD':<8} {'Len'}"
    print()
    print(c(header, BOLD))
    print("-" * 75)
    for r in sorted(results, key=lambda x: -x["score"]):
        avail = "YES" if r["available"] else "no"
        avail_col = "\033[92m" if r["available"] else "\033[91m"
        tier_col = TIER_COLORS.get(r["tier"], "")
        print(
            f"{r['domain']:<35} "
            f"{c(avail, avail_col):<17} "
            f"{r['score']:<7} "
            f"{c(r['tier'], tier_col):<20} "
            f"{r['tld']:<8} "
            f"{r['length']}"
        )
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_check(args):
    domains = args.domains
    whois = getattr(args, "whois", False)

    if len(domains) == 1:
        result = analyze_domain(domains[0], whois=whois)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_single(result, no_color=args.no_color)
    else:
        results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(analyze_domain, d, whois): d for d in domains}
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    print(f"Error processing {futures[fut]}: {e}", file=sys.stderr)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print_bulk_table(results, no_color=args.no_color)


def cmd_score(args):
    domain = args.domain
    score = score_domain(domain)
    sld, tld = _split_sld(domain)
    result = {
        "domain": domain,
        "score": score.total,
        "tier": score.tier,
        "breakdown": {
            "length": score.length,
            "tld": score.tld,
            "keywords": score.keywords,
            "pronounceable": score.pronounceable,
            "hyphens": score.hyphens,
            "numbers": score.numbers,
        }
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_single({
            "domain": domain,
            "available": None,
            "availability_note": "(availability not checked)",
            "sld": sld,
            "tld": tld,
            "length": len(sld),
            "score": score.total,
            "tier": score.tier,
            "score_breakdown": result["breakdown"],
        }, no_color=args.no_color)


def cmd_whois(args):
    raw = whois_lookup(args.domain)
    if raw is None:
        print("whois not available (is the `whois` binary installed?)", file=sys.stderr)
        sys.exit(1)
    if args.raw:
        print(raw)
    else:
        fields = _parse_whois_fields(raw)
        if args.json:
            print(json.dumps({"domain": args.domain, "whois": fields}, indent=2))
        else:
            print(f"\n  WHOIS for {args.domain}\n")
            for k, v in fields.items():
                if isinstance(v, list):
                    print(f"  {k}: {', '.join(v)}")
                else:
                    print(f"  {k}: {v}")
            print()


def cmd_bulk(args):
    with open(args.file) as fh:
        domains = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    args.domains = domains
    cmd_check(args)


# ---------------------------------------------------------------------------
# Domain generator
# ---------------------------------------------------------------------------

# Niche synonym map — extend as needed
NICHE_SYNONYMS: dict[str, list[str]] = {
    "barber":   ["barber", "blade", "fade", "trim", "clipper", "razor", "groom", "shave"],
    "shop":     ["shop", "studio", "lounge", "spot", "den", "place", "room"],
    "hair":     ["hair", "cut", "style", "curl", "mane", "lock"],
    "salon":    ["salon", "style", "beauty", "glam", "chic", "lux"],
    "food":     ["food", "eat", "bite", "taste", "chef", "dish", "meal", "feast"],
    "cafe":     ["cafe", "brew", "bean", "roast", "cup", "drip", "sip"],
    "fitness":  ["fit", "gym", "lift", "strong", "flex", "burn", "sweat"],
    "tech":     ["tech", "code", "dev", "byte", "stack", "logic", "digital"],
    "real":     ["real", "home", "nest", "dwelling", "property", "abode"],
    "estate":   ["estate", "home", "nest", "realty", "haven", "land"],
    "travel":   ["travel", "trip", "roam", "voyage", "trek", "fly", "wander"],
    "fashion":  ["fashion", "style", "vogue", "wear", "thread", "drip", "look"],
    "law":      ["law", "legal", "counsel", "justice", "firm", "rights"],
    "health":   ["health", "care", "well", "vital", "cure", "med", "life"],
    "pet":      ["pet", "paw", "tail", "fur", "bark", "vet", "critter"],
    "photo":    ["photo", "lens", "frame", "shot", "pixel", "snap", "click"],
    "music":    ["music", "beat", "sound", "tune", "track", "wave", "note"],
    "market":   ["market", "trade", "deal", "store", "hub", "cart", "bazaar"],
}

BRANDABLE_PREFIXES = [
    "go", "my", "get", "be", "the", "top", "pro", "vip", "one",
    "try", "now", "new", "we", "hey", "hi", "just", "ultra",
]

BRANDABLE_SUFFIXES = [
    "hub", "pro", "hq", "lab", "co", "zone", "spot", "club",
    "plus", "now", "bay", "base", "way", "box", "ify", "ly",
    "app", "nest", "den", "house", "place", "point", "works",
]


def _extract_words(phrase: str) -> list[str]:
    """Split a phrase into lowercase tokens, expand via synonym map."""
    tokens = re.findall(r"[a-z]+", phrase.lower())
    expanded: list[str] = []
    for tok in tokens:
        expanded.append(tok)
        expanded.extend(NICHE_SYNONYMS.get(tok, []))
    return list(dict.fromkeys(expanded))  # deduplicate, preserve order


def _market_tokens(market: str) -> list[str]:
    """Extract short usable tokens from a market/city name."""
    tokens = re.findall(r"[a-z]+", market.lower())
    result = []
    for t in tokens:
        result.append(t)
        # also add first 4-5 chars if the token is long
        if len(t) > 5:
            result.append(t[:4])
            result.append(t[:5])
    return list(dict.fromkeys(result))


def _is_valid_sld(sld: str, max_len: int) -> bool:
    return (
        sld.isalpha()
        and len(sld) <= max_len
        and len(sld) >= 3
    )


def _style_multiplier(sld: str, style: str) -> float:
    """Nudge score based on style hint."""
    style = style.lower()
    bonus = 1.0
    if "short" in style and len(sld) <= 6:
        bonus += 0.3
    if "premium" in style and len(sld) <= 8:
        bonus += 0.2
    if "brand" in style or "catchy" in style:
        # reward short pronounceable names
        if len(sld) <= 7:
            bonus += 0.25
    return bonus


def generate_domains(
    niche: str,
    market: str,
    style: str,
    count: int,
    tld: str,
    max_sld_len: int = 15,
) -> list[dict]:
    niche_words = _extract_words(niche)
    market_words = _market_tokens(market)
    tld = tld if tld.startswith(".") else f".{tld}"

    candidates: set[str] = set()

    # Strategy 1: prefix + niche word
    for pre in BRANDABLE_PREFIXES:
        for nw in niche_words:
            candidates.add(pre + nw)

    # Strategy 2: niche word + suffix
    for nw in niche_words:
        for suf in BRANDABLE_SUFFIXES:
            candidates.add(nw + suf)

    # Strategy 3: market token + niche word
    for mw in market_words:
        for nw in niche_words:
            candidates.add(mw + nw)
            candidates.add(nw + mw)

    # Strategy 4: prefix + market token
    for pre in BRANDABLE_PREFIXES:
        for mw in market_words:
            candidates.add(pre + mw)

    # Strategy 5: market token + suffix
    for mw in market_words:
        for suf in BRANDABLE_SUFFIXES:
            candidates.add(mw + suf)

    # Strategy 6: niche word alone (if short enough)
    for nw in niche_words:
        candidates.add(nw)

    # Filter
    valid = [s for s in candidates if _is_valid_sld(s, max_sld_len)]

    # Score
    scored = []
    for sld in valid:
        domain = sld + tld
        sb = score_domain(domain)
        adjusted = int(sb.total * _style_multiplier(sld, style))
        scored.append({
            "domain": domain,
            "sld": sld,
            "tld": tld,
            "length": len(sld),
            "score": adjusted,
            "tier": sb.tier,
            "score_breakdown": {
                "length": sb.length,
                "tld": sb.tld,
                "keywords": sb.keywords,
                "pronounceable": sb.pronounceable,
                "hyphens": sb.hyphens,
                "numbers": sb.numbers,
            },
        })

    scored.sort(key=lambda x: -x["score"])
    return scored[:count]


def cmd_generate(args):
    tld = args.tld if args.tld.startswith(".") else f".{args.tld}"
    results = generate_domains(
        niche=args.niche,
        market=args.market,
        style=args.style,
        count=args.count,
        tld=tld,
    )

    if args.json:
        print(json.dumps(results, indent=2))
        return

    def c(text, code=""):
        return text if args.no_color else f"{code}{text}{RESET}"

    print()
    print(c(f"  Generated domains  |  niche: {args.niche}  |  market: {args.market}  |  style: {args.style}", BOLD))
    print()
    header = f"  {'Domain':<30} {'Score':<7} {'Tier':<10} {'Len'}"
    print(c(header, BOLD))
    print("  " + "-" * 58)
    for r in results:
        tier_col = TIER_COLORS.get(r["tier"], "")
        print(
            f"  {r['domain']:<30} "
            f"{r['score']:<7} "
            f"{c(r['tier'], tier_col):<20} "
            f"{r['length']}"
        )
    print(f"\n  {len(results)} domains generated.\n")


def _add_common(p):
    p.add_argument("--json", action="store_true", help="Output as JSON")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="domain-research",
        description="Local domain research tool for domain name flipping",
    )
    _add_common(parser)

    sub = parser.add_subparsers(dest="command", required=True)

    # check
    p_check = sub.add_parser("check", help="Check availability + value score for one or more domains")
    p_check.add_argument("domains", nargs="+", metavar="DOMAIN")
    p_check.add_argument("--whois", action="store_true", help="Also run WHOIS lookup")
    _add_common(p_check)
    p_check.set_defaults(func=cmd_check)

    # score
    p_score = sub.add_parser("score", help="Value score a domain without checking availability")
    p_score.add_argument("domain")
    _add_common(p_score)
    p_score.set_defaults(func=cmd_score)

    # whois
    p_whois = sub.add_parser("whois", help="WHOIS lookup for a domain")
    p_whois.add_argument("domain")
    p_whois.add_argument("--raw", action="store_true", help="Print raw WHOIS output")
    _add_common(p_whois)
    p_whois.set_defaults(func=cmd_whois)

    # bulk
    p_bulk = sub.add_parser("bulk", help="Check many domains from a text file (one per line)")
    p_bulk.add_argument("file", help="Path to file containing domain names")
    p_bulk.add_argument("--whois", action="store_true", help="Also run WHOIS on each domain")
    _add_common(p_bulk)
    p_bulk.set_defaults(func=cmd_bulk)

    # generate
    p_gen = sub.add_parser("generate", help="Generate and score domain name ideas")
    p_gen.add_argument("--niche", required=True, help='Business niche, e.g. "barber shop"')
    p_gen.add_argument("--market", required=True, help='Target market or city, e.g. "Casablanca"')
    p_gen.add_argument("--style", default="premium short", help='Style hint, e.g. "premium short"')
    p_gen.add_argument("--count", type=int, default=20, help="Number of results to show (default: 20)")
    p_gen.add_argument("--tld", default=".com", help="TLD to use (default: .com)")
    _add_common(p_gen)
    p_gen.set_defaults(func=cmd_generate)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
