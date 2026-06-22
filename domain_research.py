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
# Market presets
# ---------------------------------------------------------------------------

PRESETS: dict[str, dict] = {
    "ai-saas": {
        "buyer_intent": "very high",
        "keywords": [
            "ai", "agent", "prompt", "model", "workflow", "copilot", "data",
            "insight", "bot", "neural", "task", "ops", "stack", "flow",
            "automate", "sync", "parse", "embed", "infer", "query",
        ],
        "prefixes": ["get", "go", "run", "use", "try", "my", "open", "super"],
        "suffixes": ["ly", "io", "hq", "lab", "co", "fy", "base", "ops",
                     "hub", "ai", "core", "mind", "iq", "gpt", "ml"],
        "patterns": [
            "agentflow", "agentops", "agentiq", "agenthq", "agentbase",
            "promptly", "promptlab", "promptops", "prompthq",
            "taskflow", "taskops", "taskhq", "taskbase", "taskly",
            "flowops", "flowbase", "flowhq", "flowai", "flowcore",
            "copilotly", "copilothq",
            "neuralops", "neuralhq", "neuralbase",
            "inferai", "inferops", "inferhq",
            "embedai", "embedops",
            "syncops", "synchq", "syncflow",
            "queryai", "queryhq",
            "stackai", "stackops", "stackflow", "stackhq",
            "insightops", "insighthq", "insightai",
            "dataops", "datahq", "dataflow", "datacore",
            "botflow", "bothq", "botops",
            "modelops", "modelhq",
            "runai", "runops", "runflow",
            "openflow", "openops",
            "superops", "superhq",
        ],
        "avoid": {"free", "cheap", "best", "online", "web", "digital",
                  "pro", "smart", "easy", "fast", "new", "top"},
        "style": "premium short brandable",
    },
    "fintech": {
        "buyer_intent": "very high",
        "keywords": [
            "pay", "finance", "money", "cash", "fund", "bank", "invest",
            "wallet", "ledger", "credit", "loan", "yield", "capital",
            "transfer", "spend", "earn", "settle", "vault", "fx",
        ],
        "prefixes": ["get", "go", "my", "open", "prime", "clear", "swift"],
        "suffixes": ["ly", "io", "hq", "co", "fy", "base", "hub",
                     "pay", "card", "wire", "flow", "ledger"],
        "patterns": [
            "payhq", "paybase", "payflow", "paycore", "payops",
            "fundly", "fundhq", "fundflow",
            "walletly", "wallethq",
            "ledgerops", "ledgerhq", "ledgerbase",
            "yieldbase", "yieldhq",
            "vaultly", "vaulthq", "vaultbase",
            "clearfund", "clearledger", "clearpay",
            "swiftpay", "swiftfund",
            "spendly", "spendhq",
            "earnly", "earnhq",
            "creditops", "credithq",
            "settlehq", "settleops",
        ],
        "avoid": {"cheap", "free", "best", "online", "digital", "web"},
        "style": "premium short trustworthy",
    },
    "cybersecurity": {
        "buyer_intent": "high",
        "keywords": [
            "shield", "vault", "guard", "secure", "cipher", "key", "lock",
            "auth", "threat", "detect", "scan", "patch", "zero", "trust",
            "soc", "cert", "firewall", "pentest", "red", "blue",
        ],
        "prefixes": ["get", "go", "open", "ultra", "meta", "dark", "deep"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "core", "hub", "ai"],
        "patterns": [
            "shieldhq", "shieldops", "shieldai", "shieldbase",
            "vaultops", "vaulthq", "vaultai",
            "guardhq", "guardops", "guardai",
            "cipherhq", "cipherops", "cipherbase",
            "authhq", "authops", "authbase", "authcore",
            "zerotrust", "zerosoc",
            "threathq", "threatops", "threatbase",
            "scanhq", "scanops",
            "patchhq", "patchops",
            "redteamhq", "blueteamhq",
            "sochq", "socops", "socbase",
            "firewallhq",
            "pentesthq",
            "darkshield", "deepscan",
        ],
        "avoid": {"cheap", "free", "best", "easy", "simple", "web", "online"},
        "style": "premium short technical",
    },
    "healthtech": {
        "buyer_intent": "high",
        "keywords": [
            "health", "care", "med", "clinical", "patient", "vital",
            "dose", "lab", "dna", "gene", "bio", "wellness", "heal",
            "rx", "ehr", "tele", "remote", "monitor", "sync",
        ],
        "prefixes": ["get", "my", "open", "clear", "smart", "one"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "core", "hub", "ai", "md"],
        "patterns": [
            "carehq", "careops", "carebase", "careai", "carecore",
            "medhq", "medops", "medbase", "medai", "medcore",
            "vitalhq", "vitalops", "vitalbase", "vitalai",
            "clinicops", "clinichq", "clinicbase",
            "patienthq", "patientops",
            "rxhq", "rxops", "rxbase",
            "ehrhq", "ehrops",
            "telehq", "teleops", "telemd",
            "biohq", "bioops", "biobase", "biocore",
            "genehq", "geneops",
            "dosehq", "doseops",
            "monitorhq", "monitorops",
            "healops", "healhq",
            "wellnesshq", "wellnessops",
        ],
        "avoid": {"cheap", "free", "best", "fast", "easy", "online", "web"},
        "style": "premium trustworthy clinical",
    },
    "legaltech": {
        "buyer_intent": "high",
        "keywords": [
            "legal", "law", "contract", "clause", "brief", "case",
            "counsel", "firm", "court", "comply", "audit", "sign",
            "doc", "esign", "notary", "para", "trial", "dispute",
        ],
        "prefixes": ["get", "open", "clear", "my", "smart", "one"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "ai", "hub", "core"],
        "patterns": [
            "legalhq", "legalops", "legalbase", "legalai", "legalcore",
            "contracthq", "contractops", "contractai", "contractbase",
            "clausehq", "clauseops", "clauseai",
            "briefhq", "briefops",
            "casehq", "caseops", "casebase",
            "counselhq", "counselops",
            "complyops", "complyhq", "complybase", "complyai",
            "audithq", "auditops", "auditbase", "auditai",
            "signhq", "signops", "signbase",
            "esignhq", "esignops",
            "notaryhq", "notaryops",
            "disputehq", "disputeops",
            "dochq", "docops",
            "parahq", "paraops",
        ],
        "avoid": {"cheap", "free", "best", "easy", "fast", "web", "online"},
        "style": "premium trustworthy professional",
    },
    "realestate-tech": {
        "buyer_intent": "high",
        "keywords": [
            "home", "property", "listing", "deed", "rent", "lease",
            "title", "escrow", "mortgage", "broker", "realty", "zoning",
            "close", "offer", "mls", "tenant", "landlord", "appraise",
        ],
        "prefixes": ["get", "open", "my", "clear", "smart", "one", "nest"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "ai", "hub", "core"],
        "patterns": [
            "proptechhq", "propbase", "propops", "propai",
            "listinghq", "listingops", "listingbase",
            "renthq", "rentops", "rentbase", "rentai",
            "leasehq", "leaseops", "leasebase",
            "titlehq", "titleops", "titlebase",
            "escrowhq", "escrowops",
            "closehq", "closeops",
            "brokerhq", "brokerops", "brokerbase",
            "realtyhq", "realtyops", "realtybase",
            "tenanthq", "tenantops",
            "offerhq", "offerops", "offerbase",
            "mlshq", "mlsops",
            "appraisehq",
            "nestops", "nesthq", "nestbase", "nestai",
        ],
        "avoid": {"cheap", "free", "best", "easy", "web", "online", "digital"},
        "style": "premium trustworthy modern",
    },
    "hr-recruiting": {
        "buyer_intent": "high",
        "keywords": [
            "hire", "talent", "recruit", "screen", "onboard", "team",
            "people", "workforce", "staff", "career", "resume", "apply",
            "interview", "ats", "hris", "payroll", "bench", "source",
        ],
        "prefixes": ["get", "open", "my", "smart", "one", "top"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "ai", "hub", "core"],
        "patterns": [
            "hirehq", "hireops", "hirebase", "hireai", "hirecore",
            "talenthq", "talentops", "talentbase", "talentai",
            "recruithq", "recruitops", "recruitbase", "recruitai",
            "screenhq", "screenops", "screenbase", "screenai",
            "onboardhq", "onboardops", "onboardbase",
            "teamhq", "teamops", "teambase",
            "peoplehq", "peopleops", "peoplebase", "peopleai",
            "staffhq", "staffops", "staffbase",
            "careerhq", "careerops", "careerbase",
            "atshq", "atsops",
            "hrishq", "hrisops",
            "payrollhq", "payrollops",
            "sourcehq", "sourceops",
            "benchhq", "benchops",
        ],
        "avoid": {"cheap", "free", "best", "easy", "fast", "web", "online"},
        "style": "premium modern professional",
    },
    "sales-automation": {
        "buyer_intent": "very high",
        "keywords": [
            "sales", "lead", "crm", "pipeline", "outreach", "sequence",
            "close", "prospect", "deal", "revenue", "quota", "forecast",
            "engage", "convert", "follow", "signal", "intent", "score",
        ],
        "prefixes": ["get", "go", "open", "my", "smart", "one", "super"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "ai", "hub", "core"],
        "patterns": [
            "saleshq", "salesops", "salesbase", "salesai", "salescore",
            "leadhq", "leadops", "leadbase", "leadai",
            "crmhq", "crmops", "crmbase", "crmai",
            "pipelinehq", "pipelineops", "pipelinebase",
            "outreachhq", "outreachops", "outreachbase", "outreachai",
            "closehq", "closeops", "closebase", "closeai",
            "prospecthq", "prospectops", "prospectbase",
            "revenuehq", "revenueops", "revenuebase",
            "forecasthq", "forecastops",
            "engagehq", "engageops", "engagebase", "engageai",
            "converthq", "convertops",
            "signalhq", "signalops", "signalbase", "signalai",
            "scorehq", "scoreops", "scorebase",
            "intenhq", "intentops", "intentbase", "intentai",
        ],
        "avoid": {"cheap", "free", "best", "easy", "fast", "web", "online"},
        "style": "premium short high-intent",
    },
    "creator-tools": {
        "buyer_intent": "medium",
        "keywords": [
            "create", "content", "video", "clip", "edit", "caption",
            "script", "brand", "voice", "studio", "publish", "schedule",
            "post", "channel", "stream", "reel", "thumb", "hook",
        ],
        "prefixes": ["get", "go", "my", "open", "super", "fast"],
        "suffixes": ["ly", "io", "hq", "co", "fy", "lab", "hub", "ai"],
        "patterns": [
            "createhq", "createops", "createai", "createbase",
            "contenthq", "contentops", "contentai", "contentbase",
            "videohq", "videoops", "videoai",
            "cliphq", "clipops", "clipai",
            "edithq", "editops", "editai", "editbase",
            "captionhq", "captionops", "captionai",
            "scripthq", "scriptops", "scriptai",
            "brandhq", "brandops", "brandai", "brandbase",
            "voicehq", "voiceops", "voiceai",
            "publishhq", "publishops",
            "schedulehq", "scheduleops",
            "streamhq", "streamops", "streamai",
            "reelhq", "reelops", "reelai",
            "thumbhq", "thumbops", "thumbai",
            "hookhq", "hookops", "hookai",
        ],
        "avoid": {"cheap", "free", "best", "easy", "fast", "web", "online"},
        "style": "short catchy modern",
    },
    "analytics-data": {
        "buyer_intent": "high",
        "keywords": [
            "data", "metric", "insight", "report", "track", "event",
            "query", "pipeline", "warehouse", "chart", "dash", "bi",
            "cohort", "funnel", "segment", "attribute", "anomaly", "log",
        ],
        "prefixes": ["get", "open", "my", "clear", "smart", "deep"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "ai", "hub", "core"],
        "patterns": [
            "datahq", "dataops", "database", "dataai", "datacore",
            "metrichq", "metricops", "metricbase", "metricai",
            "insighthq", "insightops", "insightbase", "insightai",
            "reporthq", "reportops", "reportbase",
            "trackhq", "trackops", "trackbase", "trackai",
            "queryhq", "queryops", "querybase", "queryai",
            "pipelinehq", "pipelineops",
            "warehousehq",
            "charthq", "chartops",
            "dashhq", "dashops", "dashbase", "dashai",
            "bihq", "biops", "bibase",
            "cohorthq", "cohortops",
            "funnelhq", "funnelops",
            "segmenthq", "segmentops", "segmentbase",
            "anomalyhq", "anomalyops",
            "loghq", "logops", "logbase",
        ],
        "avoid": {"cheap", "free", "best", "easy", "web", "online"},
        "style": "premium short technical",
    },
    "ecommerce-tools": {
        "buyer_intent": "high",
        "keywords": [
            "store", "shop", "cart", "checkout", "order", "ship",
            "return", "product", "catalog", "inventory", "sell",
            "merchant", "listing", "review", "upsell", "bundle", "price",
        ],
        "prefixes": ["get", "go", "my", "open", "smart", "one"],
        "suffixes": ["ly", "io", "hq", "ops", "base", "ai", "hub", "core"],
        "patterns": [
            "storehq", "storeops", "storebase", "storeai",
            "carthq", "cartops", "cartbase", "cartai",
            "checkouthq", "checkoutops",
            "orderhq", "orderops", "orderbase",
            "shiphq", "shipops", "shipbase",
            "returnhq", "returnops",
            "producthq", "productops", "productbase",
            "inventoryhq", "inventoryops",
            "merchanthq", "merchantops",
            "listinghq", "listingops",
            "reviewhq", "reviewops",
            "upsellhq", "upsellops",
            "bundlehq", "bundleops",
            "pricehq", "priceops", "priceai",
            "sellhq", "sellops", "sellbase",
        ],
        "avoid": {"cheap", "free", "best", "easy", "fast", "web", "online"},
        "style": "premium modern commerce",
    },
    "productivity": {
        "buyer_intent": "medium",
        "keywords": [
            "task", "focus", "plan", "note", "doc", "team", "flow",
            "work", "sprint", "goal", "habit", "track", "remind",
            "inbox", "block", "async", "standup", "retro", "okr",
        ],
        "prefixes": ["get", "go", "my", "open", "super", "one", "daily"],
        "suffixes": ["ly", "io", "hq", "co", "fy", "lab", "hub", "ai"],
        "patterns": [
            "taskhq", "taskops", "taskbase", "taskai", "taskflow",
            "focushq", "focusops", "focusai",
            "planhq", "planops", "planbase", "planai",
            "notehq", "noteops", "notebase",
            "dochq", "docops", "docbase",
            "teamhq", "teamops", "teambase", "teamai",
            "flowhq", "flowops", "flowbase", "flowai",
            "workhq", "workops", "workbase",
            "sprintnhq", "sprintops",
            "goalhq", "goalops", "goalbase",
            "habithq", "habitops",
            "inboxhq", "inboxops",
            "asynchq", "asyncops",
            "standups", "standuphq",
            "okrhq", "okrops", "okrbase",
            "retrohq", "retroops",
            "blockhq", "blockops",
        ],
        "avoid": {"cheap", "free", "best", "easy", "fast", "web", "online"},
        "style": "short catchy modern",
    },
}


def generate_from_preset(
    preset_name: str,
    count: int,
    tld: str,
    max_sld_len: int = 15,
) -> list[dict]:
    if preset_name not in PRESETS:
        raise ValueError(f"Unknown preset '{preset_name}'. Available: {', '.join(PRESETS)}")

    p = PRESETS[preset_name]
    keywords: list[str] = p["keywords"]
    prefixes: list[str] = p["prefixes"]
    suffixes: list[str] = p["suffixes"]
    patterns: list[str] = p["patterns"]
    avoid: set[str] = p["avoid"]
    style: str = p["style"]
    tld = tld if tld.startswith(".") else f".{tld}"

    candidates: set[str] = set()

    # prefix + keyword
    for pre in prefixes:
        for kw in keywords:
            candidates.add(pre + kw)

    # keyword + suffix
    for kw in keywords:
        for suf in suffixes:
            candidates.add(kw + suf)

    # keyword + keyword (short pairs only)
    for i, kw1 in enumerate(keywords):
        for kw2 in keywords[i + 1:]:
            combo = kw1 + kw2
            if len(combo) <= max_sld_len:
                candidates.add(combo)

    # invented patterns
    for pat in patterns:
        candidates.add(pat)

    # keyword alone
    for kw in keywords:
        candidates.add(kw)

    valid = [s for s in candidates if _is_valid_sld(s, max_sld_len)]

    scored = []
    for sld in valid:
        domain = sld + tld
        sb = score_domain(domain)

        # Penalty: contains an avoid word as standalone sld
        avoid_hit = sld in avoid
        avoid_combo = any(
            sld == av + rest or sld == rest + av
            for av in avoid
            for rest in [""]
            if rest == sld.replace(av, "", 1)
        )
        generic_penalty = 40 if avoid_hit else 0

        # Penalty for prefix+suffix only (no keyword)
        pure_affixes = set(suffixes) | set(prefixes)
        affix_only = False
        for pre in prefixes:
            if sld.startswith(pre):
                remainder = sld[len(pre):]
                if remainder in pure_affixes and remainder not in keywords:
                    affix_only = True
                    break
        if affix_only:
            generic_penalty += 40

        adjusted = max(0, int((sb.total - generic_penalty) * _style_multiplier(sld, style)))

        # Build reason
        reasons = []
        kw_hits = [kw for kw in keywords if kw in sld]
        if kw_hits:
            reasons.append(f"keyword: {', '.join(kw_hits[:2])}")
        if sld in patterns:
            reasons.append("preset pattern")
        if len(sld) <= 5:
            reasons.append("very short")
        elif len(sld) <= 8:
            reasons.append("short")
        if avoid_hit:
            reasons.append("avoid word — penalised")
        if affix_only:
            reasons.append("affix-only — penalised")
        if not kw_hits and sld not in patterns:
            reasons.append("no keyword signal")

        scored.append({
            "domain": domain,
            "sld": sld,
            "tld": tld,
            "length": len(sld),
            "score": adjusted,
            "tier": sb.tier,
            "reason": "; ".join(reasons) if reasons else "generic",
            "preset": preset_name,
            "buyer_intent": p["buyer_intent"],
        })

    scored.sort(key=lambda x: -x["score"])
    return scored[:count]


# ---------------------------------------------------------------------------
# Domain generator (manual mode)
# ---------------------------------------------------------------------------

# Strong niche tokens per keyword — only specific, brandable words
NICHE_SYNONYMS: dict[str, list[str]] = {
    "barber":  ["barber", "blade", "fade", "trim", "razor", "groom", "shave", "cut",
                "clip", "beard", "chair", "style"],
    "shop":    ["studio", "craft", "works", "lab"],
    "hair":    ["cut", "style", "fade", "blade", "trim", "clip"],
    "salon":   ["style", "groom", "blade", "trim", "shave"],
    "food":    ["food", "eat", "bite", "chef", "dish", "feast", "taste"],
    "cafe":    ["cafe", "brew", "bean", "roast", "sip", "drip"],
    "fitness": ["fit", "lift", "flex", "burn", "sweat", "strong"],
    "gym":     ["gym", "lift", "flex", "burn", "rep", "iron"],
    "tech":    ["tech", "code", "dev", "byte", "stack", "logic"],
    "real":    ["home", "nest", "realty", "haven", "land"],
    "estate":  ["home", "nest", "realty", "haven", "property"],
    "travel":  ["trip", "roam", "trek", "fly", "voyage", "wander"],
    "fashion": ["style", "wear", "thread", "vogue", "look", "drip"],
    "law":     ["law", "legal", "counsel", "firm", "rights", "justice"],
    "health":  ["care", "well", "vital", "cure", "med", "life"],
    "pet":     ["paw", "tail", "fur", "bark", "vet"],
    "photo":   ["lens", "frame", "shot", "pixel", "snap", "click"],
    "music":   ["beat", "sound", "tune", "track", "wave", "note"],
    "market":  ["trade", "deal", "cart", "bazaar"],
}

# Tokens that are too generic to stand alone — penalised unless paired with a strong token
WEAK_STANDALONE = {"shop", "room", "den", "place", "spot", "store", "thing", "stuff",
                   "lab", "hub", "co", "studio", "craft", "works", "house", "club"}

# Invented brandable patterns: (root, suffix) → combined word
INVENTED_PATTERNS: list[str] = [
    "trimora", "fadeo", "bladely", "groomly", "razorly",
    "clipora", "beardio", "cutiva", "shavora", "fadeio",
    "trimco", "bladeco", "groomco", "razorco", "cutlab",
    "fadehub", "trimhub", "groomhub", "bladehub", "cliplab",
    "casatrim", "casafade", "casagroom", "casablade", "casacut",
    "trimcasa", "fadecasa", "groomcasa",
]

BRANDABLE_PREFIXES = [
    "go", "my", "get", "pro", "prime", "urban", "casa",
]

BRANDABLE_SUFFIXES = [
    "lab", "studio", "co", "hub", "house", "works", "club", "craft",
]


def _extract_words(phrase: str) -> list[str]:
    """Split phrase into tokens and expand via niche synonym map."""
    tokens = re.findall(r"[a-z]+", phrase.lower())
    expanded: list[str] = []
    for tok in tokens:
        # Only add the raw token if it's not a weak standalone
        if tok not in WEAK_STANDALONE:
            expanded.append(tok)
        expanded.extend(NICHE_SYNONYMS.get(tok, []))
    return list(dict.fromkeys(expanded))


def _market_tokens(market: str) -> list[str]:
    """Extract short usable tokens from a market/city name."""
    tokens = re.findall(r"[a-z]+", market.lower())
    result = []
    for t in tokens:
        result.append(t)
        if len(t) > 5:
            result.append(t[:4])
            result.append(t[:5])
    return list(dict.fromkeys(result))


def _is_valid_sld(sld: str, max_len: int) -> bool:
    return sld.isalpha() and 3 <= len(sld) <= max_len


def _generic_penalty(sld: str) -> int:
    """Return a score penalty for names that are too vague."""
    penalty = 0
    if sld in WEAK_STANDALONE:
        penalty += 55
    # Penalise prefix+suffix combos with no niche word (e.g. golab, getlab, prolab)
    pure_affixes = {"lab", "hub", "co", "studio", "craft", "works", "house", "club",
                    "shop", "room", "den", "place", "spot", "store", "pro", "go",
                    "get", "my", "prime", "urban", "casa"}
    prefixes = {"go", "get", "my", "pro", "prime", "urban", "casa"}
    for pre in prefixes:
        if sld.startswith(pre):
            remainder = sld[len(pre):]
            if remainder in pure_affixes:
                penalty += 45
                break
    # Penalise combos where BOTH parts are weak (e.g. labhub, labco, lablab)
    suffix_only = {"lab", "hub", "co", "studio", "craft", "works", "house", "club",
                   "shop", "room", "den", "place", "spot", "store"}
    if len(sld) >= 5:
        for sw in suffix_only:
            remainder = sld[: len(sld) - len(sw)]
            if sld.endswith(sw) and remainder in suffix_only:
                penalty += 30
                break
    return penalty


def _style_multiplier(sld: str, style: str) -> float:
    style = style.lower()
    bonus = 1.0
    if "short" in style and len(sld) <= 6:
        bonus += 0.3
    if "premium" in style and len(sld) <= 8:
        bonus += 0.2
    if ("brand" in style or "catchy" in style) and len(sld) <= 7:
        bonus += 0.25
    return bonus


def _explain(sld: str, niche_words: list[str], market_words: list[str]) -> str:
    """Generate a short reason string for why a domain scored well or poorly."""
    reasons = []

    strong_barber = {"trim", "fade", "blade", "groom", "razor", "cut", "clip",
                     "shave", "barber", "beard", "chair", "style"}
    niche_hits = [w for w in strong_barber if w in sld]
    market_hits = [w for w in market_words if w in sld and len(w) >= 4]
    invented = any(sld == p for p in INVENTED_PATTERNS)

    if invented:
        reasons.append("invented brandable word")
    if niche_hits:
        reasons.append(f"niche token: {', '.join(niche_hits)}")
    if market_hits:
        reasons.append(f"market token: {', '.join(market_hits)}")
    if len(sld) <= 5:
        reasons.append("very short")
    elif len(sld) <= 7:
        reasons.append("short")
    if sld in WEAK_STANDALONE:
        reasons.append("too generic — penalised")
    if not niche_hits and not invented and not market_hits:
        reasons.append("no strong niche signal")

    return "; ".join(reasons) if reasons else "generic combination"


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

    # Strategy 3: market token + niche word (both directions)
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

    # Strategy 6: niche word alone
    for nw in niche_words:
        candidates.add(nw)

    # Strategy 7: invented brandable patterns
    for pat in INVENTED_PATTERNS:
        candidates.add(pat)

    # Filter
    valid = [s for s in candidates if _is_valid_sld(s, max_sld_len)]

    # Score with penalty and style multiplier
    scored = []
    for sld in valid:
        domain = sld + tld
        sb = score_domain(domain)
        penalty = _generic_penalty(sld)
        adjusted = max(0, int((sb.total - penalty) * _style_multiplier(sld, style)))
        scored.append({
            "domain": domain,
            "sld": sld,
            "tld": tld,
            "length": len(sld),
            "score": adjusted,
            "tier": sb.tier,
            "reason": _explain(sld, niche_words, market_words),
            "score_breakdown": {
                "length": sb.length,
                "tld": sb.tld,
                "keywords": sb.keywords,
                "pronounceable": sb.pronounceable,
                "hyphens": sb.hyphens,
                "numbers": sb.numbers,
                "generic_penalty": -penalty,
            },
        })

    scored.sort(key=lambda x: -x["score"])
    return scored[:count]


def _availability_label(sld: str, available: Optional[bool]) -> str:
    """Return a human label combining DNS result with domain characteristics."""
    # Single short dictionary words on .com are almost always registered
    likely_premium = len(sld) <= 5 and sld.isalpha()
    if available is None:
        return "unknown"
    if available:
        if likely_premium:
            return "likely premium/taken — verify"
        return "available"
    else:
        if likely_premium:
            return "likely premium/taken"
        return "taken"


def _run_availability_checks(results: list[dict]) -> None:
    import time
    print(f"\n  Checking availability for {len(results)} domains...", flush=True)
    for i, r in enumerate(results):
        avail, _ = check_availability(r["domain"])
        r["available"] = avail
        r["avail_label"] = _availability_label(r["sld"], avail)
        if (i + 1) % 5 == 0:
            print(f"  {i + 1}/{len(results)} checked...", flush=True)
        time.sleep(0.3)


def _print_generate_table(results: list[dict], title: str, do_check: bool,
                          no_color: bool) -> None:
    def c(text, code=""):
        return text if no_color else f"{code}{text}{RESET}"

    AVAIL_COLORS = {
        "available":                     "\033[92m",
        "taken":                         "\033[91m",
        "likely premium/taken":          "\033[91m",
        "likely premium/taken — verify": "\033[93m",
        "unknown":                       "\033[90m",
        "not checked":                   "\033[90m",
    }

    print()
    print(c(f"  {title}", BOLD))
    print()

    if do_check:
        header = f"  {'Domain':<24} {'Availability':<28} {'Score':<7} {'Len':<5} Reason"
        print(c(header, BOLD))
        print("  " + "-" * 92)
        for r in results:
            label = r.get("avail_label", "not checked")
            avail_col = AVAIL_COLORS.get(label, "")
            print(
                f"  {r['domain']:<24} "
                f"{c(label, avail_col):<38} "
                f"{r['score']:<7} "
                f"{r['length']:<5} "
                f"{r['reason']}"
            )
    else:
        header = f"  {'Domain':<24} {'Score':<7} {'Tier':<10} {'Len':<5} Reason"
        print(c(header, BOLD))
        print("  " + "-" * 82)
        for r in results:
            tier_col = TIER_COLORS.get(r["tier"], "")
            print(
                f"  {r['domain']:<24} "
                f"{r['score']:<7} "
                f"{c(r['tier'], tier_col):<20} "
                f"{r['length']:<5} "
                f"{r['reason']}"
            )

    print(f"\n  {len(results)} domains generated.\n")


def cmd_generate(args):
    tld = args.tld if args.tld.startswith(".") else f".{args.tld}"
    raw_check = getattr(args, "check", None)
    do_check = raw_check is not None and str(raw_check).lower() not in ("false", "0", "no")
    preset_name = getattr(args, "preset", None)

    if preset_name:
        if preset_name not in PRESETS:
            print(f"  Unknown preset '{preset_name}'. Available presets:", file=sys.stderr)
            for k, v in PRESETS.items():
                print(f"    {k:<22} (buyer intent: {v['buyer_intent']})", file=sys.stderr)
            sys.exit(1)
        results = generate_from_preset(preset_name, args.count, tld)
        title = f"Preset: {preset_name}  |  buyer intent: {PRESETS[preset_name]['buyer_intent']}  |  tld: {tld}"
    else:
        # Manual mode — niche/market/style required
        if not getattr(args, "niche", None) or not getattr(args, "market", None):
            print("  Error: --niche and --market are required when not using --preset", file=sys.stderr)
            sys.exit(1)
        results = generate_domains(
            niche=args.niche,
            market=args.market,
            style=getattr(args, "style", "premium short"),
            count=args.count,
            tld=tld,
        )
        title = f"niche: {args.niche}  |  market: {args.market}  |  tld: {tld}"

    if do_check:
        _run_availability_checks(results)
    else:
        for r in results:
            r["available"] = None
            r["avail_label"] = "not checked"

    if args.json:
        print(json.dumps(results, indent=2))
        return

    _print_generate_table(results, title, do_check, args.no_color)


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
    p_gen.add_argument("--preset", default=None,
                       help=f'Use a market preset. Available: {", ".join(PRESETS)}')
    p_gen.add_argument("--niche", default=None, help='Manual mode: business niche, e.g. "barber shop"')
    p_gen.add_argument("--market", default=None, help='Manual mode: target market or city')
    p_gen.add_argument("--style", default="premium short", help='Style hint (manual mode)')
    p_gen.add_argument("--count", type=int, default=20, help="Number of results to show (default: 20)")
    p_gen.add_argument("--tld", default=".com", help="TLD to use (default: .com)")
    p_gen.add_argument("--check", nargs="?", const="true", default=None,
                       help="Check DNS availability for each generated domain")
    _add_common(p_gen)
    p_gen.set_defaults(func=cmd_generate)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
