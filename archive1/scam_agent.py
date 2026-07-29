#!/usr/bin/env python3
"""
scam_agent.py - Website legitimacy / scam analysis agent running on Ollama.

Input : a URL
Output: - a printed report (summary, verdict, category, oddities)
        - a JSON report file
        - three CSVs: <slug>.text.csv, <slug>.html.csv, <slug>.scripts.csv

Design:
    fetch -> parse -> deterministic signal pass -> LLM analysis -> assemble.

The deterministic pass does the things a 14b model is unreliable at (spotting
cross-domain form posts, obfuscated JS, punycode, urgency copy, etc.) and hands
that evidence to the model, which does the summarising / judgement / wording.

Single model by default; pass --panel a,b,c to run a counsel and aggregate.

Usage:
    python scam_agent.py https://example.com
    python scam_agent.py https://example.com --model qwen2.5-coder:14b
    python scam_agent.py https://example.com --panel qwen2.5-coder:14b,qwen2.5:14b,gemma2:9b
    python scam_agent.py https://example.com --dry-run     # skip Ollama, use signals only
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment

# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

OLLAMA_URL = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "qwen2.5-coder:14b"     # matches your primary local model
NUM_CTX = 8192                          # IMPORTANT: Ollama defaults low; set it
REQUEST_TIMEOUT = 20
MAX_TEXT_FOR_LLM = 9000                 # chars of visible text sent to the model
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"
)

URGENCY_PATTERNS = [
    r"act now", r"limited time", r"verify your (account|identity)", r"suspended",
    r"unusual (activity|login)", r"confirm your (password|details|payment)",
    r"you (have )?won", r"claim your (prize|reward)", r"congratulations",
    r"wire transfer", r"gift card", r"crypto(currency)? (giveaway|doubling)",
    r"send .{0,10}(bitcoin|btc|eth|usdt)", r"final notice", r"immediately",
    r"your (account|payment) (will|has) be(en)? (locked|closed|charged)",
    r"tax refund", r"seed phrase", r"recovery phrase",
]

SENSITIVE_INPUTS = {"password", "email", "tel"}
CARD_HINTS = re.compile(r"card|cvv|cvc|iban|routing|ssn|social.?security", re.I)
OBFUSCATION_TOKENS = [
    "eval(", "unescape(", "atob(", "fromcharcode", "\\x", "document.write(",
    "settimeout(unescape", "escape(", "%u00",
]

# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class Signal:
    code: str
    severity: str          # info | low | medium | high
    detail: str


@dataclass
class Fetched:
    requested_url: str
    final_url: str
    status: int
    redirect_chain: list[str]
    headers: dict
    html: str


# --------------------------------------------------------------------------- #
# Fetch
# --------------------------------------------------------------------------- #

def fetch(url: str) -> Fetched:
    if not urlparse(url).scheme:
        url = "https://" + url
    resp = requests.get(
        url,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
        timeout=REQUEST_TIMEOUT,
        allow_redirects=True,
    )
    chain = [r.url for r in resp.history] + [resp.url]
    return Fetched(
        requested_url=url,
        final_url=resp.url,
        status=resp.status_code,
        redirect_chain=chain,
        headers=dict(resp.headers),
        html=resp.text,
    )


# --------------------------------------------------------------------------- #
# Parse
# --------------------------------------------------------------------------- #

def _domain(u: str) -> str:
    try:
        return urlparse(u).netloc.lower()
    except Exception:
        return ""


def _registrable(host: str) -> str:
    # crude eTLD+1; good enough for same-site comparison without a PSL dep
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def parse(fetched: Fetched):
    soup = BeautifulSoup(fetched.html, "html.parser")

    for tag in soup(["style", "noscript"]):
        tag.decompose()

    # --- text segments -----------------------------------------------------
    text_rows = []
    block_tags = ["h1", "h2", "h3", "h4", "p", "li", "a", "span", "td", "button",
                  "label", "title", "figcaption", "blockquote"]
    for i, el in enumerate(soup.find_all(block_tags)):
        txt = " ".join(el.get_text(" ", strip=True).split())
        if not txt:
            continue
        text_rows.append({
            "index": len(text_rows),
            "tag": el.name,
            "depth": len(list(el.parents)),
            "char_count": len(txt),
            "word_count": len(txt.split()),
            "text": txt,
        })

    # --- element inventory -------------------------------------------------
    html_rows = []
    for el in soup.find_all(True):
        attrs = {k: (" ".join(v) if isinstance(v, list) else v)
                 for k, v in el.attrs.items()}
        html_rows.append({
            "index": len(html_rows),
            "tag": el.name,
            "depth": len(list(el.parents)),
            "id": attrs.get("id", ""),
            "classes": attrs.get("class", ""),
            "attrs": json.dumps({k: v for k, v in attrs.items()
                                 if k not in ("id", "class")}, ensure_ascii=False),
            "inner_text_len": len(el.get_text(strip=True)),
        })

    # --- scripts -----------------------------------------------------------
    script_rows = []
    page_reg = _registrable(_domain(fetched.final_url))
    for el in soup.find_all("script"):
        src = el.get("src")
        if src:
            src_abs = urljoin(fetched.final_url, src)
            dom = _domain(src_abs)
            script_rows.append(_script_row(len(script_rows), "external",
                                           src_abs, dom, page_reg, body=""))
        else:
            body = el.string or el.get_text() or ""
            script_rows.append(_script_row(len(script_rows), "inline",
                                           "", "", page_reg, body=body))

    # --- forms (for signal pass) -------------------------------------------
    forms = []
    for f in soup.find_all("form"):
        action = urljoin(fetched.final_url, f.get("action", "") or "")
        inputs = []
        for inp in f.find_all(["input", "textarea", "select"]):
            inputs.append({
                "type": (inp.get("type") or inp.name or "").lower(),
                "name": inp.get("name", ""),
            })
        forms.append({"action": action, "action_domain": _domain(action),
                      "method": (f.get("method") or "get").lower(),
                      "inputs": inputs})

    # --- links & meta ------------------------------------------------------
    links = []
    for a in soup.find_all("a", href=True):
        href = urljoin(fetched.final_url, a["href"])
        links.append({"text": a.get_text(" ", strip=True),
                      "href": href, "domain": _domain(href)})

    hidden = []
    for el in soup.find_all(style=True):
        s = el.get("style", "").replace(" ", "").lower()
        if "display:none" in s or "visibility:hidden" in s or "opacity:0" in s:
            hidden.append(el)

    comments = soup.find_all(string=lambda t: isinstance(t, Comment))

    meta = {
        "title": (soup.title.get_text(strip=True) if soup.title else ""),
        "description": _meta(soup, "description"),
        "generator": _meta(soup, "generator"),
        "meta_refresh": bool(soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})),
    }

    return {
        "soup": soup, "text_rows": text_rows, "html_rows": html_rows,
        "script_rows": script_rows, "forms": forms, "links": links,
        "hidden": hidden, "comments": comments, "meta": meta,
        "page_registrable": page_reg,
    }


def _meta(soup, name):
    tag = soup.find("meta", attrs={"name": re.compile(f"^{name}$", re.I)})
    return tag.get("content", "").strip() if tag and tag.get("content") else ""


def _obfuscation_score(body: str) -> int:
    if not body:
        return 0
    low = body.lower()
    score = sum(1 for tok in OBFUSCATION_TOKENS if tok in low)
    # long unbroken tokens => likely packed/minified/encoded
    longest = max((len(t) for t in re.split(r"\s+", body)), default=0)
    if longest > 500:
        score += 2
    # long base64-looking blob
    if re.search(r"[A-Za-z0-9+/]{200,}={0,2}", body):
        score += 2
    # hex string chains
    if len(re.findall(r"\\x[0-9a-f]{2}", low)) > 30:
        score += 2
    return score


def _script_row(idx, kind, src, dom, page_reg, body):
    length = len(body) if kind == "inline" else 0
    obf = _obfuscation_score(body)
    flags = []
    if kind == "external" and dom and _registrable(dom) != page_reg:
        flags.append("third_party")
    if obf >= 3:
        flags.append("obfuscated")
    if kind == "inline" and length > 0:
        density = len(body.replace(" ", "")) / max(body.count("\n") + 1, 1)
        if density > 400:
            flags.append("minified")
    return {
        "index": idx,
        "kind": kind,
        "src_or_domain": src or dom,
        "length": length,
        "obfuscation_score": obf,
        "flags": ";".join(flags),
    }


# --------------------------------------------------------------------------- #
# Deterministic signal pass
# --------------------------------------------------------------------------- #

def detect_signals(fetched: Fetched, parsed) -> list[Signal]:
    sig: list[Signal] = []
    page_reg = parsed["page_registrable"]

    # redirects
    hops = parsed_hops(fetched.redirect_chain)
    if len({_registrable(_domain(u)) for u in fetched.redirect_chain}) > 1:
        sig.append(Signal("cross_domain_redirect", "medium",
                          f"Redirect crossed domains: {' -> '.join(hops)}"))
    if parsed["meta"]["meta_refresh"]:
        sig.append(Signal("meta_refresh", "low", "Page uses a <meta> refresh redirect."))

    # IP-address host / punycode
    host = _domain(fetched.final_url)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}", host):
        sig.append(Signal("ip_host", "medium", f"Site served from a raw IP: {host}"))
    if "xn--" in host:
        sig.append(Signal("punycode_domain", "high",
                          f"Punycode/homograph domain: {host}"))

    # forms
    for f in parsed["forms"]:
        sensitive = [i for i in f["inputs"]
                     if i["type"] in SENSITIVE_INPUTS
                     or CARD_HINTS.search(i["name"] or "")]
        if sensitive and f["action_domain"] and _registrable(f["action_domain"]) != page_reg:
            sig.append(Signal("cross_domain_credential_post", "high",
                              f"Form collecting {[i['type'] for i in sensitive]} "
                              f"posts to third-party domain {f['action_domain']}."))
        elif any(i["type"] == "password" for i in f["inputs"]):
            sig.append(Signal("password_form", "info",
                              f"Page has a password form (action: {f['action_domain'] or 'same-site'})."))

    # scripts
    third_party = {r["src_or_domain"] for r in parsed["script_rows"]
                   if "third_party" in r["flags"]}
    if len(third_party) >= 6:
        sig.append(Signal("many_third_party_scripts", "low",
                          f"{len(third_party)} distinct third-party script domains."))
    obf = [r for r in parsed["script_rows"] if "obfuscated" in r["flags"]]
    if obf:
        sig.append(Signal("obfuscated_script", "high",
                          f"{len(obf)} script(s) look obfuscated/encoded."))

    # urgency / pressure language
    body_text = " ".join(r["text"] for r in parsed["text_rows"]).lower()
    hits = sorted({p for p in URGENCY_PATTERNS if re.search(p, body_text)})
    if hits:
        sev = "high" if len(hits) >= 3 else "medium"
        sig.append(Signal("pressure_language", sev,
                          f"Urgency/scam phrasing matched: {[h for h in hits][:8]}"))

    # anchor text / href mismatch (brand shown, off-domain link)
    for l in parsed["links"]:
        t = l["text"].lower()
        if any(b in t for b in ("paypal", "amazon", "microsoft", "apple",
                                "netflix", "bank", "coinbase")):
            if l["domain"] and _registrable(l["domain"]) != page_reg:
                sig.append(Signal("brand_link_mismatch", "medium",
                                  f"Link labelled '{l['text'][:30]}' points to {l['domain']}."))
                break

    # hidden content
    if len(parsed["hidden"]) > 8:
        sig.append(Signal("many_hidden_elements", "low",
                          f"{len(parsed['hidden'])} elements hidden via inline style."))

    # missing TLS
    if urlparse(fetched.final_url).scheme != "https":
        sig.append(Signal("no_https", "medium", "Page not served over HTTPS."))

    return sig


def parsed_hops(chain):
    return [_domain(u) or u for u in chain]


# --------------------------------------------------------------------------- #
# LLM analysis (Ollama)
# --------------------------------------------------------------------------- #

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "category": {"type": "string"},
        "verdict": {"type": "string", "enum": ["legitimate", "suspicious", "likely_scam", "scam", "unknown"]},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "reasoning": {"type": "string"},
        "oddities": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "category", "verdict", "risk_score", "oddities"],
}

SYSTEM_PROMPT = (
    "You are a website legitimacy analyst. You are given extracted, stripped "
    "content from a single web page plus a list of automatically detected "
    "technical signals. Judge whether the site is legitimate or a scam and "
    "explain concisely. Base your verdict on the evidence given; do not invent "
    "content you were not shown. Respond ONLY with the JSON object matching the "
    "provided schema."
)


def build_user_prompt(fetched, parsed, signals):
    text = " ".join(r["text"] for r in parsed["text_rows"])[:MAX_TEXT_FOR_LLM]
    form_lines = [f"- {f['method'].upper()} -> {f['action_domain'] or 'same-site'} "
                  f"inputs={[i['type'] for i in f['inputs']]}" for f in parsed["forms"]]
    ext_domains = sorted({r["src_or_domain"] for r in parsed["script_rows"]
                          if r["kind"] == "external"})
    sig_lines = [f"- [{s.severity.upper()}] {s.code}: {s.detail}" for s in signals]

    return (
        f"URL requested: {fetched.requested_url}\n"
        f"Final URL: {fetched.final_url}\n"
        f"HTTP status: {fetched.status}\n"
        f"Redirect chain: {' -> '.join(parsed_hops(fetched.redirect_chain))}\n"
        f"Title: {parsed['meta']['title']}\n"
        f"Meta description: {parsed['meta']['description']}\n\n"
        f"Forms:\n" + ("\n".join(form_lines) or "  (none)") + "\n\n"
        f"External script domains ({len(ext_domains)}): {', '.join(ext_domains) or '(none)'}\n\n"
        f"Automated signals:\n" + ("\n".join(sig_lines) or "  (none detected)") + "\n\n"
        f"Visible text (truncated):\n\"\"\"\n{text}\n\"\"\"\n"
    )


def call_ollama(model, system, user):
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "format": RESPONSE_SCHEMA,     # structured output
        "stream": False,
        "options": {"temperature": 0.1, "num_ctx": NUM_CTX},
    }
    r = requests.post(OLLAMA_URL, json=payload, timeout=300)
    r.raise_for_status()
    content = r.json()["message"]["content"]
    return json.loads(content)


def analyze_single(model, fetched, parsed, signals):
    user = build_user_prompt(fetched, parsed, signals)
    return call_ollama(model, SYSTEM_PROMPT, user)


def analyze_panel(models, fetched, parsed, signals):
    results = []
    for m in models:
        try:
            print(f"  querying {m} ...", file=sys.stderr)
            results.append(call_ollama(m, SYSTEM_PROMPT,
                                       build_user_prompt(fetched, parsed, signals)))
        except Exception as e:
            print(f"  {m} failed: {e}", file=sys.stderr)
    if not results:
        raise RuntimeError("all panel models failed")
    return aggregate(results)


def aggregate(results):
    labels = [r.get("verdict", "unknown") for r in results]
    scores = [int(r.get("risk_score", 50)) for r in results]
    cats = [r.get("category", "unknown") for r in results]
    mean_score = round(sum(scores) / len(scores))
    verdict = Counter(labels).most_common(1)[0][0]
    category = Counter(cats).most_common(1)[0][0]
    # summary from the model whose score is closest to the mean
    rep = min(results, key=lambda r: abs(int(r.get("risk_score", 50)) - mean_score))
    oddities = []
    for r in results:
        for o in r.get("oddities", []):
            if o not in oddities:
                oddities.append(o)
    return {
        "summary": rep.get("summary", ""),
        "category": category,
        "verdict": verdict,
        "risk_score": mean_score,
        "reasoning": f"Panel of {len(results)} models; verdicts={labels}, scores={scores}.",
        "oddities": oddities,
        "panel_votes": labels,
    }


def dry_run_analysis(fetched, parsed, signals):
    high = [s for s in signals if s.severity == "high"]
    med = [s for s in signals if s.severity == "medium"]
    score = min(100, len(high) * 30 + len(med) * 15)
    verdict = ("likely_scam" if score >= 60 else
               "suspicious" if score >= 30 else "legitimate")
    return {
        "summary": (parsed["meta"]["title"] or fetched.final_url) +
                   f" — {len(parsed['text_rows'])} text blocks, "
                   f"{len(parsed['forms'])} form(s).",
        "category": "unknown (dry-run, no LLM)",
        "verdict": verdict,
        "risk_score": score,
        "reasoning": "Deterministic signals only; Ollama not called.",
        "oddities": [f"{s.code}: {s.detail}" for s in signals],
    }


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def slugify(url):
    host = _domain(url) or "site"
    return re.sub(r"[^a-z0-9.-]+", "_", host.lower()).strip("._") or "site"


def write_csvs(outdir: Path, slug, parsed):
    files = {}
    specs = {
        "text": (parsed["text_rows"],
                 ["index", "tag", "depth", "char_count", "word_count", "text"]),
        "html": (parsed["html_rows"],
                 ["index", "tag", "depth", "id", "classes", "attrs", "inner_text_len"]),
        "scripts": (parsed["script_rows"],
                    ["index", "kind", "src_or_domain", "length",
                     "obfuscation_score", "flags"]),
    }
    for name, (rows, cols) in specs.items():
        p = outdir / f"{slug}.{name}.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        files[name] = p
    return files


def print_report(fetched, analysis, signals, csv_files):
    line = "=" * 68
    print(line)
    print(f"REPORT  {fetched.final_url}")
    print(line)
    print(f"\nVerdict     : {analysis['verdict'].upper()}  (risk {analysis['risk_score']}/100)")
    print(f"Category    : {analysis['category']}")
    print(f"\nSummary:\n  {analysis['summary']}")
    if analysis.get("reasoning"):
        print(f"\nReasoning:\n  {analysis['reasoning']}")
    print("\nOddities:")
    if analysis["oddities"]:
        for o in analysis["oddities"]:
            print(f"  - {o}")
    else:
        print("  (none reported)")
    print("\nCSV files:")
    for name, p in csv_files.items():
        print(f"  {name:8s}: {p}")
    print(line)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Website scam-analysis agent (Ollama).")
    ap.add_argument("url")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--panel", help="comma-separated model list for counsel mode")
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--dry-run", action="store_true",
                    help="skip Ollama; report from deterministic signals only")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print(f"[1/4] fetching {args.url}", file=sys.stderr)
    fetched = fetch(args.url)

    print("[2/4] parsing", file=sys.stderr)
    parsed = parse(fetched)

    print("[3/4] detecting signals", file=sys.stderr)
    signals = detect_signals(fetched, parsed)

    print("[4/4] analysing", file=sys.stderr)
    if args.dry_run:
        analysis = dry_run_analysis(fetched, parsed, signals)
    elif args.panel:
        analysis = analyze_panel([m.strip() for m in args.panel.split(",")],
                                 fetched, parsed, signals)
    else:
        analysis = analyze_single(args.model, fetched, parsed, signals)

    # merge deterministic signals into the oddity list (dedup by detail)
    for s in signals:
        entry = f"{s.code}: {s.detail}"
        if entry not in analysis["oddities"]:
            analysis["oddities"].append(entry)

    slug = slugify(fetched.final_url)
    csv_files = write_csvs(outdir, slug, parsed)

    report = {
        "url": fetched.requested_url,
        "final_url": fetched.final_url,
        "http_status": fetched.status,
        "redirect_chain": fetched.redirect_chain,
        "analysis": analysis,
        "signals": [asdict(s) for s in signals],
        "csv_files": {k: str(v) for k, v in csv_files.items()},
    }
    (outdir / f"{slug}.report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print_report(fetched, analysis, signals, csv_files)


if __name__ == "__main__":
    main()