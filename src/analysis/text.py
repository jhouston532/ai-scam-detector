"""
text.py — the human-readable-text worker.

Owns the third analysis category: what a page actually *says* to a visitor, as
opposed to how it's built (web_code.py) or what it runs (scripts.py). This is
where social engineering lives, so the module keeps a little structure
(headings and calls-to-action carry outsized signal), pulls scam-relevant
linguistic features, flags text-level evasion tricks, and segments long copy
into model-sized chunks.

Design contract (matches analysis.py's "parse once" rule): the public entry
point `build_text_report` takes an already-parsed BeautifulSoup tree.
`report_from_html` is a convenience wrapper that parses first, for standalone
use and tests.

Ordering note: obfuscation detection runs on the *raw* visible text, before
Unicode NFKC normalization, because normalization would erase some of the very
tricks it's looking for (homoglyphs, zero-width characters). Feature extraction
and chunking run on the normalized text.

This module extracts signals; it does NOT decide scam/benign — that's the
committees' job.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass

from bs4 import BeautifulSoup, Comment

# Text nodes whose direct parent is one of these are not visible page copy.
_SKIP_TEXT_PARENTS = {
    "script", "style", "noscript", "template", "head", "title", "[document]",
}

# Zero-width / invisible characters used to break up keywords and dodge filters.
_ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff")

# Lexicons of scam-relevant phrases (lowercase). Presence, not frequency.
_URGENCY = (
    "urgent", "immediately", "act now", "right now", "expires", "expire",
    "limited time", "hurry", "last chance", "final notice", "within 24 hours",
    "24 hours", "asap", "verify now", "don't delay", "deadline",
)
_MONEY = (
    "free", "prize", "winner", "you won", "lottery", "cash reward", "reward",
    "refund", "gift card", "claim your", "bonus", "jackpot", "million",
    "inheritance", "wire transfer", "bitcoin", "cryptocurrency",
)
_CREDENTIAL = (
    "password", "verify your account", "confirm your identity", "sign in",
    "log in", "login", "ssn", "social security", "account number",
    "credit card", "cvv", "security code", "one-time", "otp",
    "update your payment", "banking details",
)
_THREAT = (
    "suspended", "terminated", "locked", "legal action", "arrested", "lawsuit",
    "penalty", "unauthorized", "fraud detected", "account closed",
    "will be deleted", "police",
)

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_URL_RE = re.compile(r"https?://[^\s]+")
_PHONE_RE = re.compile(r"\+?\d[\d\s().\-]{7,}\d")
_BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-Z0-9]{25,39}\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_CURRENCY_RE = re.compile(r"[$€£¥]")


# ---------------------------------------------------------------------------
# Typed records
# ---------------------------------------------------------------------------
@dataclass
class StructuredText:
    title: str
    meta_description: str
    headings: list[str]        # h1..h6, document order
    paragraphs: list[str]
    list_items: list[str]
    link_texts: list[str]      # anchor visible text
    button_texts: list[str]    # <button> text + submit/button input values
    image_alts: list[str]
    aria_labels: list[str]
    placeholders: list[str]
    labels: list[str]          # <label> text


@dataclass
class TextSignals:
    char_count: int
    word_count: int
    uppercase_ratio: float     # ALLCAPS words / all words
    exclamation_count: int
    urgency_hits: list[str]
    money_hits: list[str]
    credential_hits: list[str]
    threat_hits: list[str]
    phone_numbers: list[str]
    emails: list[str]
    urls_in_text: list[str]
    crypto_addresses: list[str]
    currency_symbol_count: int


@dataclass
class Obfuscation:
    has_zero_width: bool
    zero_width_count: int
    mixed_script_words: list[str]   # tokens mixing Latin with Cyrillic/Greek
    has_excessive_spacing: bool     # s p a c e d - o u t evasion


@dataclass
class TextReport:
    visible_text: str
    structured: StructuredText
    signals: TextSignals
    obfuscation: Obfuscation
    key_snippets: list[str]
    chunks: list[str]
    features: dict                  # compact, committee-facing summary

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _collapse_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _char_script(ch: str) -> str | None:
    """Classify a single character into Latin / Cyrillic / Greek, or None."""
    o = ord(ch)
    if ("a" <= ch.lower() <= "z") or (0x00C0 <= o <= 0x024F):
        return "Latin"
    if 0x0400 <= o <= 0x04FF:
        return "Cyrillic"
    if 0x0370 <= o <= 0x03FF:
        return "Greek"
    return None


def _match_terms(text_lower: str, terms: tuple[str, ...]) -> list[str]:
    return [t for t in terms if t in text_lower]


# ---------------------------------------------------------------------------
# 1. Visible text
# ---------------------------------------------------------------------------
def extract_visible_text(soup: BeautifulSoup) -> str:
    """Return the human-readable text, with code and head content removed.

    Non-mutating: it filters text nodes by parent rather than stripping tags,
    so the shared soup stays intact for scripts.py / web_code.py.
    """
    parts: list[str] = []
    for node in soup.find_all(string=True):
        if isinstance(node, Comment):
            continue
        parent = getattr(node.parent, "name", "") or ""
        if parent in _SKIP_TEXT_PARENTS:
            continue
        s = str(node).strip()
        if s:
            parts.append(s)
    return _collapse_ws(" ".join(parts))


# ---------------------------------------------------------------------------
# 2. Structured text
# ---------------------------------------------------------------------------
def _meta_description(soup: BeautifulSoup) -> str:
    for m in soup.find_all("meta"):
        if (m.get("name") or "").strip().lower() == "description":
            return (m.get("content") or "").strip()
    return ""


def extract_structured_text(soup: BeautifulSoup) -> StructuredText:
    """Pull the slots where scam signals cluster, kept separate from body prose.

    Headings and CTAs ("Verify your account now") carry far more weight per word
    than ordinary paragraph text, so preserving them lets a committee prioritize.
    """
    title_tag = soup.find("title")

    buttons = [b.get_text(strip=True) for b in soup.find_all("button")]
    for inp in soup.find_all("input"):
        if (inp.get("type") or "").lower() in ("submit", "button", "reset"):
            val = (inp.get("value") or "").strip()
            if val:
                buttons.append(val)

    def _texts(tag_names) -> list[str]:
        return [t for t in (el.get_text(strip=True) for el in soup.find_all(tag_names)) if t]

    return StructuredText(
        title=title_tag.get_text(strip=True) if title_tag else "",
        meta_description=_meta_description(soup),
        headings=_texts(["h1", "h2", "h3", "h4", "h5", "h6"]),
        paragraphs=_texts("p"),
        list_items=_texts("li"),
        link_texts=_texts("a"),
        button_texts=[b for b in buttons if b],
        image_alts=[a for a in ((img.get("alt") or "").strip() for img in soup.find_all("img")) if a],
        aria_labels=[
            v for v in ((el.get("aria-label") or "").strip() for el in soup.find_all(attrs={"aria-label": True})) if v
        ],
        placeholders=[
            v for v in ((el.get("placeholder") or "").strip() for el in soup.find_all(attrs={"placeholder": True})) if v
        ],
        labels=_texts("label"),
    )


# ---------------------------------------------------------------------------
# 3. Normalization
# ---------------------------------------------------------------------------
def normalize_text(text: str) -> str:
    """NFKC-normalize and collapse whitespace into a canonical readable form."""
    return _collapse_ws(unicodedata.normalize("NFKC", text))


# ---------------------------------------------------------------------------
# 4. Obfuscation detection (runs on RAW text, before normalization)
# ---------------------------------------------------------------------------
def detect_text_obfuscation(text: str) -> Obfuscation:
    """Flag text-level evasion: zero-width chars, homoglyphs, spaced-out words.

    These exist specifically to fool keyword filters like this one, which is
    exactly why their presence is a signal. Must run before NFKC normalization,
    which would erase some of them.
    """
    zero_width_count = sum(text.count(z) for z in _ZERO_WIDTH)

    mixed: list[str] = []
    seen: set[str] = set()
    for word in text.split():
        scripts = {s for s in (_char_script(c) for c in word) if s}
        if len(scripts) > 1 and word not in seen:
            seen.add(word)
            mixed.append(word)

    # Longest run of consecutive single-letter tokens ("V E R I F Y").
    best = run = 0
    for tok in text.split():
        if len(tok) == 1 and tok.isalpha():
            run += 1
            best = max(best, run)
        else:
            run = 0

    return Obfuscation(
        has_zero_width=zero_width_count > 0,
        zero_width_count=zero_width_count,
        mixed_script_words=mixed,
        has_excessive_spacing=best >= 4,
    )


# ---------------------------------------------------------------------------
# 5. Linguistic signals
# ---------------------------------------------------------------------------
def extract_text_signals(text: str) -> TextSignals:
    """Extract scam-relevant linguistic features from (normalized) text."""
    lower = text.lower()
    alpha_words = re.findall(r"[A-Za-z]+", text)
    allcaps = [w for w in alpha_words if len(w) >= 2 and w.isupper()]

    return TextSignals(
        char_count=len(text),
        word_count=len(re.findall(r"\b\w+\b", text)),
        uppercase_ratio=(len(allcaps) / len(alpha_words)) if alpha_words else 0.0,
        exclamation_count=text.count("!"),
        urgency_hits=_match_terms(lower, _URGENCY),
        money_hits=_match_terms(lower, _MONEY),
        credential_hits=_match_terms(lower, _CREDENTIAL),
        threat_hits=_match_terms(lower, _THREAT),
        phone_numbers=_PHONE_RE.findall(text),
        emails=_EMAIL_RE.findall(text),
        urls_in_text=_URL_RE.findall(text),
        crypto_addresses=_BTC_RE.findall(text) + _ETH_RE.findall(text),
        currency_symbol_count=len(_CURRENCY_RE.findall(text)),
    )


# ---------------------------------------------------------------------------
# 6. Key snippets
# ---------------------------------------------------------------------------
def extract_key_snippets(structured: StructuredText, limit: int = 10) -> list[str]:
    """The few highest-signal short strings: title, headings, CTAs, description.

    Lets a committee get a cheap first read before spending budget on full-body
    chunks.
    """
    ordered = []
    if structured.title:
        ordered.append(structured.title)
    ordered.extend(structured.headings)
    ordered.extend(structured.button_texts)
    if structured.meta_description:
        ordered.append(structured.meta_description)

    out: list[str] = []
    seen: set[str] = set()
    for s in ordered:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# 7. Segmentation
# ---------------------------------------------------------------------------
def segment_text(text: str, max_chars: int = 800) -> list[str]:
    """Chunk text at sentence boundaries into windows under max_chars.

    Character-budgeted (a rough proxy for a small model's token window); a single
    oversized sentence is hard-split as a fallback.
    """
    text = text.strip()
    if not text:
        return []

    sentences = re.split(r"(?<=[.!?])\s+", text)
    chunks: list[str] = []
    cur = ""
    for s in sentences:
        if not cur:
            cur = s
        elif len(cur) + 1 + len(s) <= max_chars:
            cur += " " + s
        else:
            chunks.append(cur)
            cur = s
    if cur:
        chunks.append(cur)

    final: list[str] = []
    for c in chunks:
        if len(c) <= max_chars:
            final.append(c)
        else:
            final.extend(c[i:i + max_chars] for i in range(0, len(c), max_chars))
    return final


# ---------------------------------------------------------------------------
# 8. Assemble the report
# ---------------------------------------------------------------------------
def build_text_report(soup: BeautifulSoup) -> TextReport:
    """Run every extractor and assemble one text report for a single page."""
    visible = extract_visible_text(soup)
    structured = extract_structured_text(soup)
    obfuscation = detect_text_obfuscation(visible)     # raw, pre-NFKC
    normalized = normalize_text(visible)
    signals = extract_text_signals(normalized)
    snippets = extract_key_snippets(structured)
    chunks = segment_text(normalized)

    features = {
        "char_count": signals.char_count,
        "word_count": signals.word_count,
        "uppercase_ratio": round(signals.uppercase_ratio, 3),
        "exclamation_count": signals.exclamation_count,
        "urgency_hit_count": len(signals.urgency_hits),
        "money_hit_count": len(signals.money_hits),
        "credential_hit_count": len(signals.credential_hits),
        "threat_hit_count": len(signals.threat_hits),
        "phone_number_count": len(signals.phone_numbers),
        "email_count": len(signals.emails),
        "crypto_address_count": len(signals.crypto_addresses),
        "currency_symbol_count": signals.currency_symbol_count,
        "has_zero_width": obfuscation.has_zero_width,
        "mixed_script_word_count": len(obfuscation.mixed_script_words),
        "has_excessive_spacing": obfuscation.has_excessive_spacing,
        "chunk_count": len(chunks),
        "title": structured.title,
    }

    return TextReport(
        visible_text=visible,
        structured=structured,
        signals=signals,
        obfuscation=obfuscation,
        key_snippets=snippets,
        chunks=chunks,
        features=features,
    )


def report_from_html(html: str) -> TextReport:
    """Convenience wrapper: parse `html` then build the report.

    analysis.py should call build_text_report with the shared soup instead;
    this exists for standalone use and tests.
    """
    return build_text_report(BeautifulSoup(html, "html.parser"))