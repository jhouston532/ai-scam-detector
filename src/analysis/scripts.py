"""
scripts.py — the executable-layer worker.

Owns the second analysis category: everything on a page that runs, as opposed
to how the page is built (web_code.py) or what it says (text.py). Scripts carry
the most dangerous and most obfuscated scam behavior — silent redirects,
credential exfiltration, form hijacking, fingerprinting — and raw JavaScript
blows a small model's context window fast, so this module isolates it, flags
risky patterns, and chunks large bodies into digestible windows.

Design contract (matches analysis.py's "parse once" rule): the public entry
point `build_scripts_report` takes an already-parsed BeautifulSoup tree plus the
page's URL (to resolve external `src`) and the site's `home_domain` (to tell
first-party from third-party). `report_from_html` parses first, for standalone
use and tests.

SAFETY / SCOPE: this module is read-only signal extraction. It does NOT execute
scripts, and it does NOT deobfuscate — `normalize_script` only removes block
comments and collapses whitespace; it never decodes escape sequences or unpacks
anything, so it cannot reconstruct a working payload. Feature detection merely
records that a risky API *appears*; deciding scam/benign is the committees' job.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from bs4.element import Tag

from analysis.crawler import get_domain

# <script type="..."> values that are data/templates, not executable JS.
_DATA_SCRIPT_TYPES = {
    "application/ld+json", "application/json", "text/template", "text/html",
    "application/xml", "text/x-template",
}

# Registrable domains recognized as analytics/trackers and as generic CDNs.
_TRACKER_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.net", "hotjar.com", "segment.com", "mixpanel.com",
    "scorecardresearch.com", "quantserve.com",
}
_CDN_DOMAINS = {
    "jsdelivr.net", "unpkg.com", "cloudflare.com", "cloudflareinsights.com",
    "googleapis.com", "gstatic.com", "bootstrapcdn.com", "jquery.com",
    "cdnjs.com",
}

# --- feature-detection patterns (case-sensitive: JS identifiers have fixed case) ---
_RE_EVAL = re.compile(r"\beval\s*\(")
_RE_FUNCTION_CTOR = re.compile(r"\bnew\s+Function\b|\bFunction\s*\(")
_RE_BASE64 = re.compile(r"\b(?:atob|btoa)\s*\(")
_RE_DOC_WRITE = re.compile(r"document\s*\.\s*write")
_RE_FROM_CHAR = re.compile(r"fromCharCode")
_RE_REDIRECT = re.compile(r"location\s*\.\s*(?:href|replace|assign)|window\s*\.\s*location")
_RE_KEYBOARD = re.compile(
    r"addEventListener\s*\(\s*['\"](?:keydown|keyup|keypress)['\"]|onkey(?:down|up|press)"
)
_RE_FORMS = re.compile(r"addEventListener\s*\(\s*['\"]submit['\"]|\.submit\s*\(|onsubmit")
_RE_COOKIE = re.compile(r"document\s*\.\s*cookie")
_RE_HIGH_ENTROPY = re.compile(r"\S{200,}")
_ESCAPE_RUN_RES = (
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}"),
    re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"),
    re.compile(r"(?:%[0-9a-fA-F]{2}){6,}"),
)


# ---------------------------------------------------------------------------
# Typed records
# ---------------------------------------------------------------------------
@dataclass
class ScriptFeatures:
    length: int
    uses_eval: bool
    uses_function_ctor: bool
    uses_base64: bool
    uses_document_write: bool
    uses_from_char_code: bool
    uses_redirect: bool
    listens_keyboard: bool
    hooks_forms: bool
    uses_cookie_access: bool
    long_escape_runs: int
    high_entropy: bool
    suspicious_score: int


@dataclass
class InlineScript:
    code: str                 # normalized (comments stripped, whitespace collapsed)
    length: int
    features: ScriptFeatures
    chunks: list[str]


@dataclass
class ExternalScript:
    src: str                  # raw src attribute
    url: str                  # resolved absolute
    domain: str
    off_domain: bool
    origin: str               # first-party | third-party | known-tracker | known-cdn
    is_async: bool
    is_defer: bool


@dataclass
class EventHandler:
    tag: str
    attribute: str            # e.g. "onclick"
    code: str
    identifier: str


@dataclass
class ScriptsReport:
    inline_scripts: list[InlineScript]
    external_scripts: list[ExternalScript]
    event_handlers: list[EventHandler]
    javascript_urls: list[str]
    json_data_block_count: int
    features: dict

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _attr(tag: Tag, name: str) -> str:
    value = tag.get(name)
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(value).strip()
    return str(value).strip()


def _identifier(tag: Tag) -> str:
    ident = tag.name
    tid = _attr(tag, "id")
    if tid:
        ident += f"#{tid}"
    classes = tag.get("class") or []
    if classes:
        ident += "." + ".".join(classes[:3])
    return ident[:80]


def _off_domain(url: str, home_domain: str) -> bool:
    dom = get_domain(url)
    return dom != "None" and dom != home_domain


def _script_type(tag: Tag) -> str:
    return (tag.get("type") or "").strip().lower()


# ---------------------------------------------------------------------------
# 1. Inline scripts
# ---------------------------------------------------------------------------
def extract_inline_scripts(soup: BeautifulSoup) -> list[str]:
    """Return the raw bodies of executable <script> elements (no src).

    Data/template blocks (application/ld+json, text/template, ...) are excluded —
    they're not code — and counted separately by count_json_data_blocks.
    """
    out: list[str] = []
    for s in soup.find_all("script"):
        if s.has_attr("src"):
            continue
        if _script_type(s) in _DATA_SCRIPT_TYPES:
            continue
        code = s.get_text().strip()
        if code:
            out.append(code)
    return out


def count_json_data_blocks(soup: BeautifulSoup) -> int:
    """Count inline <script> blocks that carry data/templates rather than code."""
    return sum(
        1
        for s in soup.find_all("script")
        if not s.has_attr("src") and _script_type(s) in _DATA_SCRIPT_TYPES
    )


# ---------------------------------------------------------------------------
# 2. External scripts
# ---------------------------------------------------------------------------
def _classify_origin(domain: str, off_domain: bool) -> str:
    if not off_domain:
        return "first-party"
    if domain in _TRACKER_DOMAINS:
        return "known-tracker"
    if domain in _CDN_DOMAINS:
        return "known-cdn"
    return "third-party"


def extract_external_scripts(
    soup: BeautifulSoup, base_url: str, home_domain: str
) -> list[ExternalScript]:
    """Record every <script src>, classified by origin.

    You usually can't fetch and evaluate a third-party script body locally, so
    the *reference* — its URL and origin — is the artifact. An unknown
    third-party script on a credential page deserves a committee's attention.
    """
    scripts: list[ExternalScript] = []
    for s in soup.find_all("script", src=True):
        src = _attr(s, "src")
        url = urljoin(base_url, src)
        domain = get_domain(url)
        off = _off_domain(url, home_domain)
        scripts.append(
            ExternalScript(
                src=src,
                url=url,
                domain=domain,
                off_domain=off,
                origin=_classify_origin(domain, off),
                is_async=s.has_attr("async"),
                is_defer=s.has_attr("defer"),
            )
        )
    return scripts


# ---------------------------------------------------------------------------
# 3. Event-handler attributes
# ---------------------------------------------------------------------------
def extract_event_handlers(soup: BeautifulSoup) -> list[EventHandler]:
    """Collect inline on* attribute handlers (onclick, onload, onerror, ...).

    A common place to stash redirect and form-hijack logic outside <script>.
    """
    handlers: list[EventHandler] = []
    for el in soup.find_all(True):
        for attr, value in el.attrs.items():
            if attr.lower().startswith("on"):
                code = value if isinstance(value, str) else " ".join(value)
                handlers.append(
                    EventHandler(
                        tag=el.name,
                        attribute=attr.lower(),
                        code=code,
                        identifier=_identifier(el),
                    )
                )
    return handlers


# ---------------------------------------------------------------------------
# 4. javascript: URLs
# ---------------------------------------------------------------------------
def extract_js_urls(soup: BeautifulSoup) -> list[str]:
    """Find href/src values that are javascript: URLs (small but often hostile)."""
    urls: list[str] = []
    for tag in soup.find_all(href=True):
        href = _attr(tag, "href")
        if href.lower().startswith("javascript:"):
            urls.append(href)
    for tag in soup.find_all(src=True):
        src = _attr(tag, "src")
        if src.lower().startswith("javascript:"):
            urls.append(src)
    return urls


# ---------------------------------------------------------------------------
# 5. Normalization (light — never deobfuscation)
# ---------------------------------------------------------------------------
def normalize_script(code: str) -> str:
    """Remove block comments and collapse whitespace. Nothing else.

    Line comments are intentionally left alone so URLs like http:// inside code
    aren't corrupted, and no escape decoding happens — the point is to make a
    body readable for a model, not to reveal or reconstruct a payload.
    """
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    return re.sub(r"\s+", " ", code).strip()


# ---------------------------------------------------------------------------
# 6. Feature detection
# ---------------------------------------------------------------------------
def extract_script_features(code: str) -> ScriptFeatures:
    """Flag risky JS APIs and obfuscation indicators by presence, not behavior."""
    uses_eval = bool(_RE_EVAL.search(code))
    uses_function_ctor = bool(_RE_FUNCTION_CTOR.search(code))
    uses_base64 = bool(_RE_BASE64.search(code))
    uses_document_write = bool(_RE_DOC_WRITE.search(code))
    uses_from_char_code = bool(_RE_FROM_CHAR.search(code))
    uses_redirect = bool(_RE_REDIRECT.search(code))
    listens_keyboard = bool(_RE_KEYBOARD.search(code))
    hooks_forms = bool(_RE_FORMS.search(code))
    uses_cookie_access = bool(_RE_COOKIE.search(code))
    long_escape_runs = sum(len(p.findall(code)) for p in _ESCAPE_RUN_RES)
    high_entropy = bool(_RE_HIGH_ENTROPY.search(code))

    flags = (
        uses_eval, uses_function_ctor, uses_base64, uses_document_write,
        uses_from_char_code, uses_redirect, listens_keyboard, hooks_forms,
        uses_cookie_access, high_entropy, long_escape_runs > 0,
    )
    return ScriptFeatures(
        length=len(code),
        uses_eval=uses_eval,
        uses_function_ctor=uses_function_ctor,
        uses_base64=uses_base64,
        uses_document_write=uses_document_write,
        uses_from_char_code=uses_from_char_code,
        uses_redirect=uses_redirect,
        listens_keyboard=listens_keyboard,
        hooks_forms=hooks_forms,
        uses_cookie_access=uses_cookie_access,
        long_escape_runs=long_escape_runs,
        high_entropy=high_entropy,
        suspicious_score=sum(1 for f in flags if f),
    )


# ---------------------------------------------------------------------------
# 7. Chunking
# ---------------------------------------------------------------------------
def chunk_script(code: str, max_chars: int = 1200) -> list[str]:
    """Split code into windows under max_chars, preferring statement (;) breaks.

    A single oversized statement is hard-split as a fallback so no chunk exceeds
    the budget.
    """
    code = code.strip()
    if not code:
        return []
    if len(code) <= max_chars:
        return [code]

    parts = [p for p in re.split(r"(?<=;)", code) if p]
    chunks: list[str] = []
    cur = ""
    for p in parts:
        if not cur:
            cur = p
        elif len(cur) + len(p) <= max_chars:
            cur += p
        else:
            chunks.append(cur)
            cur = p
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
def build_scripts_report(
    soup: BeautifulSoup, page_url: str, home_domain: str
) -> ScriptsReport:
    """Run every extractor and assemble one scripts report for a single page."""
    inline: list[InlineScript] = []
    for raw in extract_inline_scripts(soup):
        norm = normalize_script(raw)
        feats = extract_script_features(norm)
        inline.append(
            InlineScript(code=norm, length=len(norm), features=feats, chunks=chunk_script(norm))
        )

    external = extract_external_scripts(soup, page_url, home_domain)
    handlers = extract_event_handlers(soup)
    js_urls = extract_js_urls(soup)
    json_blocks = count_json_data_blocks(soup)

    features = {
        "inline_script_count": len(inline),
        "external_script_count": len(external),
        "third_party_script_count": sum(1 for e in external if e.off_domain),
        "known_tracker_count": sum(1 for e in external if e.origin == "known-tracker"),
        "event_handler_count": len(handlers),
        "javascript_url_count": len(js_urls),
        "json_data_block_count": json_blocks,
        "uses_eval": any(s.features.uses_eval for s in inline),
        "uses_base64": any(s.features.uses_base64 for s in inline),
        "uses_document_write": any(s.features.uses_document_write for s in inline),
        "uses_redirect": any(s.features.uses_redirect for s in inline),
        "listens_keyboard": any(s.features.listens_keyboard for s in inline),
        "hooks_forms": any(s.features.hooks_forms for s in inline),
        "uses_cookie_access": any(s.features.uses_cookie_access for s in inline),
        "has_high_entropy_script": any(s.features.high_entropy for s in inline),
        "max_suspicious_score": max((s.features.suspicious_score for s in inline), default=0),
        "total_inline_chars": sum(s.length for s in inline),
    }

    return ScriptsReport(
        inline_scripts=inline,
        external_scripts=external,
        event_handlers=handlers,
        javascript_urls=js_urls,
        json_data_block_count=json_blocks,
        features=features,
    )


def report_from_html(html: str, page_url: str, home_domain: str) -> ScriptsReport:
    """Convenience wrapper: parse `html` then build the report.

    analysis.py should call build_scripts_report with the shared soup instead;
    this exists for standalone use and tests.
    """
    return build_scripts_report(BeautifulSoup(html, "html.parser"), page_url, home_domain)