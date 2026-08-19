"""
web_code.py — the HTML / CSS / "everything structural" worker.

Owns the first of the three analysis categories: how a page is *built* and
*presented*, as opposed to what it says (text.py) or what it runs (scripts.py).
Given a parsed page it produces typed, JSON-serializable records plus a compact
`features` summary, all aimed at the structural tricks scams rely on:

  * forms whose action posts credentials off-domain or over plain http
  * content cloaked with CSS / attributes (present for a model, hidden from a user)
  * iframes and resources pulled from foreign origins
  * meta-refresh redirects, brand-mismatched metadata
  * lopsided outbound-link patterns

Design contract (matches analysis.py's "parse once" rule): the public entry
point `build_web_code_report` takes an already-parsed BeautifulSoup tree plus
the page's URL and the site's registrable `home_domain`. The URL is needed to
resolve relative references; the home domain is needed to tell first-party from
third-party. `report_from_html` is a convenience wrapper that parses first, for
standalone use and tests.

This module extracts signals; it does NOT decide scam/benign. That verdict is
the committees' job.

Limitation worth knowing: hidden-element detection inspects inline `style`
attributes and hiding attributes (`hidden`, `aria-hidden`). Rules living in
`<style>` blocks or external stylesheets are counted as a suspicion signal but
are not matched back to individual elements — that would need a full CSS cascade
engine, which is out of scope here.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from bs4.element import Tag

from analysis.crawler import get_domain

# Substrings in a field's name/id/autocomplete that suggest payment/PII capture.
_PAYMENT_TOKENS = (
    "cardnumber", "card-number", "ccnumber", "cc-number", "creditcard",
    "credit-card", "cvv", "cvc", "cvn", "cc-csc", "cardexpiry", "cc-exp",
    "exp-date", "expiry", "iban", "sortcode", "sort-code", "routing",
    "accountnumber", "account-number", "ssn", "socialsecurity",
)
# link rel values that pull a resource without being a stylesheet or script.
_PRELOAD_RELS = {"preload", "prefetch", "dns-prefetch", "preconnect", "modulepreload"}


# ---------------------------------------------------------------------------
# Typed records
# ---------------------------------------------------------------------------
@dataclass
class FormField:
    name: str
    type: str
    autocomplete: str
    placeholder: str
    hidden: bool


@dataclass
class FormInfo:
    action: str                       # raw action attribute, as written
    action_url: str                   # resolved absolute action
    action_domain: str                # registrable domain of the action ("None" if n/a)
    action_off_domain: bool           # action leaves the site's domain
    action_insecure: bool             # action resolves to http:// (plaintext)
    method: str                       # get | post | "" (defaults to get)
    input_count: int                  # inputs + selects + textareas
    hidden_input_count: int
    field_type_counts: dict[str, int]
    has_password_field: bool
    has_email_field: bool
    has_payment_field: bool
    fields: list[FormField]


@dataclass
class HiddenElement:
    tag: str
    technique: str                    # e.g. "display:none", "offscreen", "aria-hidden"
    identifier: str                   # tag#id.class summary
    text_preview: str                 # what's being hidden (truncated)


@dataclass
class StylesheetRef:
    href: str
    url: str
    domain: str
    off_domain: bool


@dataclass
class CssBundle:
    inline_style_count: int
    style_block_count: int
    style_blocks: list[str]           # raw <style> contents (chunked later)
    stylesheets: list[StylesheetRef]
    third_party_stylesheet_count: int
    suspicious_declaration_count: int  # hiding declarations seen in <style> blocks


@dataclass
class Metadata:
    title: str
    description: str
    keywords: str
    lang: str
    charset: str
    favicon: str
    canonical: str
    generator: str
    og: dict[str, str]
    meta_refresh: dict | None         # {"delay": str, "url": str} or None


@dataclass
class DomSkeleton:
    element_count: int
    max_depth: int
    tag_counts: dict[str, int]
    outline: str                      # bounded, indented tag-only outline


@dataclass
class ResourceRef:
    kind: str                         # image | iframe | object | embed | media | preload
    url: str
    domain: str
    off_domain: bool


@dataclass
class ResourceInventory:
    resources: list[ResourceRef]
    counts: dict[str, int]            # per-kind counts
    third_party_domains: list[str]


@dataclass
class LinkBuckets:
    internal: list[str]
    external: list[str]
    mailto: list[str]
    tel: list[str]
    other: list[str]                  # javascript:, fragment-only, data:, etc.
    external_domains: list[str]
    counts: dict[str, int]
    outbound_ratio: float             # external / (internal + external)


@dataclass
class WebCodeReport:
    url: str
    home_domain: str
    skeleton: DomSkeleton
    forms: list[FormInfo]
    css: CssBundle
    hidden_elements: list[HiddenElement]
    metadata: Metadata
    resources: ResourceInventory
    links: LinkBuckets
    features: dict                    # compact, committee-facing summary

    def to_dict(self) -> dict:
        """Fully JSON-serializable view (nested dataclasses flattened)."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------
def _attr(tag: Tag, name: str) -> str:
    """Return an attribute as a stripped string; '' if absent or list-valued oddly."""
    value = tag.get(name)
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(value).strip()
    return str(value).strip()


def _off_domain(url: str, home_domain: str) -> bool:
    """True if url has a registrable domain different from home_domain."""
    dom = get_domain(url)
    return dom != "None" and dom != home_domain


def _identifier(tag: Tag) -> str:
    ident = tag.name
    tid = _attr(tag, "id")
    if tid:
        ident += f"#{tid}"
    classes = tag.get("class") or []
    if classes:
        ident += "." + ".".join(classes[:3])
    return ident[:80]


def _text_preview(tag: Tag, limit: int = 120) -> str:
    return tag.get_text(" ", strip=True)[:limit]


# ---------------------------------------------------------------------------
# 1. DOM skeleton
# ---------------------------------------------------------------------------
def extract_dom_skeleton(
    soup: BeautifulSoup,
    max_depth: int = 6,
    max_children: int = 10,
    max_lines: int = 120,
) -> DomSkeleton:
    """Summarize page structure with text and scripts stripped away.

    Produces tag-frequency counts, the maximum nesting depth, a total element
    count, and a bounded indented outline. Structural anomalies — a "login"
    page that's really one giant obfuscated div, or a deeply nested wrapper
    hiding an overlay — show up here cheaply and fit a small context window.
    """
    all_tags = soup.find_all(True)
    tag_counts = dict(Counter(t.name for t in all_tags))

    root = soup.find("html") or soup

    # Max depth, computed iteratively to survive pathologically deep pages.
    max_seen = 0
    stack = [(root, 1)]
    while stack:
        el, depth = stack.pop()
        if depth > max_seen:
            max_seen = depth
        for child in el.children:
            if getattr(child, "name", None):
                stack.append((child, depth + 1))

    # Bounded, indented, tag-only outline.
    lines: list[str] = []

    def walk(el: Tag, depth: int) -> None:
        if depth >= max_depth or len(lines) >= max_lines:
            return
        children = [c for c in el.children if getattr(c, "name", None)]
        for child in children[:max_children]:
            if len(lines) >= max_lines:
                break
            lines.append("  " * depth + child.name)
            walk(child, depth + 1)
        if len(children) > max_children and len(lines) < max_lines:
            lines.append("  " * depth + f"... (+{len(children) - max_children} more)")

    walk(root, 0)

    return DomSkeleton(
        element_count=len(all_tags),
        max_depth=max_seen,
        tag_counts=tag_counts,
        outline="\n".join(lines[:max_lines]),
    )


# ---------------------------------------------------------------------------
# 2. Forms  (highest-value structural signal)
# ---------------------------------------------------------------------------
def _field_info(tag: Tag) -> FormField:
    if tag.name == "input":
        ftype = _attr(tag, "type").lower() or "text"
    else:  # select / textarea
        ftype = tag.name
    return FormField(
        name=_attr(tag, "name") or _attr(tag, "id"),
        type=ftype,
        autocomplete=_attr(tag, "autocomplete").lower(),
        placeholder=_attr(tag, "placeholder"),
        hidden=(ftype == "hidden"),
    )


def _looks_like_payment(f: FormField) -> bool:
    haystack = f"{f.name} {f.autocomplete}".lower()
    return any(tok in haystack for tok in _PAYMENT_TOKENS)


def _looks_like_email(f: FormField) -> bool:
    return f.type == "email" or "email" in f"{f.name} {f.autocomplete}".lower()


def extract_forms(soup: BeautifulSoup, base_url: str, home_domain: str) -> list[FormInfo]:
    """Describe every <form>: where it submits, how, and what it collects.

    The single richest web-code signal for phishing. A form that posts a
    password or card number to a *different* registrable domain, or over plain
    http, is exactly the shape credential theft takes. Each form is isolated as
    its own record so a committee can score it without the rest of the page.
    """
    forms: list[FormInfo] = []
    for form in soup.find_all("form"):
        raw_action = _attr(form, "action")
        action_url = urljoin(base_url, raw_action) if raw_action else base_url
        action_domain = get_domain(action_url)
        scheme = urlsplit(action_url).scheme.lower()

        fields = [_field_info(t) for t in form.find_all(["input", "select", "textarea"])]
        type_counts = dict(Counter(f.type for f in fields))

        forms.append(
            FormInfo(
                action=raw_action,
                action_url=action_url,
                action_domain=action_domain,
                action_off_domain=_off_domain(action_url, home_domain),
                action_insecure=(scheme == "http"),
                method=_attr(form, "method").lower(),
                input_count=len(fields),
                hidden_input_count=sum(1 for f in fields if f.hidden),
                field_type_counts=type_counts,
                has_password_field=any(f.type == "password" for f in fields),
                has_email_field=any(_looks_like_email(f) for f in fields),
                has_payment_field=any(_looks_like_payment(f) for f in fields),
                fields=fields,
            )
        )
    return forms


# ---------------------------------------------------------------------------
# 3. CSS inventory
# ---------------------------------------------------------------------------
# Declarations that hide content, in whitespace-stripped, lowercased form.
_HIDING_PATTERNS = (
    re.compile(r"display:none"),
    re.compile(r"visibility:hidden"),
    re.compile(r"opacity:0(?:\.0+)?(?:;|!|$)"),
    re.compile(r"font-size:0(?:px|em|rem|pt)?(?:;|!|$)"),
    re.compile(r"text-indent:-\d"),
    re.compile(r"clip:rect\(0"),
    re.compile(r"(?:left|top):-\d{3,}"),
)


def extract_css(soup: BeautifulSoup, base_url: str, home_domain: str) -> CssBundle:
    """Inventory the three CSS sources: inline styles, <style> blocks, links.

    Keeps raw <style> text (chunked downstream if large) and classifies linked
    stylesheets by origin. Also counts hiding declarations that appear in
    <style> blocks as a coarse cloaking signal (not matched to elements — see
    the module note).
    """
    inline_count = len(soup.select("[style]"))

    style_blocks = [tag.get_text() for tag in soup.find_all("style")]
    suspicious = 0
    for block in style_blocks:
        norm = re.sub(r"\s+", "", block.lower())
        suspicious += sum(len(p.findall(norm)) for p in _HIDING_PATTERNS)

    stylesheets: list[StylesheetRef] = []
    for link in soup.find_all("link", href=True):
        rels = [r.lower() for r in (link.get("rel") or [])]
        if "stylesheet" not in rels:
            continue
        href = _attr(link, "href")
        url = urljoin(base_url, href)
        stylesheets.append(
            StylesheetRef(
                href=href,
                url=url,
                domain=get_domain(url),
                off_domain=_off_domain(url, home_domain),
            )
        )

    return CssBundle(
        inline_style_count=inline_count,
        style_block_count=len(style_blocks),
        style_blocks=style_blocks,
        stylesheets=stylesheets,
        third_party_stylesheet_count=sum(1 for s in stylesheets if s.off_domain),
        suspicious_declaration_count=suspicious,
    )


# ---------------------------------------------------------------------------
# 4. Hidden / cloaked elements
# ---------------------------------------------------------------------------
def _hidden_technique(style_norm: str) -> str | None:
    """Return the hiding technique for a normalized inline style, or None."""
    if "display:none" in style_norm:
        return "display:none"
    if "visibility:hidden" in style_norm:
        return "visibility:hidden"
    if re.search(r"opacity:0(?:\.0+)?(?:;|!|$)", style_norm):
        return "opacity:0"
    if re.search(r"font-size:0(?:px|em|rem|pt)?(?:;|!|$)", style_norm):
        return "tiny-font"
    if re.search(r"width:0(?:px)?(?:;|!|$)", style_norm) and re.search(
        r"height:0(?:px)?(?:;|!|$)", style_norm
    ):
        return "zero-size"
    if re.search(r"text-indent:-\d", style_norm) or re.search(r"(?:left|top):-\d{3,}", style_norm):
        return "offscreen"
    if "clip:rect(0" in style_norm:
        return "clip"
    return None


def detect_hidden_elements(soup: BeautifulSoup, max_hits: int = 200) -> list[HiddenElement]:
    """Find content hidden from users but still present for a crawler/model.

    Cloaking — invisible text stuffed with keywords, an off-screen overlay
    form — is a strong scam tell. Inputs are skipped (a type="hidden" input is
    a normal form mechanism, captured in the form record instead).
    """
    hits: list[HiddenElement] = []
    for el in soup.find_all(True):
        if el.name in ("input", "style", "script", "meta", "link"):
            continue
        technique: str | None = None

        style = _attr(el, "style")
        if style:
            technique = _hidden_technique(re.sub(r"\s+", "", style.lower()))
        if technique is None and el.has_attr("hidden"):
            technique = "hidden-attr"
        if technique is None and _attr(el, "aria-hidden").lower() == "true":
            technique = "aria-hidden"

        if technique is not None:
            hits.append(
                HiddenElement(
                    tag=el.name,
                    technique=technique,
                    identifier=_identifier(el),
                    text_preview=_text_preview(el),
                )
            )
            if len(hits) >= max_hits:
                break
    return hits


# ---------------------------------------------------------------------------
# 5. Metadata
# ---------------------------------------------------------------------------
def _meta_content(soup: BeautifulSoup, name: str) -> str:
    for m in soup.find_all("meta"):
        if _attr(m, "name").lower() == name.lower():
            return _attr(m, "content")
    return ""


def _charset(soup: BeautifulSoup) -> str:
    m = soup.find("meta", charset=True)
    if m:
        return _attr(m, "charset")
    for m in soup.find_all("meta"):
        if _attr(m, "http-equiv").lower() == "content-type":
            match = re.search(r"charset=([\w-]+)", _attr(m, "content"), re.I)
            if match:
                return match.group(1)
    return ""


def _link_href_by_rel(soup: BeautifulSoup, base_url: str, rel_token: str) -> str:
    for link in soup.find_all("link", href=True):
        rels = " ".join(link.get("rel") or []).lower()
        if rel_token in rels:
            return urljoin(base_url, _attr(link, "href"))
    return ""


def _parse_meta_refresh(soup: BeautifulSoup) -> dict | None:
    for m in soup.find_all("meta"):
        if _attr(m, "http-equiv").lower() != "refresh":
            continue
        content = _attr(m, "content")
        delay, _, rest = content.partition(";")
        url = ""
        rest = rest.strip()
        if rest.lower().startswith("url="):
            url = rest[4:].strip().strip("'\"")
        return {"delay": delay.strip(), "url": url}
    return None


def extract_metadata(soup: BeautifulSoup, base_url: str) -> Metadata:
    """Pull <title>, meta tags, lang, charset, favicon, canonical, OG tags, and
    any meta-refresh redirect.

    Feeds brand-impersonation checks (an og:site_name of a bank on a random
    domain), language/geography mismatch, and — importantly — meta-refresh,
    which is a classic silent redirect used to bounce victims onward.
    """
    title_tag = soup.find("title")
    og = {}
    for m in soup.find_all("meta", attrs={"property": True}):
        prop = _attr(m, "property").lower()
        if prop.startswith("og:"):
            og[prop] = _attr(m, "content")

    html_tag = soup.find("html")
    return Metadata(
        title=title_tag.get_text(strip=True) if title_tag else "",
        description=_meta_content(soup, "description"),
        keywords=_meta_content(soup, "keywords"),
        lang=_attr(html_tag, "lang") if html_tag else "",
        charset=_charset(soup),
        favicon=_link_href_by_rel(soup, base_url, "icon"),
        canonical=_link_href_by_rel(soup, base_url, "canonical"),
        generator=_meta_content(soup, "generator"),
        og=og,
        meta_refresh=_parse_meta_refresh(soup),
    )


# ---------------------------------------------------------------------------
# 6. Resource references
# ---------------------------------------------------------------------------
def extract_resource_references(
    soup: BeautifulSoup, base_url: str, home_domain: str
) -> ResourceInventory:
    """Inventory non-script external resources by origin.

    Covers images, iframes, objects/embeds, media, and preload-style link
    hints. Iframes and objects loaded from foreign origins are laundering /
    overlay signals; a heavy third-party footprint is itself informative.
    Stylesheets are handled in extract_css; scripts belong to scripts.py.
    """
    specs = [
        ("image", "img", "src"),
        ("iframe", "iframe", "src"),
        ("object", "object", "data"),
        ("embed", "embed", "src"),
        ("media", "source", "src"),
        ("media", "video", "src"),
        ("media", "audio", "src"),
    ]
    resources: list[ResourceRef] = []
    for kind, tag_name, attr in specs:
        for tag in soup.find_all(tag_name):
            ref = _attr(tag, attr)
            if not ref:
                continue
            url = urljoin(base_url, ref)
            resources.append(
                ResourceRef(
                    kind=kind,
                    url=url,
                    domain=get_domain(url),
                    off_domain=_off_domain(url, home_domain),
                )
            )

    for link in soup.find_all("link", href=True):
        rels = {r.lower() for r in (link.get("rel") or [])}
        if rels & _PRELOAD_RELS:
            url = urljoin(base_url, _attr(link, "href"))
            resources.append(
                ResourceRef(
                    kind="preload",
                    url=url,
                    domain=get_domain(url),
                    off_domain=_off_domain(url, home_domain),
                )
            )

    counts = dict(Counter(r.kind for r in resources))
    third_party = sorted({r.domain for r in resources if r.off_domain and r.domain != "None"})
    return ResourceInventory(resources=resources, counts=counts, third_party_domains=third_party)


# ---------------------------------------------------------------------------
# 7. Link classification
# ---------------------------------------------------------------------------
def classify_links(soup: BeautifulSoup, base_url: str, home_domain: str) -> LinkBuckets:
    """Split anchors into internal / external / mailto / tel / other.

    Outbound-link ratio and the set of external domains are cheap, informative
    features; a page that is mostly links off to unrelated domains reads
    differently from a normal site.
    """
    internal: list[str] = []
    external: list[str] = []
    mailto: list[str] = []
    tel: list[str] = []
    other: list[str] = []

    for a in soup.find_all("a", href=True):
        raw = _attr(a, "href")
        low = raw.lower()
        if low.startswith("#") or not raw:
            other.append(raw)
        elif low.startswith("mailto:"):
            mailto.append(raw[len("mailto:"):].split("?", 1)[0])
        elif low.startswith("tel:"):
            tel.append(raw[len("tel:"):])
        elif low.startswith(("javascript:", "data:")):
            other.append(raw)
        else:
            url = urljoin(base_url, raw)
            if _off_domain(url, home_domain):
                external.append(url)
            else:
                internal.append(url)

    external_domains = sorted({get_domain(u) for u in external if get_domain(u) != "None"})
    reachable = len(internal) + len(external)
    counts = {
        "internal": len(internal),
        "external": len(external),
        "mailto": len(mailto),
        "tel": len(tel),
        "other": len(other),
        "total": len(internal) + len(external) + len(mailto) + len(tel) + len(other),
    }
    return LinkBuckets(
        internal=internal,
        external=external,
        mailto=mailto,
        tel=tel,
        other=other,
        external_domains=external_domains,
        counts=counts,
        outbound_ratio=(len(external) / reachable) if reachable else 0.0,
    )


# ---------------------------------------------------------------------------
# 8. Assemble the report
# ---------------------------------------------------------------------------
def build_web_code_report(
    soup: BeautifulSoup, page_url: str, home_domain: str
) -> WebCodeReport:
    """Run every extractor and assemble one report for a single page.

    `soup` is the shared parse from analysis.py; `page_url` resolves relative
    references; `home_domain` is the site's registrable domain (from the
    crawler's get_domain on the seed). The `features` dict is the compact,
    committee-facing view; the rest is raw material for building artifacts.
    """
    skeleton = extract_dom_skeleton(soup)
    forms = extract_forms(soup, page_url, home_domain)
    css = extract_css(soup, page_url, home_domain)
    hidden = detect_hidden_elements(soup)
    metadata = extract_metadata(soup, page_url)
    resources = extract_resource_references(soup, page_url, home_domain)
    links = classify_links(soup, page_url, home_domain)

    refresh_off_domain = False
    if metadata.meta_refresh and metadata.meta_refresh.get("url"):
        refresh_target = urljoin(page_url, metadata.meta_refresh["url"])
        refresh_off_domain = _off_domain(refresh_target, home_domain)

    features = {
        "form_count": len(forms),
        "has_password_form": any(f.has_password_field for f in forms),
        "has_payment_form": any(f.has_payment_field for f in forms),
        "has_off_domain_form_action": any(f.action_off_domain for f in forms),
        "has_insecure_form_action": any(f.action_insecure for f in forms),
        "hidden_element_count": len(hidden),
        "iframe_count": resources.counts.get("iframe", 0),
        "third_party_iframe_count": sum(
            1 for r in resources.resources if r.kind == "iframe" and r.off_domain
        ),
        "third_party_resource_domain_count": len(resources.third_party_domains),
        "third_party_resource_domains": resources.third_party_domains[:20],
        "third_party_stylesheet_count": css.third_party_stylesheet_count,
        "suspicious_css_declaration_count": css.suspicious_declaration_count,
        "external_link_count": links.counts["external"],
        "outbound_ratio": round(links.outbound_ratio, 3),
        "has_meta_refresh": metadata.meta_refresh is not None,
        "meta_refresh_off_domain": refresh_off_domain,
        "max_dom_depth": skeleton.max_depth,
        "element_count": skeleton.element_count,
        "title": metadata.title,
    }

    return WebCodeReport(
        url=page_url,
        home_domain=home_domain,
        skeleton=skeleton,
        forms=forms,
        css=css,
        hidden_elements=hidden,
        metadata=metadata,
        resources=resources,
        links=links,
        features=features,
    )


def report_from_html(html: str, page_url: str, home_domain: str) -> WebCodeReport:
    """Convenience wrapper: parse `html` then build the report.

    analysis.py should call build_web_code_report with the shared soup instead;
    this exists for standalone use and tests.
    """
    return build_web_code_report(BeautifulSoup(html, "html.parser"), page_url, home_domain)