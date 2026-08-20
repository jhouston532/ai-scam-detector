"""
analysis.py — the orchestrator.

Ties the three category workers together and turns a crawled site into
committee-ready payloads:

    crawl(seed) -> {url: html}  ->  analyze_site  ->  build_committee_payloads

Responsibilities:
  * parse each page exactly once and fan the shared soup out to web_code,
    scripts, and text (the "parse once" rule the workers assume)
  * assemble a per-page record, then roll pages up to a site view with
    cross-page deduplication of shared resources
  * flatten the site view into small, self-contained per-artifact payloads
    sized for a small-context local model, each tagged with its committee
  * serialize intermediates as JSONL and expose a CLI entry point

This module decides nothing about scam/benign; it packages evidence. The
verdict is the committees' job.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from bs4 import BeautifulSoup

from analysis.crawler import get_domain
from analysis.scripts import ScriptsReport, build_scripts_report
from analysis.text import TextReport, build_text_report
from analysis.web_code import WebCodeReport, build_web_code_report

DEFAULT_MAX_CONTENT_CHARS = 2000

_QUESTIONS = {
    "text": "Does this page text indicate a scam, phishing, or fraudulent solicitation?",
    "scripts": "Does this script artifact indicate malicious or deceptive behavior?",
    "web_code": "Does this page structure indicate a phishing or deceptive site?",
}


# ---------------------------------------------------------------------------
# Typed records
# ---------------------------------------------------------------------------
@dataclass
class PageAnalysis:
    url: str
    home_domain: str
    web_code: WebCodeReport
    scripts: ScriptsReport
    text: TextReport

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SiteAnalysis:
    home_domain: str
    page_count: int
    pages: list[PageAnalysis]
    site_features: dict

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Parse + split (the three-way categorization)
# ---------------------------------------------------------------------------
def parse(html: str) -> BeautifulSoup:
    """The single shared parse. Every worker reads this same tree."""
    return BeautifulSoup(html, "html.parser")


def split_content(soup: BeautifulSoup, page_url: str, home_domain: str) -> dict:
    """Fan the shared soup out to the three category workers.

    Returns {"web_code": WebCodeReport, "scripts": ScriptsReport,
    "text": TextReport} — the literal three-way split.
    """
    return {
        "web_code": build_web_code_report(soup, page_url, home_domain),
        "scripts": build_scripts_report(soup, page_url, home_domain),
        "text": build_text_report(soup),
    }


def analyze_page(url: str, html: str, home_domain: str) -> PageAnalysis:
    """Parse one page once and assemble its three-category record."""
    parts = split_content(parse(html), url, home_domain)
    return PageAnalysis(
        url=url,
        home_domain=home_domain,
        web_code=parts["web_code"],
        scripts=parts["scripts"],
        text=parts["text"],
    )


# ---------------------------------------------------------------------------
# Site-level aggregation
# ---------------------------------------------------------------------------
def _derive_home_domain(items: list[tuple[str, str]]) -> str:
    for url, _ in items:
        dom = get_domain(url)
        if dom != "None":
            return dom
    return "None"


def _aggregate_site_features(pages: list[PageAnalysis], home_domain: str) -> dict:
    ext_script_domains: set[str] = set()
    tracker_domains: set[str] = set()
    tpr_domains: set[str] = set()
    ext_link_domains: set[str] = set()

    for p in pages:
        for e in p.scripts.external_scripts:
            if e.off_domain and e.domain != "None":
                ext_script_domains.add(e.domain)
                if e.origin == "known-tracker":
                    tracker_domains.add(e.domain)
        tpr_domains.update(p.web_code.resources.third_party_domains)
        ext_link_domains.update(p.web_code.links.external_domains)

    def wc(key):
        return (p.web_code.features[key] for p in pages)

    return {
        "page_count": len(pages),
        "form_count": sum(p.web_code.features["form_count"] for p in pages),
        "pages_with_off_domain_form_action": sum(
            1 for p in pages if p.web_code.features["has_off_domain_form_action"]
        ),
        "any_password_form": any(p.web_code.features["has_password_form"] for p in pages),
        "any_payment_form": any(p.web_code.features["has_payment_form"] for p in pages),
        "any_insecure_form_action": any(
            p.web_code.features["has_insecure_form_action"] for p in pages
        ),
        "pages_with_meta_refresh": sum(
            1 for p in pages if p.web_code.features["has_meta_refresh"]
        ),
        "pages_with_meta_refresh_off_domain": sum(
            1 for p in pages if p.web_code.features["meta_refresh_off_domain"]
        ),
        "pages_with_hidden_elements": sum(
            1 for p in pages if p.web_code.features["hidden_element_count"] > 0
        ),
        "external_script_domains": sorted(ext_script_domains),
        "known_tracker_domains": sorted(tracker_domains),
        "third_party_resource_domains": sorted(tpr_domains),
        "external_link_domains": sorted(ext_link_domains),
        "max_suspicious_script_score": max(
            (p.scripts.features["max_suspicious_score"] for p in pages), default=0
        ),
        "any_eval_script": any(p.scripts.features["uses_eval"] for p in pages),
        "any_redirect_script": any(p.scripts.features["uses_redirect"] for p in pages),
        "total_urgency_hits": sum(p.text.features["urgency_hit_count"] for p in pages),
        "total_money_hits": sum(p.text.features["money_hit_count"] for p in pages),
        "total_credential_hits": sum(p.text.features["credential_hit_count"] for p in pages),
        "total_threat_hits": sum(p.text.features["threat_hit_count"] for p in pages),
        "any_zero_width_text": any(p.text.features["has_zero_width"] for p in pages),
        "any_mixed_script_text": any(
            p.text.features["mixed_script_word_count"] > 0 for p in pages
        ),
    }


def analyze_site(pages, home_domain: str | None = None) -> SiteAnalysis:
    """Analyze a whole site from the crawler's {url: html} (or (url, html) pairs).

    home_domain defaults to the registrable domain of the first valid URL, so a
    caller can pass crawl(seed) straight through.
    """
    items = list(pages.items()) if isinstance(pages, dict) else list(pages)
    if home_domain is None:
        home_domain = _derive_home_domain(items)

    page_analyses = [analyze_page(url, html, home_domain) for url, html in items]
    return SiteAnalysis(
        home_domain=home_domain,
        page_count=len(page_analyses),
        pages=page_analyses,
        site_features=_aggregate_site_features(page_analyses, home_domain),
    )


# ---------------------------------------------------------------------------
# Committee payloads
# ---------------------------------------------------------------------------
def _compact_form(form) -> str:
    return (
        f"action={form.action_url} method={form.method or 'get'} "
        f"off_domain={form.action_off_domain} insecure={form.action_insecure} "
        f"fields={form.field_type_counts}"
    )


def _compact_metadata(meta) -> str:
    parts = [f"title={meta.title!r}", f"description={meta.description!r}"]
    if meta.meta_refresh:
        parts.append(f"meta_refresh={meta.meta_refresh}")
    if meta.og:
        parts.append(f"og={meta.og}")
    return " ".join(parts)


def _compact_hidden(hidden) -> str:
    return "; ".join(f"{h.technique}: {h.text_preview}" for h in hidden[:20])


def build_committee_payloads(site: SiteAnalysis, config: dict | None = None) -> list[dict]:
    """Flatten a site view into one small payload per artifact.

    Each payload targets one committee (text / scripts / web_code), carries the
    single artifact to score plus precomputed features and minimal context, and
    is truncated to the content budget so it fits a small model's window.
    """
    max_chars = (config or {}).get("max_content_chars", DEFAULT_MAX_CONTENT_CHARS)
    payloads: list[dict] = []
    counter = 0

    def add(url, committee, artifact_type, content, features, context):
        nonlocal counter
        payloads.append(
            {
                "payload_id": f"{url}#{committee}:{artifact_type}:{counter}",
                "site": site.home_domain,
                "url": url,
                "committee": committee,
                "artifact_type": artifact_type,
                "content": content[:max_chars],
                "features": features,
                "context": context,
                "question": _QUESTIONS[committee],
                "response_schema": {
                    "verdict": "scam|suspicious|benign",
                    "confidence": 0.0,
                    "flags": [],
                    "evidence": "",
                },
            }
        )
        counter += 1

    for page in site.pages:
        base_ctx = {"home_domain": site.home_domain, "page_title": page.web_code.metadata.title}
        tf = page.text.features

        # --- TEXT committee ---
        if page.text.key_snippets:
            add(page.url, "text", "text_snippets", "\n".join(page.text.key_snippets),
                dict(tf), dict(base_ctx))
        for i, chunk in enumerate(page.text.chunks):
            ctx = dict(base_ctx, chunk_index=i, chunk_total=len(page.text.chunks))
            add(page.url, "text", "text_chunk", chunk, dict(tf), ctx)

        # --- SCRIPTS committee ---
        for si, script in enumerate(page.scripts.inline_scripts):
            for ci, chunk in enumerate(script.chunks):
                ctx = dict(base_ctx, script_index=si, chunk_index=ci, chunk_total=len(script.chunks))
                add(page.url, "scripts", "inline_script", chunk, asdict(script.features), ctx)
        for ext in page.scripts.external_scripts:
            add(page.url, "scripts", "external_script_ref", ext.url,
                {"origin": ext.origin, "off_domain": ext.off_domain, "domain": ext.domain},
                dict(base_ctx))
        for h in page.scripts.event_handlers:
            add(page.url, "scripts", "event_handler", h.code,
                {"attribute": h.attribute, "tag": h.tag}, dict(base_ctx))
        for ju in page.scripts.javascript_urls:
            add(page.url, "scripts", "javascript_url", ju, {}, dict(base_ctx))

        # --- WEB_CODE committee ---
        add(page.url, "web_code", "metadata", _compact_metadata(page.web_code.metadata),
            {k: page.web_code.features[k] for k in ("has_meta_refresh", "meta_refresh_off_domain", "title")},
            dict(base_ctx))
        for form in page.web_code.forms:
            add(page.url, "web_code", "form", _compact_form(form),
                {
                    "action_off_domain": form.action_off_domain,
                    "action_insecure": form.action_insecure,
                    "has_password_field": form.has_password_field,
                    "has_payment_field": form.has_payment_field,
                },
                dict(base_ctx))
        if page.web_code.hidden_elements:
            add(page.url, "web_code", "hidden_elements", _compact_hidden(page.web_code.hidden_elements),
                {"hidden_element_count": len(page.web_code.hidden_elements)}, dict(base_ctx))
        tpr = page.web_code.resources.third_party_domains
        if tpr:
            add(page.url, "web_code", "third_party_resources", ", ".join(tpr),
                {
                    "third_party_resource_domain_count": len(tpr),
                    "iframe_count": page.web_code.features["iframe_count"],
                },
                dict(base_ctx))

    return payloads


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------
def estimate_tokens(text: str) -> int:
    """Rough token estimate (~4 chars/token) for budgeting chunk sizes."""
    return len(text) // 4


def to_jsonl(records: list[dict]) -> str:
    """Serialize records as newline-delimited JSON (no trailing newline)."""
    return "\n".join(json.dumps(r, ensure_ascii=False) for r in records)


def write_jsonl(path: str, records: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    import argparse
    import os

    ap = argparse.ArgumentParser(
        description="Crawl a single site and emit committee payloads for scam analysis."
    )
    ap.add_argument("seed_url", help="URL to start crawling from")
    ap.add_argument("-o", "--out-dir", default=".", help="directory for output files")
    args = ap.parse_args(argv)

    from analysis.crawler import crawl

    pages = crawl(args.seed_url)
    if not pages:
        print("No pages crawled (invalid seed or nothing fetched).")
        return 1

    site = analyze_site(pages)
    payloads = build_committee_payloads(site)

    os.makedirs(args.out_dir, exist_ok=True)
    write_jsonl(os.path.join(args.out_dir, "analysis.jsonl"), [site.to_dict()])
    write_jsonl(os.path.join(args.out_dir, "payloads.jsonl"), payloads)
    print(f"{site.page_count} pages, {len(payloads)} payloads -> {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())