Before I lay this out — this analysis stage plugs into your scam-detection project, so let me note the design direction in my records, then give you the full outline.Here's the design outline for the four-file analysis pipeline.

## Architecture overview

The pipeline consumes what the crawler gathers for **one website** and turns it into small, self-contained artifacts that a panel of local models can score. The natural input contract is a mapping of `{url: html}` for the site (see the integration note at the end — your `crawl` currently returns only visited URLs, so it needs to also hand back the fetched HTML).

`analysis.py` is the conductor. It parses each page's HTML **once** into a BeautifulSoup tree and passes that tree to three worker modules, each owning one category:

- `web_code.py` — structure and presentation: the DOM skeleton, CSS, forms, metadata, resource references
- `scripts.py` — everything executable: inline `<script>`, external script refs, event-handler attributes, `javascript:` URLs
- `text.py` — the human-readable layer: visible text, headings, link/button text, alt/aria text, metadata copy

Each worker returns a structured, JSON-serializable report. `analysis.py` merges the per-page reports into a site-level record, then flattens that record into **committee payloads** — one small artifact per model call, sized to a small context window and carrying precomputed features so a 7B–14B model doesn't have to infer everything from raw markup.

A shared principle across all three workers: **extract, don't judge.** The modules produce signals and clean chunks; the verdict is the models' job. Parse once, pass the tree down, and never re-parse in a leaf function.

---

## `web_code.py` — HTML, CSS, and the rest

**Overview.** Owns the structural and presentational category. Its job is to describe *how the page is built* and surface the structural tricks scams rely on: cross-domain form actions, cloaked/hidden elements, brand-mismatched metadata, and suspicious external resources. It takes a parsed tree (plus the site's `home_domain` for first/third-party classification) and returns a `WebCodeReport`.

**Function summary:**
- `extract_dom_skeleton(soup)` — compact structural tree, text and scripts stripped
- `extract_forms(soup, home_domain)` — form descriptors (the highest-value web-code signal)
- `extract_css(soup)` — inline styles, `<style>` blocks, linked stylesheet URLs
- `detect_hidden_elements(soup)` — cloaked/off-screen/invisible content
- `extract_metadata(soup)` — title, meta tags, lang, favicon
- `extract_resource_references(soup, home_domain)` — images, iframes, links, preloads by origin
- `classify_links(soup, home_domain)` — anchors split internal/external/mailto/tel
- `build_web_code_report(...)` — assemble the compact report

**Detailed functions:**

`extract_dom_skeleton(soup) -> str` walks the tree emitting only tag names and nesting (e.g., an indented outline or a flattened `body>div>form>input` path list), dropping text nodes and script bodies. A skeleton is tiny, fits a small context, and exposes structural anomalies — a "login" page whose real structure is one giant obfuscated `div`, or an invisible overlay form.

`extract_forms(soup, home_domain) -> list[dict]` is the centerpiece. For each `<form>` it records the `action` URL and whether it points **off-domain** (credentials leaving to a foreign host is a top phishing signal), the method, and every input's `type`/`name`/`placeholder`, flagging password, email, `tel`, and payment-like fields, plus hidden inputs. It returns one descriptor per form so the script committee never has to see them but the web-code committee gets them isolated.

`extract_css(soup) -> dict` collects three CSS sources: `style="..."` attributes, `<style>` block contents, and `<link rel="stylesheet">` hrefs (with origin). It doesn't parse CSS into an AST; it keeps raw declarations plus flags for the rules that matter to `detect_hidden_elements`.

`detect_hidden_elements(soup) -> list[dict]` cross-references CSS and attributes to find content hidden from users but present for crawlers/models: `display:none`, `visibility:hidden`, `opacity:0`, off-screen positioning (`left:-9999px`), zero-size boxes, tiny fonts, and `hidden`/`aria-hidden` attributes. Each hit records the element, the technique, and a snippet of what's being hidden — cloaking is a strong scam tell.

`extract_metadata(soup) -> dict` pulls `<title>`, `<meta name="description|keywords">`, Open Graph tags (`og:site_name`, `og:title`), `<html lang>`, charset, and favicon href. Feeds brand-impersonation checks (an `og:site_name` of a bank on a random domain) and language/geography mismatch signals.

`extract_resource_references(soup, home_domain) -> dict` inventories `img[src]`, `iframe[src]`, `link[href]`, `source`, and preload/prefetch hints, bucketed first-party vs third-party. Iframes to foreign origins and heavy cross-domain loading are laundering/redirect signals.

`classify_links(soup, home_domain) -> dict` splits anchors into internal / external / `mailto:` / `tel:`, with counts and the external host list. Outbound-link ratio and suspicious TLDs are cheap, informative features.

`build_web_code_report(...) -> dict` composes the above into one serializable object, keeping raw blobs (CSS, skeleton) separate from the compact feature flags so payloads can carry features without the bulk.

---

## `scripts.py` — the executable layer

**Overview.** Isolates everything that runs, because scripts carry the most dangerous and most obfuscated scam behavior (redirects, credential exfiltration, fingerprinting, miners) and because raw JS blows a small context window fast. This module extracts, lightly normalizes, feature-flags, and **chunks** scripts so each model call sees a digestible window.

**Function summary:**
- `extract_inline_scripts(soup)` — bodies of `<script>` without `src`
- `extract_external_scripts(soup, home_domain)` — `<script src>` URLs, origin-classified
- `extract_event_handlers(soup)` — `on*` attribute JS
- `extract_js_urls(soup)` — `href="javascript:..."`
- `normalize_script(code)` — strip comments, collapse whitespace, decode trivial escapes
- `extract_script_features(code)` — heuristic risk flags
- `chunk_script(code, max_tokens)` — window large scripts to fit context
- `build_scripts_report(...)` — aggregate

**Detailed functions:**

`extract_inline_scripts(soup) -> list[str]` returns the text of every `<script>` with no `src` (skipping `type="application/ld+json"` and other data blocks, which it can route to a separate list — structured data is a text/metadata signal, not code).

`extract_external_scripts(soup, home_domain) -> list[dict]` records each `src` with an origin classification: first-party, known-CDN, known-tracker, or unknown-third-party. Unknown third-party scripts on a "banking" page are worth a model's attention; you generally can't fetch and evaluate their bodies locally, so the *reference itself* (URL, origin) becomes the artifact.

`extract_event_handlers(soup) -> list[dict]` collects inline `on*` attributes (`onclick`, `onload`, `onmouseover`, …) with their element and code. Inline handlers are a common place to stash redirect and form-hijack logic.

`extract_js_urls(soup) -> list[str]` finds `href="javascript:..."` anchors — small but frequently malicious.

`normalize_script(code) -> str` does *light* cleanup for readability without destroying signals: strip comments, collapse whitespace, decode simple `\xNN`/`\uNNNN` escapes. It deliberately does **not** fully deobfuscate — the presence of obfuscation is itself the signal, captured next.

`extract_script_features(code) -> dict` scans for high-value heuristics and returns boolean/count flags: `eval`, `Function()`, `atob`/`btoa` (base64), `document.write`, `String.fromCharCode`, long hex/unicode escape runs, high character entropy (packing), `window.location`/redirect patterns, `addEventListener('keydown'...)` (keylogging), form-submission interception, crypto-miner and fingerprinting fingerprints. These let a small model reason over a compact flag set instead of parsing minified JS.

`chunk_script(code, max_tokens) -> list[str]` splits oversized scripts into token-budgeted windows, preferring statement/line boundaries with small overlap so a suspicious pattern isn't severed at a seam.

`build_scripts_report(...) -> dict` aggregates counts, the union of feature flags, external-origin summary, and the ranked-most-suspicious chunks.

---

## `text.py` — the human-readable layer

**Overview.** Produces what a person actually reads, which is where social-engineering lives: urgency, prize/lottery bait, credential/verification demands, threats, and brand names. It keeps a little structure (headings and CTAs carry outsized signal) and extracts linguistic features, then segments long text into model-sized pieces.

**Function summary:**
- `extract_visible_text(soup)` — rendered text with script/style/noscript removed
- `extract_structured_text(soup)` — headings, CTAs, alt/aria, metadata copy, form labels
- `normalize_text(text)` — whitespace + Unicode (NFKC) normalization
- `detect_text_obfuscation(text)` — homoglyphs, mixed scripts, zero-width chars
- `extract_text_features(text)` — scam-language signals
- `extract_key_snippets(structured)` — highest-signal short strings
- `segment_text(text, max_tokens)` — chunk at sentence/paragraph bounds
- `build_text_report(...)` — aggregate

**Detailed functions:**

`extract_visible_text(soup) -> str` removes `<script>`, `<style>`, `<noscript>`, and comments, then `get_text` with sensible separators and whitespace collapsing — the baseline readable content.

`extract_structured_text(soup) -> dict` preserves slots that matter: `h1`–`h6`, paragraphs, list items, **button and anchor text** (CTAs like "Verify your account now"), `img[alt]`, `aria-label`, `<title>`, meta description, and form labels/placeholders. Scam signals cluster in these slots, so keeping them separated helps the model weight them.

`normalize_text(text) -> str` applies Unicode NFKC normalization and whitespace cleanup for a readable canonical form used in chunks.

`detect_text_obfuscation(text) -> dict` runs *before* aggressive normalization and flags evasion tricks: homoglyphs (Cyrillic "а" for Latin "a"), mixed-script tokens, zero-width and combining characters, and spaced-out words designed to dodge keyword filters. These are strong signals precisely because they exist to fool filters like this one.

`extract_text_features(text) -> dict` produces the linguistic feature set: urgency terms, money/prize/lottery language, credential/verification requests, threats/consequences, excessive capitalization or punctuation, detected language, phone numbers, crypto-wallet-address patterns, and brand-name mentions (to compare against `home_domain` for impersonation).

`extract_key_snippets(structured) -> list[str]` selects the few highest-signal short strings (title, top headings, primary CTAs) so a committee can get a fast, cheap read before spending budget on full-body chunks.

`segment_text(text, max_tokens) -> list[str]` chunks long bodies on sentence/paragraph boundaries within the token budget, with light overlap.

`build_text_report(...) -> dict` aggregates snippets, features, obfuscation flags, and chunks.

---

## `analysis.py` — tying it together

**Overview.** Orchestration, aggregation, and payload construction. It never parses markup itself beyond the single shared `parse` call; it composes the three workers, rolls per-page reports up to a site view, and emits committee-ready payloads plus serialized intermediate artifacts.

**Function summary:**
- `parse(html)` — the single shared BeautifulSoup call
- `split_content(soup, home_domain)` — invoke the three workers → the 3-way split
- `analyze_page(url, html, home_domain)` — full per-page record
- `analyze_site(pages, home_domain)` — aggregate + deduplicate across pages
- `build_committee_payloads(site_analysis, config)` — flatten to per-artifact model inputs
- `estimate_tokens(text)` — budget helper used by the chunkers
- `serialize(analysis, path)` — write JSON/JSONL intermediates
- `main()` — CLI: read crawler output → analyze → write payloads

**Detailed functions:**

`parse(html) -> BeautifulSoup` centralizes parser choice (`"html.parser"`, matching your crawler) so every module shares one tree.

`split_content(soup, home_domain) -> dict` is the literal three-category split you asked for: it calls `web_code.build_web_code_report`, `scripts.build_scripts_report`, and `text.build_text_report` and returns `{"web_code": ..., "scripts": ..., "text": ...}`. This is the seam where the raw page becomes three clean buckets.

`analyze_page(url, html, home_domain) -> dict` parses once, runs `split_content`, and wraps the result with page identity (url, normalized url, fetch status). One page in, one structured record out.

`analyze_site(pages, home_domain) -> dict` maps `analyze_page` over the site and then does the **site-level** work single pages can't: deduplicate resources that repeat across pages (the same tracker script or stylesheet shouldn't be scored ten times), compute site-wide ratios (outbound-link ratio, count of pages with off-domain form actions), and collect the union of brand mentions vs. the domain. This is why single-site scope matters — `home_domain` anchors every first/third-party decision.

`build_committee_payloads(site_analysis, config) -> list[dict]` is the bridge to the models (schema below). It flattens the site record into one payload per artifact, attaches the precomputed features, tags each with its target committee, and enforces the token budget from `config`.

`estimate_tokens(text) -> int` gives the chunkers a budget (a fast chars/≈4 heuristic, or a real tokenizer if you have one) so no payload overflows a small model's window.

`serialize(analysis, path)` writes intermediates as JSONL — one record per line — so runs are reproducible, inspectable, and replayable into models without re-crawling.

`main()` reads the crawler's `{url: html}` output, runs `analyze_site`, writes both the full analysis and the payloads, and is the CLI entry point.

---

## Data produced

Three tiers, each JSON-serializable:

1. **Per-page report** — the three category reports plus page identity. Bulky (holds raw CSS, scripts, text), meant for storage and inspection, not for direct model input.

2. **Site analysis** — pages rolled up with deduplicated resources and site-level features. This is also the shape that matches the "three CSVs (text / html / scripts)" export you had in mind — each category report flattens cleanly to a CSV per site.

3. **Committee payloads** — the small units actually sent to models. One artifact per payload:

```
{
  "payload_id": "example.com/login#form-0",
  "site": "example.com",
  "url": "https://example.com/login",
  "committee": "web_code",              // or "scripts" | "text"
  "artifact_type": "form",              // form | dom_skeleton | inline_script |
                                        // external_script_ref | text_chunk | metadata | ...
  "content": "<the one small chunk to evaluate>",
  "features": { "action_off_domain": true, "has_password_field": true },
  "context": { "home_domain": "example.com", "page_title": "...",
               "chunk_index": 0, "chunk_total": 1 },
  "question": "Does this artifact indicate a scam or phishing attempt?",
  "response_schema": { "verdict": "scam|suspicious|benign",
                       "confidence": 0.0, "flags": [], "evidence": "" }
}
```

The `content` stays under the model's budget; `features` gives the model a head start; `response_schema` forces structured output you can aggregate mechanically.

## Presenting to committees of local models

The mapping is one **committee per category**: a text committee, a scripts committee, a web-code committee. Each committee is *N* small models (your 7B–14B jurors) that each receive one payload and return the `response_schema` JSON independently. Because the models are small-context, you send **one artifact per call** rather than a whole page — that's the entire reason for the chunking and per-artifact payloads above.

Aggregation ladders up in four steps:

1. **Per artifact** — combine the *N* jurors' JSON verdicts (majority vote for the label, mean for confidence), so each artifact gets one verdict with agreement recorded.
2. **Per category** — combine a page's artifact verdicts into a category verdict, ideally weighting by artifact type (an off-domain password form should outweigh a benign heading).
3. **Per page** — combine the three category verdicts into a page verdict.
4. **Per site** — combine page verdicts, letting the site-level features (cross-page off-domain forms, cloaking prevalence) adjust the final risk score.

Because every step consumes structured JSON and precomputed features, aggregation is deterministic code, not another model call — which keeps the whole thing debuggable and cheap. `config` carries the knobs: token budget per model, juror count, per-artifact-type weights, and score thresholds.

---

**One integration point to close first:** your `crawl` returns `set[str]` of visited URLs, but this pipeline needs the HTML too. The clean fix is to have the crawler retain the `{normalized_url: html}` it already fetches and return that (the bodies pass through `fetch_page` anyway), so `analyze_site` gets fed directly without re-fetching.

Want me to turn any of this into a skeleton — the four files with typed function stubs, docstrings, and `TODO`s wired together so you can fill in the bodies — or start with one module (I'd suggest `web_code.py`, since forms and hidden elements are your highest-signal features)?