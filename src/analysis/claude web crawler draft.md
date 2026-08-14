# Simple Same-Domain Web Crawler — Design Outline

## Goal

Take **one starting link** (e.g. `https://example.com`), visit pages on that
same domain, and collect **every link on the domain the crawler can reach** by
following links from page to page. Anything pointing off the domain is noted but
not followed.

This outline describes the pieces in plain language — no code. Each function has
a single clear job, and they chain together into one crawl loop.

---

## The idea in one paragraph

Start with a to-do list containing just the seed URL. Repeatedly take a URL off
the list, download the page, pull out every link on it, throw away links that
leave the domain or that we've already seen, and add the fresh same-domain ones
back onto the to-do list. Keep a separate "already visited" record so we never
process the same page twice and never loop forever. When the to-do list is empty,
we've crawled everything reachable — return the collection.

This is a **breadth-first search** over the website's link graph.

---

## State the crawler keeps

Two collections do all the bookkeeping:

- **`to_visit`** — the frontier, or "to-do list": URLs discovered but not yet
  fetched. A queue (first in, first out) gives breadth-first order.
- **`visited`** — a set of URLs already fetched (or already queued), so we never
  handle the same page twice. A **set** matters here: membership checks are fast,
  and duplicates are impossible.

Everything below reads from or writes to these two.

---

## Functions

### `get_domain(url) -> str`

**Purpose:** Pull the domain (host) out of a URL so we have something to compare
every other link against.

**Input:** A full URL string, e.g. `https://example.com/about`.

**Output:** Just the host portion, e.g. `example.com`.

**How it works:** Parse the URL into its parts (scheme, host, path, …) and return
the host. Called once at the start on the seed URL to establish the "home"
domain that defines the crawl boundary.

---

### `fetch_page(url) -> str | None`

**Purpose:** Download the raw HTML of one page.

**Input:** A single URL to request.

**Output:** The page's HTML as text, or `None` if the request failed.

**How it works:** Send a GET request with a timeout. If the server responds with
a success code and the content is HTML, return the response body. If anything
goes wrong — timeout, connection error, non-success status, or non-HTML content
like a PDF or image — catch it and return `None` instead of crashing. Returning
`None` lets the main loop simply skip bad pages and keep going. (This is the same
request-and-handle-failures pattern as a ping check, just keeping the body.)

---

### `extract_links(html, base_url) -> list[str]`

**Purpose:** Find every link on a page and turn each into a full, usable URL.

**Input:** The page's HTML text, plus the URL that page came from (`base_url`).

**Output:** A list of absolute URL strings found on the page.

**How it works:** Parse the HTML and locate every anchor tag's `href` value. Many
of those are **relative** (`/about`, `contact.html`, `../index`), so each one is
joined against `base_url` to produce a complete absolute URL
(`/about` + `https://example.com/page` → `https://example.com/about`). Return the
list of absolute links. This function only *finds and resolves* links — it does
no filtering; deciding what to keep happens later.

---

### `normalize_url(url) -> str`

**Purpose:** Put a URL into one canonical form so the same page isn't treated as
several different ones.

**Input:** A single URL string.

**Output:** A cleaned-up, standardized version of that URL.

**How it works:** Apply a few consistent tidy-ups so equivalent links collapse to
one string — for example, drop the `#section` fragment (it points within the same
page, not to a new one), lowercase the host, and settle on a consistent handling
of trailing slashes. Without this step, `example.com/about`,
`example.com/about#top`, and `example.com/about/` would each look "new" and get
fetched separately. Normalizing before the `visited` check is what keeps the
crawler from doing redundant work.

---

### `same_domain(url, home_domain) -> bool`

**Purpose:** Decide whether a link belongs to the domain we're crawling.

**Input:** A URL to test, and the `home_domain` string from `get_domain`.

**Output:** `True` if the URL is on the home domain, `False` otherwise.

**How it works:** Extract the host from `url` (same parsing as `get_domain`) and
compare it to `home_domain`. Only matching links get followed; off-domain links
can be recorded if you want an "external links found" list, but they're never
added to `to_visit`. This is the guardrail that keeps the crawler from wandering
onto the whole internet.

---

### `crawl(seed_url) -> set[str]`

**Purpose:** The orchestrator — drives the whole process and ties every function
above together.

**Input:** The one starting URL.

**Output:** The set of all same-domain URLs discovered.

**How it works, step by step:**

1. Call `get_domain(seed_url)` to fix the home domain.
2. Initialize `to_visit` with the seed URL and an empty `visited` set.
3. **Loop while `to_visit` is not empty:**
   - Take the next URL off `to_visit`.
   - Normalize it; if it's already in `visited`, skip and continue.
   - Mark it as visited (add to the set).
   - `fetch_page(url)`; if it returns `None`, skip to the next URL.
   - `extract_links(html, url)` to get the links on this page.
   - For each link: normalize it, then keep it only if `same_domain(...)` is
     `True` and it isn't already in `visited` or already queued — those fresh
     links get added to `to_visit`.
4. When `to_visit` empties, every reachable same-domain page has been seen.
   Return `visited` (or a dedicated collected set) as the full list of links.

---

## Overall flow

```
seed URL
   │
   ▼
get_domain ──► "home" domain (the boundary)
   │
   ▼
crawl loop ──────────────────────────────────┐
   │  take a URL from to_visit                │
   │  normalize ──► seen already? skip        │
   │  mark visited                            │
   │  fetch_page ──► None? skip               │
   │  extract_links                           │
   │  for each: normalize + same_domain check │
   │  new & on-domain ──► add to to_visit ────┘
   │
   ▼
return every discovered same-domain URL
```

---

## Keep-it-simple boundaries (and what to add later)

To stay "basic," this design deliberately leaves some things out. Worth knowing
they exist:

- **Politeness:** A real crawler pauses briefly between requests and reads the
  site's `robots.txt` to respect which paths it's asked not to fetch. Add a small
  delay and a `robots.txt` check before hammering a live site you don't own.
- **Limits:** Add a maximum page count or a maximum link-depth so a huge site
  doesn't run forever.
- **One page at a time:** This version fetches sequentially, which is simplest to
  reason about. Fetching several pages concurrently is faster but adds real
  complexity — a later upgrade, not a starter feature.
- **JavaScript-rendered links:** This crawler only sees links present in the raw
  HTML. Sites that build their links in the browser with JavaScript would need a
  headless browser to see those links — out of scope here.

---

## Quick function summary

| Function | Job |
|---|---|
| `get_domain` | Find the home domain that bounds the crawl |
| `fetch_page` | Download one page's HTML, or `None` on failure |
| `extract_links` | Find all links on a page, made absolute |
| `normalize_url` | Standardize a URL so duplicates collapse |
| `same_domain` | Keep on-domain links, reject external ones |
| `crawl` | Run the loop that ties them all together |