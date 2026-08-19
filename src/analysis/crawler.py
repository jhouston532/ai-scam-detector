from collections import deque
from urllib.parse import urljoin, urlsplit, urlunsplit

import tldextract
from bs4 import BeautifulSoup

import utils.ping as Ping

DEFAULT_TIME_OUT = 30

def get_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if not ext.domain or not ext.suffix:
        return "None"
    else:
        return f"{ext.domain}.{ext.suffix}"

def fetch_page(url: str) -> str | None:
    check: str | None = Ping.grab_html(url, DEFAULT_TIME_OUT)
    if check is not None:
        html: str = check
        return html
    else:
        return None

def extract_links(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href")
        if not isinstance(href, str):
            continue
        links.append(urljoin(base_url, href))
    return links

def normalize_url(url: str) -> str:
    parts = urlsplit(url)
    netloc = parts.netloc.lower()
    path = parts.path
    if len(path) > 1:
        path = path.rstrip("/")
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))

def same_domain(url: str, home_domain: str) -> bool:
    return get_domain(url) == home_domain


def crawl(seed_url: str) -> dict[str, str]:
    """Crawl every reachable same-domain page starting from seed_url.

    Returns a mapping of normalized URL -> page HTML for each same-domain page
    that was fetched successfully. Pages whose fetch failed (or that weren't
    HTML) are visited but omitted from the result, since there's no body to
    hand downstream. Recover the old visited-set with `set(crawl(seed))`.
    """
    # 1. Fix the home domain once, from the seed.
    home_domain: str = get_domain(seed_url)
    if home_domain == "None":
        return {}  # seed has no valid registrable domain; nothing to crawl

    # 2. Initialize the frontier and the bookkeeping sets.
    to_visit: deque[str] = deque([seed_url])
    seen: set[str] = set()                       # normalized URLs already processed
    queued: set[str] = {normalize_url(seed_url)}  # normalized URLs already on to_visit
    pages: dict[str, str] = {}                    # normalized URL -> HTML (successful only)

    # 3. Process the frontier until it's empty.
    while to_visit:
        url: str = to_visit.popleft()
        norm: str = normalize_url(url)

        if norm in seen:
            continue  # already handled this page
        seen.add(norm)

        html: str | None = fetch_page(url)
        if html is None:
            continue  # fetch failed / non-HTML — skip, keep going

        pages[norm] = html  # keep the body for the analysis stage

        for link in extract_links(html, url):
            norm_link: str = normalize_url(link)
            if (
                same_domain(link, home_domain)
                and norm_link not in seen
                and norm_link not in queued
            ):
                to_visit.append(link)
                queued.add(norm_link)

    # 4. Frontier empty — return every same-domain page we could fetch.
    return pages