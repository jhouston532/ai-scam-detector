from collections import deque
from urllib.parse import urljoin, urlsplit, urlunsplit

import tldextract
from bs4 import BeautifulSoup

import utils.ping as Ping

DEFAULT_TIME_OUT = 30

def get_domain(url: str) -> str:
    """
        Get the domain of a website from a url 
    """


    ext = tldextract.extract(url)
    if not ext.domain or not ext.suffix: 
        return "None"
    else: 
        return f"{ext.domain}.{ext.suffix}"

def fetch_page(url: str) -> str | None: 
    """
        Get the html of a webpage  as a string; 
        or get nothing if there's an error
    """

    check: str | None = Ping.grab_html(url, DEFAULT_TIME_OUT)
    if check is not None:
        html: str = check
        return html
    else: 
        return None

def extract_links(html: str, base_url: str) -> list[str]:
    """Find every anchor href on the page and resolve each to an absolute URL.
        Made by claude 
    """
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href")
        if not isinstance(href, str):
            continue  # skip the (practically impossible) multi-valued case
        links.append(urljoin(base_url, href))
    return links

def normalize_url(url: str) -> str:
    """Collapse equivalent URLs to one canonical form for the visited-set check."""
    parts = urlsplit(url)

    # Lowercase the host (case-insensitive per spec); leave the path case alone.
    netloc = parts.netloc.lower()

    # Consistent trailing-slash handling: strip a trailing slash,
    # but keep the root path "/" as-is so "example.com" and "example.com/" agree.
    path = parts.path
    if len(path) > 1:
        path = path.rstrip("/")

    # Drop the #fragment entirely (points within a page, not to a new one).
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))

def same_domain(url: str, home_domain: str) -> bool:
    """True if url is on the same registrable domain as home_domain."""
    return get_domain(url) == home_domain


def crawl(seed_url: str) -> set[str]:
    """Crawl every reachable same-domain page starting from seed_url.
    Returns the set of normalized same-domain URLs visited.
    """
    # 1. Fix the home domain once, from the seed.
    home_domain: str = get_domain(seed_url)
    if home_domain == "None":
        return set()  # seed has no valid registrable domain; nothing to crawl

    # 2. Initialize the frontier and the seen-set.
    to_visit: deque[str] = deque([seed_url])
    visited: set[str] = set()
    queued: set[str] = {normalize_url(seed_url)}  # tracks what's already on to_visit

    # 3. Process the frontier until it's empty.
    while to_visit:
        url: str = to_visit.popleft()
        norm: str = normalize_url(url)

        if norm in visited:
            continue  # already handled this page
        visited.add(norm)

        html: str | None = fetch_page(url)
        if html is None:
            continue  # fetch failed / non-HTML — skip, keep going

        for link in extract_links(html, url):
            norm_link: str = normalize_url(link)
            if (
                same_domain(link, home_domain)
                and norm_link not in visited
                and norm_link not in queued
            ):
                to_visit.append(link)
                queued.add(norm_link)

    # 4. Frontier empty — every reachable same-domain page has been seen.
    return visited