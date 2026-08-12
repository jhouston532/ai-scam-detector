from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def check_online(url: str, timeout: int = 10) -> bool: 
    """
    Checks if a website is online by hitting the URL with a GET requiest.
    true = it is online 
    false = it is not 

    timeout is in seconds
    """

    try:
        resp = requests.head(url, timeout=timeout, allow_redirects=True)
        return resp.status_code < 400
    except requests.RequestException:
        return False

def get_single_html(url: str, timeout: int = 10) -> str:
    """
    Gets the HTML of a single page.
    """

    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return ""

def index_site(start_url, max_pages=500, timeout=5):
    domain = urlparse(start_url).netloc
    session = requests.Session()
    session.headers["User-Agent"] = "site-indexer/1.0"

    seen = set()
    queue = deque([start_url])
    indexed = []

    while queue and len(indexed) < max_pages:
        url = queue.popleft()
        url, _ = urldefrag(url)          # strip #fragments
        if url in seen:
            continue
        seen.add(url)

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue

        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        indexed.append({
            "url": url,
            "status": resp.status_code,
            "title": soup.title.string.strip() if soup.title and soup.title.string else None,
        })

        # only follow links from healthy pages
        if resp.status_code < 400:
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                link, _ = urldefrag(link)
                if urlparse(link).netloc == domain and link not in seen:
                    queue.append(link)

    return indexed