from bs4 import BeautifulSoup

def extract_content(html: str) -> dict:
    """
    Split an HTML string into its raw markup, code (scripts/styles),
    and human-visible text.
    """
    if not html:
        return {"html": "", "code": [], "text": ""}

    soup = BeautifulSoup(html, "html.parser")

    # Pull out code-bearing tags and record their contents
    code = []
    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        contents = tag.string or tag.get_text()
        if contents and contents.strip():
            code.append({
                "type": tag.name,
                "src": tag.get("src"),          # None for inline blocks
                "content": contents.strip(),
            })
        tag.decompose()                          # remove from tree

    # Now the remaining tree has no script/style noise
    text = soup.get_text(separator="\n", strip=True)

    return {
        "html": html,        # original, untouched markup
        "code": code,        # list of scripts/styles
        "text": text,        # visible readable text
    }

def extract_content(html: str) -> dict:
    """
    Split an HTML string into its raw markup, code (scripts/styles),
    and human-visible text.
    """
    if not html:
        return {"html": "", "code": [], "text": ""}

    soup = BeautifulSoup(html, "html.parser")

    # Pull out code-bearing tags and record their contents
    code = []
    for tag in soup.find_all(["script", "style", "noscript", "template"]):
        contents = tag.string or tag.get_text()
        if contents and contents.strip():
            code.append({
                "type": tag.name,
                "src": tag.get("src"),          # None for inline blocks
                "content": contents.strip(),
            })
        tag.decompose()                          # remove from tree

    # Now the remaining tree has no script/style noise
    text = soup.get_text(separator="\n", strip=True)

    return {
        "html": html,        # original, untouched markup
        "code": code,        # list of scripts/styles
        "text": text,        # visible readable text
    }