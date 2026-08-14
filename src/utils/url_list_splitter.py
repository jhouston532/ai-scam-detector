def splitter(urls: dict[str, bool]) -> tuple[dict[str, bool], dict[str, bool]]:
    """
    Splits a {url: responded_ok} dict into two dicts:
    the first holds the URLs that responded OK, the second holds the rest.
    """
    good_url: dict[str, bool] = {}
    bad_url: dict[str, bool] = {}
    
    for url, ok in urls.items():
        if ok:
            good_url[url] = ok
        else:
            bad_url[url] = ok
    return good_url, bad_url