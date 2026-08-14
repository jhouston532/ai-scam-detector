
def splitter(urls: dict[str, bool]) -> list[dict[str, bool]]: 

    good_url: list[dict[str, bool]] = []
    bad_url: list[dict[str, bool]] = []

    for url, ok in urls: 
        if ok == True: 
            good_url.append[{url, ok}]
        else: 
            bad_url.append[{url, ok}]

    return [good_url, bad]