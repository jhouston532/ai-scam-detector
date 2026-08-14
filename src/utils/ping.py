import requests 
import csv

def ping(url: str, timeout: int) -> bool: 
    """
        Sends a website a typical GET request. 
        Returns true if the website responds with an OK code before a timeout. 
        Returns false if the website responds with a code other than OK or does not respond. 
    """

    try:
        response = requests.get(url, timeout=timeout)
        return response.status_code == requests.codes.ok  # 200
    except requests.RequestException:
        return False


def ping_urls(urls: list[str], timeout: int) -> dict[str, bool]:
    """
    Pings each URL and maps it to its result.
    """
    
    return {url: ping(url, timeout) for url in urls}

def read_from_csv_file(filepath: str) -> list[str]: 

    """
        Reads from a csv file that is a list of websites. 
        The CSV must have a header "url", which this function reads from. 
        The function ignores all columns besides the one with the url header. 
    """

    urls: list[str] = []

    with open(filepath, newline="") as file:
        reader = csv.DictReader(file)
        if reader.fieldnames is None or "url" not in reader.fieldnames:
            raise ValueError(f"CSV has no 'url' column; found {reader.fieldnames}")
        for row in reader:
            if row["url"]:
                urls.append(row["url"])

    return urls

def ping_main(mode: str, target: str, timeout: int = 15) -> dict[str, bool]:
    """
        The main function of this utility, bringing together all the functionality. 
        ping all of the url and get them into a dictionary that is URL : True/False depending on ping status. 
    """


    if mode == "file":
        urls = read_from_csv_file(target)
        return ping_urls(urls, timeout)
    
    return {target: ping(target, timeout)}