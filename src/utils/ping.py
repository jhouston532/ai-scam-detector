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
        return response.status_code == requests.ok  # 200
    except requests.RequestException:
        return False

def ping_list(l: list[str], t: int) -> list[bool]: 
    """
        Ping a list of URLs with the ping function 
    """

    if l == []: 
        return [] 

    r: list[bool] = []

    for website in l: 
        r.append(ping(website, t))

    return r

def read_from_csv_file(filepath: str) -> list[str]: 

    """
        Reads from a csv file that is a list of websites. 
        The CSV must have a header "url", which this function reads from. 
        The function ignores all columns besides the one with the url header. 
    """

    l: list[str] = []

    with open(filepath, newline="") as file: 
        reader = csv.DictReader(file)

        for row in reader: 
            if "url" in row and row["url"]: 
                l.append(row["url"])

    return l

def ping_main(mode: str,  x: str, t: int, timeout: int = 15) -> list[bool]:     
    result: list[bool] = []

    if mode == "file": 
        filepath = x
        url_list: list[str] = read_from_csv_file(filepath)
        result = ping_list(url_list, t)
    else: 
        url = x 
        result = [ping(url, t)]
    return result