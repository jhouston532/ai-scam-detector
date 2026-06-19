
"""
Outline of Program

    Usage: `python main.py list.csv`

    options: 
        
    
    For each item in the list, 
        - curl the html page 
        - create two stripped text files: one with the code only and one with the text only 
        - pass the text files' content to the two committees
        - each member of the committees evaluate what they are given 
        - their evaluation is measured and synthesized into a report 
        - both reports are combined to synthesize a full report
"""
import requests


def get_html(url: str) -> str: 
    # Get the full html of a webpage 
    response = requests.get(url, timeout=60)
    response.raise_for_status()  # raises on 4xx/5xx
    return response.text

def read_lines(filepath: str) -> list[str]:
    """
    Reads the lines from a text file and returns them as a list of strings.

    :param filepath: The path to the text file.
    :return: A list of strings, where each string is a line from the file.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        print(f"The file at {filepath} was not found.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

