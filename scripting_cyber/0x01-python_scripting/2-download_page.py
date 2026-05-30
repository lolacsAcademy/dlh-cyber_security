#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup


def download_page(url):
    """Downloads a web page and returns its formatted HTML content."""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.prettify()
    except requests.exceptions.RequestException as e:
        return str(e)


if __name__ == "__main__":
    pass
