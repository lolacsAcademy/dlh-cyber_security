#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2, visited=None):
    """Crawls a website recursively and collects internal links."""
    if visited is None:
        visited = set()

    if max_depth == 0 or start_url in visited:
        return visited

    try:
        page = requests.get(start_url, timeout=5)
        visited.add(start_url)
        print(f"Crawling: {start_url}")

        parsed = BeautifulSoup(page.text, 'html.parser')
        origin = urlparse(start_url).netloc

        for anchor in parsed.find_all('a', href=True):
            full_url = urljoin(start_url, anchor['href'])
            full_url_domain = urlparse(full_url).netloc

            if full_url_domain == origin and full_url not in visited:
                crawl_website(full_url, max_depth - 1, visited)

    except Exception:
        pass

    return visited


if __name__ == "__main__":
    pass
