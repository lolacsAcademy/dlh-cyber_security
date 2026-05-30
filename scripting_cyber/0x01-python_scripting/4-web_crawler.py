#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl_website(start_url, max_depth=2):
    """Crawls a website recursively and collects internal links."""
    discovered = set()

    def explore(current_url, remaining_depth):
        if remaining_depth == 0 or current_url in discovered:
            return
        try:
            response = requests.get(current_url, timeout=5)
            discovered.add(current_url)
            print(f"Crawling: {current_url}")
            soup = BeautifulSoup(response.text, 'html.parser')
            base_domain = urlparse(start_url).netloc
            for anchor in soup.find_all('a', href=True):
                full_url = urljoin(current_url, anchor['href'])
                if urlparse(full_url).netloc == base_domain:
                    explore(full_url, remaining_depth - 1)
        except Exception:
            pass

    explore(start_url, max_depth)
    return discovered


if __name__ == "__main__":
    pass
