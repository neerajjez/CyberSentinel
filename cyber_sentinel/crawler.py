#!/usr/bin/python
from .utils import get_url_host
from .client import Client, NotAPage, RedirectedToExternal

from collections import deque
from re import search

class Crawler(object):
    def __init__(self, target, client=None, whitelist=None, blacklist=set(),additional_pages=[]):
        self.target = target

        if whitelist is None:
            self.whitelist = { get_url_host(target) }
        else:
            self.whitelist = whitelist
            self.whitelist.add(get_url_host(target))

        if client is None:
            self.client = Client()
        else:
            self.client = client

        if additional_pages:
            self.to_visit_links = deque(additional_pages)
        else:
            self.to_visit_links = deque()

        self.blacklist = blacklist
        self.visited_links  = set()
        self.count = 0

    def __iter__(self):
        self.to_visit_links.append(self.target)

        while self.to_visit_links:
            url = self.to_visit_links.pop()
            if not get_url_host(url) in self.whitelist:
                continue
            if any(search(x, url) for x in self.blacklist):
                continue

            url_without_hashbang, _, _ = url.partition("#")
            if url_without_hashbang in self.visited_links:
                continue

            try:
                page = self.client.get(url, ignore_type=False)
            except (NotAPage, RedirectedToExternal) as e:
                continue

            if page.url in self.visited_links:
                continue

            self.visited_links.add(page.url)
            self.count += 1

            self.to_visit_links.extend(page.get_links())
            yield page
