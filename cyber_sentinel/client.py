from urllib.parse import urlparse
from http.cookiejar import CookieJar
from .page import Page
from .utils import NOT_A_PAGE_CONTENT_TYPES, get_url_query

import requests
import sys
import tldextract

class NotAPage(Exception):
    """ The content at the URL in question is not a webpage, but something
    static (image, text, etc.) """

class RedirectedToExternal(Exception):
    """ Response return 3** code and redirected to external link """

class BadStatusCode(Exception):
    """Response with status code not equal 2**"""

class Client(object):
    def __init__(self):
        self.cookie_jar = CookieJar()
        self.default_headers = {
            #'Accept-Encoding': 'gzip, deflate, sdch',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36'
        }
        self.session = requests.Session()

    @property
    def cookies(self):
        return self.session.cookies.get_dict()

    def get(self, url, headers=None, ignore_type=True):
        try:
            r = self.session.get(url, headers=headers or self.default_headers)
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as error:
            r = error

        if not isinstance(r, requests.Response):
            raise NotAPage()

        if not ignore_type and r.headers.get('content-type') in NOT_A_PAGE_CONTENT_TYPES \
            and not get_url_query(r.url):
            raise NotAPage()

        if r.history and tldextract.extract(r.url).domain != tldextract.extract(url).domain:
            raise RedirectedToExternal()

        return Page(r)

    def post(self, url, data={}, headers=None, ignore_type=False):
        try:
            r = self.session.post(url, data=data, headers=headers or self.default_headers)
            r.raise_for_status()
        except (requests.exceptions.HTTPError, requests.exceptions.RequestException) as error:
            r = error

        if not isinstance(r, requests.Response):
            raise NotAPage()

        if not ignore_type and r.headers.get('content-type') in NOT_A_PAGE_CONTENT_TYPES:
            raise NotAPage()

        if r.history and urlparse(r.url).netloc != urlparse(url).netloc:
            raise RedirectedToExternal()

        return Page(r)
