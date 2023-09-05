from urllib.parse import urlparse, urljoin, parse_qsl
from .form import Form
from .utils import remove_url_params, contains_url, get_all_path_links, get_url_path

from bs4 import BeautifulSoup

import re
import itertools
import js2py
import six



class Page(object):
    def __init__(self, response):
        assert hasattr(response, 'request')
        self.request = response.request
        self.headers = response.headers
        self.cookies = response.cookies
        self.status_code = response.status_code

        if 'text/html' in self.headers.get('content-type', ''):
            self.html = response.text
        else:
            self.html = ''

        self.document = BeautifulSoup(self.html, 'lxml')#'html.parser''lxml')
        self.response = response

    @property
    def url(self):
        return self.request.url

    @property
    def parsed_url(self):
        return urlparse(self.request.url)

    @property
    def url_parameters(self):
        _, _, url = self.url.partition("?")
        return parse_qsl(url)

    def get_forms(self, blacklist=[]):
        """ Generator for all forms on the page. """
        for form in self.document.find_all('form'):
            form_obj = Form(self.url, form)
            if any(re.search(x, form.get(action)) for x in blacklist):
                continue

            yield form_obj

    def get_links(self, blacklist=[]):
        """ Generator for all links on the page. """
        refresh = [re.split("url=", m.get('content'), flags=re.IGNORECASE)[-1].strip("'") for m in self.document.find_all(attrs={'http-equiv': 'refresh'})]
        ahref = [h.get('href') for h in self.document.find_all('a')]
        src_all = [s.get('src') for s in self.document.find_all(contains_url)]
        script_links = []
        for script in self.document.find_all('script'):
            urls = re.findall(r"""(?:href|url|location|u)\s?(?:=|:)\s?[a-zA-Z\'.\/\+]+(?:;|\s|$)""", script.text)
            for u in urls:
                try:
                    js_url = js2py.eval_js(u)
                    if isinstance(js_url, six.string_types):
                        script_links.append(js_url)
                        continue
                except js2py.base.PyJsException as e:
                    continue
                script_links.append(u)

        for ref in itertools.chain(refresh, ahref, src_all, script_links):
            if not ref:
                continue

            url = urljoin(self.url, ref.strip())

            if any(re.search(x, url) for x in blacklist):
                continue

            if urlparse(url).query:
                url_without_query = remove_url_params(url)

                yield url_without_query

            if '/' in get_url_path(url).partition('/')[2]:
                for link in list(get_all_path_links(url)):
                    yield link

            yield url
