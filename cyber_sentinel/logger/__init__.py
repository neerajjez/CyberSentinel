# -*- coding: utf-8 -*-
import os
import io

from ..utils import remove_url_params, check_dir
from ..attacks import ATTACK_INFO
from jinja2 import Environment, FileSystemLoader

LEVEL_NAMES = {
    'warn': 'Warning',
    'vuln': 'Vulnerability',
}

REPORTS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
HTML_DIR = os.path.join(REPORTS_DIR, 'html')

check_dir(REPORTS_DIR)
check_dir(HTML_DIR)

PATH = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_ENVIRONMENT = Environment(
    autoescape=False,
    loader=FileSystemLoader(os.path.join(PATH, 'templates')),
    trim_blocks=False)

def entry_str(level, type, url, params, injections=None, request=None, message=None, _level=None, _type=None, page_url=None):
    if not params:
        return "{} {} on {} on page {}".format(level, type, url, page_url)
    else:
        return "{} {} on {} (params {}) on page {}".format(level, type, url, params, page_url)

def render_template(template_filename, context):
    return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)

class Log(object):
    def __init__(self, direct_print=True):
        self.urls = {}
        self.vulns = []
        self.direct_print = direct_print
        self.counter = {
            'warn': 0,
            'vuln': 0
        }

    def __call__(self, level, a_type, url, param=None, injections=None, request=None, message=None, page_url=None):
        assert level in LEVEL_NAMES
        assert a_type in ATTACK_INFO

        level_name = LEVEL_NAMES[level]
        attack_type = ATTACK_INFO[a_type]['name']
        url_without_params = remove_url_params(url)
        params = []
        if param:
            if not isinstance(param, list):
                param = [param]

            params = list(set(param))

        entry = {
            '_level': level,
            '_type': a_type,
            'level': level_name,
            'type': attack_type,
            'url': url_without_params,
            'params': params,
            'injections': injections or [],
            'request': request,
            'message': message,
            'page_url': page_url,
        }

        self.counter[level] += 1

        if page_url:
            self.add_url(page_url, color='red')

        if not entry in self.vulns:
            self.vulns.append(entry)
            self.add_url(url_without_params, color='red')
            if self.direct_print:
                print(entry_str(**entry))

    def add_url(self, url, color='green'):
        self.urls.update({url: color})

    def write_html_report(self, filename='report.html', audit_info=None):
        file_path = os.path.join(REPORTS_DIR, 'html', filename)
        self.counter['all'] = sum(self.counter.values())
        context = {
            'info': audit_info,
            'counter': self.counter,
            'vulns': self.vulns,
            'vulns_info': ATTACK_INFO,
            'urls': self.urls
        }

        with io.open(file_path, 'w', encoding='utf-8') as f:
            html = render_template('report.html', context)
            f.write(html)
