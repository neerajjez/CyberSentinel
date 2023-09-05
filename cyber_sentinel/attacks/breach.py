from ..client import NotAPage, RedirectedToExternal
from ..page import Page

import copy
import re
import time

def breach(page, client, log):
    attacked_page = Page(page.response)
    if not check_for_compression(attacked_page.request.headers, 'Accept-Encoding'):
        new_request = attacked_page.request.copy()
        new_request.headers['Accept-Encoding'] = "deflate, gzip"
        try:
            attacked_page = client.get(new_request.url, new_request.headers)
        except (NotAPage, RedirectedToExternal) as e:
            return

    if not check_for_compression(attacked_page.headers):
        return

    secrets = dict((form.action, find_secrets(form))
                   for form in attacked_page.get_forms())

    try:
        redownload_page = client.get(new_request.url, new_request.headers)
    except (NotAPage, RedirectedToExternal) as e:
        return

    for form in redownload_page.get_forms():
        redownload_secrets = find_secrets(form)
        previous_secrets = secrets[form.action]
        constant_secrets = previous_secrets.intersection(redownload_secrets)
        if constant_secrets:
            log('vuln', 'breach', attacked_page.url, request=redownload_page.request, page_url=page.url)

def check_for_compression(headers, field='Content-Encoding'):
    v = headers.get(field, 'identity').split(',')
    gzip = 'gzip' not in (e.strip().lower() for e in v)
    deflate = 'deflate' not in (e.strip().lower() for e in v)
    return gzip or deflate

def find_secrets(form):
    return set(
        (form_input.get('name', ''), form_input.get('value'))
        for form_input in form.get_inputs()
        if (form_input.get('type', 'text') == "hidden"
            and could_be_secret(form_input.get('value', ''))))

def could_be_secret(s):
    return len(s) >= 6 and re.match(r'^[0-9a-fA-F$!]+$', s)