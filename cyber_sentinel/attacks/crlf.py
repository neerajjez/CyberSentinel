from ..utils import dict_iterate, modify_parameter, update_url_params, get_url_query
from ..client import NotAPage, RedirectedToExternal

BODY = u'o'
CRLF_SEQUENCE = (
    u"Content-Type: text/html\r\n" +
    u"Content-Length: %d\r\n\r\n" % len(BODY))
ATTACK_SEQUENCE = CRLF_SEQUENCE + BODY

def crlf(page, client, log):
    attack_url(page.url, client, log)

    for form in page.get_forms():
        parameters = dict(form.get_parameters())
        report = {'params': [], 'injections': []}
        for param in parameters:
            injected_parameters = modify_parameter(parameters, param, ATTACK_SEQUENCE)

            try:
                res_page = form.send(client, injected_parameters)
            except (NotAPage, RedirectedToExternal) as e:
                continue

            if check_crlf(res_page):
                report['request'] = res_page.request
                report['params'].append(param)

        if report['params']:
            log('vuln', 'crlf', form.action, report['params'], injections=ATTACK_SEQUENCE, request=report['request'], page_url=page.url)


def attack_url(url, client, log):
    query = get_url_query(url)

    report = {'params': [], 'injections': []}
    for param, value in dict_iterate(query):
        injected_url = update_url_params(url, {param: ATTACK_SEQUENCE})

        try:
            res_page = client.get(injected_url)
        except (NotAPage, RedirectedToExternal) as e:
            continue

        if check_crlf(res_page):
            report['request'] = res_page.request
            report['params'].append(param)

    if report['params']:
        log('vuln', 'crlf', url, report['params'], injections=ATTACK_SEQUENCE, request=report['request'], page_url=url)

def check_crlf(res_page):
    return res_page.headers.get('Content-Length') == str(len(BODY))