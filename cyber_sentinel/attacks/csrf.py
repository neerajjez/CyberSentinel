from ..utils import compare
from ..client import NotAPage, RedirectedToExternal

COMMON_CSRF_NAMES = (
    'csrf_token',
    'CSRFName',                   # OWASP CSRF_Guard
    'CSRFToken',                  # OWASP CSRF_Guard
    'anticsrf',                   # AntiCsrfParam.java
    '__RequestVerificationToken', # AntiCsrfParam.java
    'token',
    'csrf',
    'YII_CSRF_TOKEN',             # http://www.yiiframework.com/
    'yii_anticsrf'                # http://www.yiiframework.com/
    '[_token]',                   # Symfony 2.x
    '_csrf_token',                # Symfony 1.4
    'csrfmiddlewaretoken',        # Django 1.5
)

def csrf(page, client, log):
    for form in page.get_forms():
        if form.is_search_form:
            continue

        valid_params = dict(form.get_parameters())
        broken_params = dict(form.get_parameters(filter_by_name=COMMON_CSRF_NAMES))

        try:
            valid_res = form.send(client, valid_params)
            broken_res = form.send(client, broken_params)
        except (NotAPage, RedirectedToExternal) as e:
            continue

        if broken_res.status_code == 200 \
            and compare(list(valid_res.document.stripped_strings), list(broken_res.document.stripped_strings)):

            log('warn', 'csrf', form.action, request=broken_res.request, page_url=page.url)

