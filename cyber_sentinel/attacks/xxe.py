from ..utils import dict_iterate, update_url_params, get_url_host, get_url_query, modify_parameter, SCRIPTABLE_ATTRS
from ..client import NotAPage, RedirectedToExternal

def xxe(page, client, log):

    for form in page.get_forms():
        if get_url_host(page.url) != get_url_host(form.action):
            continue

        form_parameters = dict(form.get_parameters())
        for param, value in dict_iterate(form_parameters):
            xml = postvul(form_parameters, param)
            try:
                res_page = client.post(form.action, data=xml)
            except (NotAPage, RedirectedToExternal) as e:
                continue

            if "XXEVulnerable" in res_page.html:
                print("XXE Vuln")

def postvul(params, param):
    inject = modify_parameter(params, param, str(value) + injection)
    xml = '<?xml version="1.0" encoding="utf-8"?>'
    xml += '<!DOCTYPE Anything [<!ENTITY myxxe "XXEVulnerable"> ]>'
    xml += inject
    return xml
