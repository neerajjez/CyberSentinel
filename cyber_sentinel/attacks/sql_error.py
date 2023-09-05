from ..utils import dict_iterate, update_url_params, replace_url_params, get_url_query, modify_parameter

from urllib.parse import urlparse
from ..client import NotAPage, RedirectedToExternal

import re

PAYLOAD = "'"
DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}

def sql_error(page, client, log):
    query = get_url_query(page.url)

    report = {'params': []}
    for param, value in dict_iterate(query):
        injected_url = update_url_params(page.url, {param: PAYLOAD})

        try:
            res_page = client.get(injected_url)
        except (NotAPage, RedirectedToExternal) as e:
            continue

        if check_sql_error(res_page):
            report['request'] = res_page.request
            report['params'].append(param)

    if report['params']:
        log('vuln', 'sql_error', page.url, report['params'], request=report['request'], page_url=page.url)

    for form in page.get_forms():
        form_parameters = dict(form.get_parameters())
        report = {'params': []}
        for param in form_parameters:
            injected_params = modify_parameter(form_parameters, param, PAYLOAD)

            try:
                res_page = form.send(client, injected_params)
            except (NotAPage, RedirectedToExternal) as e:
                continue

            if check_sql_error(res_page):
                report['request'] = res_page.request
                report['params'].append(param)

        if report['params']:
            log('vuln', 'sql_error', form.action, report['params'], request=report['request'], page_url=page.url)

        query = get_url_query(form.action)
        report = {'params': []}
        for param, value in dict_iterate(query):
            injected_action = update_url_params(form.action, {param: PAYLOAD})
            try:
                res_page = form.send(client, form_parameters, changed_action=injected_action)
            except (NotAPage, RedirectedToExternal) as e:
                continue

            if check_sql_error(res_page):
                report['request'] = res_page.request
                report['params'].append(param)

        if report['params']:
            log('vuln', 'sql_error', form.action, report['params'], request=report['request'], page_url=page.url)

def check_sql_error(res_page):
    for db, errors in dict_iterate(DBMS_ERRORS):
        for e in errors:
            res = re.findall(e, res_page.html)
            if res:
                return True

    return False
