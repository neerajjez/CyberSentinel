def cookiescan(page, client, log):
    if not check_for_cookies(page.headers):
        return

    if not secure_cache_control(page):
        log('warn', 'cookiescan', page.url, request=page.request, page_url=page.url)

def check_for_cookies(headers):
    return "Set-Cookie" in headers or "Set-Cookies" in headers

def secure_cache_control(page):
    if "Cache-Control" in page.headers:
        cache_control = page.headers.get("Cache-Control")

        if cache_control in "no-cache" or cache_control in "private":
            return True

        if "max-age" in cache_control and "0" in cache_control:
            return True

    return False