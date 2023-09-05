PATTERN = "Index of {}"

def directory_listing(page, client, log):
    def path_in_headings(path):
        if path:
            headings = page.document.find_all('h1')
            for h in headings:
                if path in h.text:
                    return True

        return False

    title = page.document.title
    if title:
        path = page.parsed_url.path.rstrip('/')
        if title.text == PATTERN.format(path) or path_in_headings(path):
            log('warn', 'directory_listing', page.url, request=page.request, page_url=page.url)
