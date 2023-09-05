# -*- coding: utf-8 -*-
from .xss import xss
from .hpp import hpp
from .sql_error import sql_error
from .sql_blind import sql_blind
from .csrf import csrf
from .crlf import crlf
from .lfi import lfi
from .directory_listing import directory_listing
from .breach import breach
from .clickjack import clickjack
from .cookiescan import cookiescan

ATTACK_TYPES = {
    'xss': 'Cross-Site Scripting (XSS)',
    'xss_file': 'Remote file inclusion XSS',
    'hpp': 'HTTP Parameter Pollution',
    'breach': 'Breach',
    'clickjack': 'Clickjack',
    'cookiescan': 'Implicit Cacheable Cookies',
    'crlf': 'Carriage Return Line Feed',
    'csrf': 'Cross-Site Request Forgery',
    'directory_listing': 'Directory listing',
    'lfi': 'Local File Inclusion',
    'sql_blind': 'SQL Blind',
    'sql_error': 'SQL Error',
    'cms_vuln': 'CMS Vulnerability'
}

ATTACK_INFO = {
    'xss': {
    'name': 'Cross-Site Scripting (XSS)',
    'description': 'Cross-Site Scripting (XSS) is a type of software vulnerability specific to web applications (by bypassing browser security restrictions) that allows an attacker to inject client-side scripts into web pages viewed by other users. XSS vulnerability can be exploited by an attacker to circumvent security mechanisms such as same-origin policy.',
    'recommendations': 'Use input/output data escaping. Set the HttpOnly flag. This flag makes client-side cookies inaccessible through scripting languages like JavaScript.',
    'severity': 'High',
},
'xss_file': {
    'name': 'Remote File Inclusion XSS',
    'description': 'Remote file inclusion (RFI) is the ability to execute remote files on the attacked server, which in 100% of cases leads to the compromise of the website. Exploiting the RFI vulnerability, an attacker gains access to the server of the targeted website by placing web shells or other malicious code on it. In most cases, RFI is immediately used to obtain a web shell on the attacked server.',
    'recommendations': 'Edit the source code to validate user input correctness. Where possible, create a list of accepted file names and restrict input to this list. For PHP, the allow_url_fopen option usually allows the programmer to open, include, or otherwise use remote files using URLs instead of local file paths. It is recommended to disable this option in php.ini.',
    'severity': 'High',
},
'hpp': {
    'name': 'HTTP Parameter Pollution',
    'description': 'HPP attacks involve introducing encoded query string delimiters into other existing parameters. If a web application does not properly sanitize user input, a malicious user can compromise the application logic to perform either client-side or server-side attacks.',
    'recommendations': 'The application should properly validate user input (URL encoding) to protect against this vulnerability.',
    'severity': 'High',
},
'breach': {
    'name': 'Breach',
    'description': 'BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext) is a security vulnerability related to HTTPS when using HTTP compression. To carry out a BREACH attack, the attacker must have the ability to intercept the victim\'s network traffic. This can be achieved through a Wi-Fi network or by gaining access to the Internet service provider\'s equipment. The attacker also needs to identify a vulnerable part of the application that accepts input data via URL parameters and returns this data in an encrypted response. The attacker can force the client application to send a large number of requests and thus guess all characters of the authentication token.',
    'recommendations': 'Recommended measures include disabling HTTP compression, separating secrets from user input, randomizing secrets on request, secret masking, protecting vulnerable pages with CSRF tokens, and limiting request frequency.',
    'severity': 'Medium',
},
'clickjack': {
    'name': 'Clickjacking',
    'description': 'Clickjacking is a mechanism of deceiving Internet users, where an attacker can gain access to confidential information or even gain access to the user\'s computer by luring them to an externally harmless page or injecting malicious code into a secure page.',
    'recommendations': 'Sending proper X-Frame-Options headers in the HTTP response is necessary. These headers instruct the browser not to allow iframes from other domains. Using defensive coding in the user interface to ensure that the current frame is the top-level window.',
    'severity': 'Low',
},
'cookiescan': {
    'name': 'Implicit Cacheable Cookies',
    'description': '',
    'recommendations': 'Set the cache in cookie parameters or set Cache-control: no-cache, no-store, must-revalidate in the HTTP header.',
    'severity': 'Medium',
},
    'crlf': {
    'name': 'Carriage Return Line Feed',
    'description': 'CRLF, or Carriage Return Line Feed, refers to the type of vulnerabilities that occur when a user inserts CRLF into an application. CRLF characters signify the end of a line for many internet protocols, including HTML, and appear as %0D%0A, which decodes to rn. They can be used to denote line breaks and, when combined with HTTP request and response headers, can lead to various vulnerabilities, including HTTP Request Smuggling and HTTP Response Splitting.',
    'recommendations': 'Limit CR (0x13) and LF (0x10) from user input or properly encode output to prevent injection of user HTTP headers.',
    'severity': 'Medium',
},
'csrf': {
    'name': 'Cross-Site Request Forgery',
    'description': 'CSRF is a type of attack on website visitors that exploits vulnerabilities in the HTTP protocol. If the victim visits a site created by an attacker, a request is secretly sent on their behalf to another server (e.g., a payment system server) that performs a malicious operation (e.g., transferring money to the attacker\'s account). To execute this attack, the victim must be authenticated on the server to which the request is sent, and this request should not require any confirmation from the user that cannot be ignored or forged by the attacking script.',
    'recommendations': 'Make sure this form requires CSRF protection and applies CSRF countermeasures if necessary.',
    'severity': 'Medium',
},
'directory_listing': {
    'name': 'Directory Listing',
    'description': 'Directory listing is a feature of a web server that displays a list of all files if a specific directory on the website does not have an index file, such as index.php or default.asp.',
    'recommendations': 'First and foremost, ensure you have installed the latest version of your web server software and make sure all patches have been applied. Secondly, effectively filter any user data. Ideally, remove everything except known useful data and filter metacharacters from user input.',
    'severity': 'Medium',
},
'lfi': {
    'name': 'Local File Inclusion',
    'description': 'LFI is the ability to use and execute local files on the server side. The vulnerability allows a remote user to gain access by using a specially crafted request to arbitrary files on the server, including those containing confidential information.',
    'recommendations': 'Edit the source code to validate user input correctness. Where possible, create a list of accepted file names and restrict input to this list. For PHP, the allow_url_fopen option usually allows the programmer to open, include, or otherwise use remote files using URLs instead of local file paths. It is recommended to disable this option in php.ini.',
    'severity': 'High',
},
'sql_blind': {
    'name': 'SQL Blind',
    'description': 'This page may be vulnerable to SQL Injection attacks. SQL Injection is a vulnerability that allows an attacker to modify internal SQL operators by manipulating user input. SQL Injection occurs when web applications accept user input that is directly placed into an SQL statement and does not properly filter dangerous characters. This is one of the most common application-level attacks currently used on the Internet. Despite being relatively easy to defend against, there are a large number of vulnerable web applications.',
    'recommendations': 'Your script should filter metacharacters from user input. For more details, see the "Fixing this vulnerability" article.',
    'severity': 'High',
},
'sql_error': {
    'name': 'SQL Error',
    'description': 'This page contains a database error/warning message that can disclose confidential information. The message may also contain the location of the file where an unhandled exception occurred.',
    'recommendations': 'Review the source code for error information output.',
    'severity': 'Medium',
},
}

def all_attacks():
    return [xss, hpp, sql_error, sql_blind, csrf, crlf, lfi, directory_listing, breach, clickjack, cookiescan]
    

def xss_attack():
    return [xss]

def hpp_attack():
    return [hpp]

def sql_error_attack():
    return [sql_error]

def csrf_attack():
    return [csrf]

def crlf_attack():
    return [crlf]

def lfi_attack():
    return [lfi]

def directory_listing_attack():
    return [directory_listing]

def breach_attack():
    return [breach]

def clickjack_attack():
    return [clickjack]

def cookiescan_attack():
    return [cookiescan]

