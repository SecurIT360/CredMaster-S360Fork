import requests
import utils.utils as utils
from urllib.parse import urlparse
from credmaster import log_entry
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

paths = {'OWA version 2003': '/exchweb/bin/auth/owaauth.dll',
         'OWA version 2007': '/owa/auth/owaauth.dll',
         'OWA version > 2007': '/owa/auth.owa'}

def check_url(url):
    r = requests.get(url, verify=False)
    return r.status_code

def check_path(url):
    current_path = urlparse(url).path
    if not current_path or current_path == "/":
        srv = url.rstrip('/')   # just in case
        log_entry('Trying to guess OWA version. Please wait...')
        for key, value in paths.items():
            url_value = srv + value
            if check_url(url_value) == 200:
                log_entry('Looks like %s' % key)
                log_entry('Using "%s" as a target' % url_value)
                return url_value
    else:
        log_entry('[!] Unable to find OWA - using "%s" as a target' % url)
        return url


def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --url https://mail.domain.com   ->  OWA mail target
    #
    if 'url' in pluginargs.keys():
        return True, None, pluginargs
    else:
        error = "Missing url argument, specify as --url https://mail.domain.com"
        return False, error, None


def testconnect(pluginargs, args, api_dict, useragent):

    url = api_dict['proxy_url']

    success = True
    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : utils.generate_ip(),
        "x-amzn-apigateway-api-id" : utils.generate_id(),
        "X-My-X-Amzn-Trace-Id" : utils.generate_trace_id(),
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    server_url = pluginargs['url']
    owa_server = check_path(pluginargs['url'])

    resp = requests.get(url, headers=headers, verify=False)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Fingerprinting host... Internal Domain name: {domain}, continuing"

    if success:
        domainname = utils.get_owa_domain(server_url, "/autodiscover/autodiscover.xml", useragent)
        output = output.format(domain=domainname)
        pluginargs['domain'] = domainname
        pluginargs['url'] = owa_server

    return success, output, pluginargs
