import asyncio
import json
import re
import time
import urllib.parse
import requests
import websockets
from bs4 import BeautifulSoup
import urllib.parse

url = "http://138.197.38.125:4001/"

headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

proxies = {
    'http': 'http://127.0.0.1:8080',
}

burp_proxy_flag = False


# helper function: compact json body
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


def auto_registration():
    global url, headers, proxies, burp_proxy_flag

    # Create a Session object
    session = requests.Session()

    # send GET request at /users/register
    if burp_proxy_flag:
        res = session.get(url=url + "users/register", headers=headers, proxies=proxies)
    else:
        res = session.get(url=url + "users/register", headers=headers)

    res_body = res.text
    # Parse the HTML content
    soup = BeautifulSoup(res_body, 'html.parser')

    # Find the div with the data-phx-session attribute
    div_element = soup.find('div', {'data-phx-session': True})
    data_phx_session = div_element['data-phx-session']
    data_phx_static = div_element['data-phx-static']

    # Find the <a> tag with the data-csrf attribute
    csrf_meta_tag = soup.find('meta', attrs={'name': 'csrf-token'})
    data_csrf_token = csrf_meta_tag.get('content')

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
    # print(f"phx_session: {_phx_session}")
    # print(f"phx_static: {_phx_static}")

    _topic_name = data_ws_id
    _csrf_token = data_csrf_token
    #
    # print(f"topic_name: {_topic_name}")
    # print(f"csrf_token: {_csrf_token}")

    # print values
    # print(f"_frat_test_web_user_tracker: {session.cookies['_frat_test_web_user_tracker']}")
    # print(f"_frat_test_v2_key: {session.cookies['_frat_test_v2_key']}")
    # print("")

    return _topic_name, _csrf_token, _phx_session, _phx_static, session


def send_post_request(post_params, session):
    # send the POST request at users/log_in and redirects to /login_challenge

    # setting headers
    headers["Origin"] = url[:len(url) - 1]
    headers["Referer"] = url + "users/register"
    headers["Cache-Control"] = "max-age=0"
    headers["Accept-Language"] = "en-US"
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    if burp_proxy_flag:
        res = session.post(url=url + "users/log_in?_action=registered", data=post_params, headers=headers,
                           proxies=proxies, allow_redirects=True)
    else:
        res = session.post(url=url + "users/log_in?_action=registered", data=post_params, headers=headers,
                           allow_redirects=True)


async def websocket_requests(topic_number, initial_sequence_number, topic_name, csrf_token, phx_session, phx_static,
                             email, password, session):
    # print(f"[+] websocket flow")

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
                "url": "http://138.197.38.125:4001/users/register", "params": {"_csrf_token": csrf_token,
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
        # print(f"\n Sent message: {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        # print(f"Received message: {message}")

        index_phx_submit = message.find("phx-submit=")
        new_csrf_token = message[index_phx_submit + 47: index_phx_submit + 103]

        # print(f"\n new csrf_token: {new_csrf_token}")

        seq = str(int(initial_sequence_number) + 8)
        # validate
        validate_event = [
            topic_number,
            seq,
            full_topic_name,
            "event",
            {
                "type": "form",
                "event": "validate",
                "value": f"_csrf_token={csrf_token}&user%5Bemail%5D={email}&user%5Bpassword%5D={password}",
                "uploads": {},
            }]

        cleaned_data = remove_spaces_from_json(validate_event)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        # print(f"\n {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        # print(f"Received message: {message}")

        # event_data for creating the request
        seq = str(int(initial_sequence_number) + 24)
        send_event_save_data = [
            topic_number,
            seq,
            full_topic_name,
            "event",
            {
                "type": "form",
                "event": "save",
                "value": f"_csrf_token={csrf_token}&user%5Bemail%5D={email}&user%5Bpassword%5D={password}",
            }

        ]

        cleaned_data = remove_spaces_from_json(send_event_save_data)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        # print(f"\n {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        # print(f"Received message: {message}")

        # phx_leave topic
        seq = str(int(initial_sequence_number) + 1)
        send_phx_leave_data = [
            topic_number,
            seq,
            full_topic_name,
            "phx_leave",
            {
            }
        ]

        cleaned_data = remove_spaces_from_json(send_phx_leave_data)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        # print(f"\n {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        # print(f"Received message: {message}")

        await websocket.close()
        # print("")

        # processing response
        data_dict = send_event_save_data[4]
        post_params_ = data_dict.get("value")
        return post_params_


def login(email, password):
    global url, headers, proxies, burp_proxy_flag

    # Create a Session object
    session = requests.Session()
    # print(f"[+] user login flow")
    # print("")

    # send GET request at /users/log_in
    if burp_proxy_flag:
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

    if burp_proxy_flag:
        res = session.post(url=url + "users/log_in", data=data, headers=headers, proxies=proxies, allow_redirects=False)
    else:
        res = session.post(url=url + "users/log_in", data=data, headers=headers, allow_redirects=False)

    if "/login_challenge" in res.text:
        print("[+] login successful")
        return True
    else:
        if "/users/log_in" in res.text:
            print("[x] login unsuccessful")
        else:
            print("[*] received new value")

        return False


if __name__ == '__main__':

    first_name = "abhijit"
    last_name = "sinha"

    first_letter_of_first_name = first_name[0]
    first_letter_of_last_name = last_name[0]

    # accept same number
    topic_number = initial_sequence_number = 4

    total_accounts = 20

    counter = 1
    while counter <= total_accounts:

        email = f"{first_letter_of_first_name}%2B{first_letter_of_last_name}%2B{counter}%40test.com"
        password = email

        topic_name, csrf_token, phx_session, phx_static, session_obj = auto_registration()
        post_params = asyncio.run(
            websocket_requests(topic_number, initial_sequence_number, topic_name, csrf_token, phx_session,
                               phx_static, email, password, session_obj))
        send_post_request(post_params, session_obj)

        # verify if that account is really created
        email = urllib.parse.unquote(email)
        password = urllib.parse.unquote(password)

        print(f"[=] trying to create an account for {email}")

        result = login(email, password)

        if result:
            print(f"{counter}. {email} account created")
            counter += 1
        else:
            print(f"{counter}. {email} account not created, retrying the process after 10 min")
            # try to delay for 10 min: worked
            time.sleep(60 * 10)

        print("")
