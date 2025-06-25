#!/usr/bin/env python3
import requests
import sys
import base64
import urllib.parse

# Check if a URL was provided as a command-line argument
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <url>")
    sys.exit(1)

# Get the base URL from the argument
url = sys.argv[1]

# Dummy credentials to send in POST request
data = {
    "username": "test",
    "password": "password"
}

# Create a session object to store cookies
session = requests.Session()

# Ensure the URL ends with /login.php
if "login.php" not in url:
    if url.endswith("/"):
        url += "login.php"
    else:
        url += "/login.php"

# Send the POST request to login
response = session.post(url, data=data)

print("We got the cookie, now printing and decoding it...\n")

# Get cookies from the session
cookies = session.cookies

# Check if any cookies were set
if not cookies:
    print("No cookies received. Something might be wrong.")
else:
    for cookie in cookies:
        print(f"{cookie.name} = {cookie.value}")
        try:
            # Step 1: URL-decode the cookie value
            url_decoded = urllib.parse.unquote(cookie.value)

            # Step 2: Fix missing base64 padding if necessary
            missing_padding = len(url_decoded) % 4
            if missing_padding:
                url_decoded += '=' * (4 - missing_padding)

            # Step 3: Base64-decode the result
            decoded = base64.b64decode(url_decoded).decode("utf-8", errors="ignore")
            print("Decoded:", decoded)
        except Exception as e:
            print("Error decoding:", e)
