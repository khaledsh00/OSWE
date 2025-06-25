import requests  # For sending HTTP requests
import sys       # For reading command-line arguments
import re        # For using regular expressions to extract the flag

# Check if the user provided exactly one argument (the URL)
if len(sys.argv) != 2:
    print(f"[!] Usage: {sys.argv[0]} <URL>")
    sys.exit(1)

# Read the URL from the command-line argument
url = sys.argv[1]

try:
    # Send an HTTP GET request to the provided URL
    response = requests.get(url)
    response.raise_for_status()  # Raise error if status code is not 200 OK
except requests.RequestException as e:
    print(f"[!] Failed to fetch the URL: {e}")
    sys.exit(1)

# Extract the response content as text (HTML or JavaScript)
page_content = response.text

# Use regex to search for the picoCTF flag pattern
match = re.search(r'picoCTF\{.*?\}', page_content)

# If a flag is found, print it. Otherwise, inform the user.
if match:
    print(f"\033[92m[+] Extracted Flag: {match.group()}\033[0m")
else:
    print("[-] picoCTF flag not found in the response.")
