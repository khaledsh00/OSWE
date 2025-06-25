import requests
from bs4 import BeautifulSoup
import sys

def decrypt_flag(encrypted, key):
    decrypted = ''
    for i in range(len(encrypted)):
        decrypted += chr((ord(encrypted[i]) - ord(key[i % len(key)]) + 256) % 256)
    return decrypted

if len(sys.argv) != 2: 
    print(f"Correct Usage of App: {sys.argv[0]} <URL>")
    sys.exit(1)

url = sys.argv[1]

try:
    r = requests.get(url)
    r.raise_for_status()
except Exception as e:
    print(f"Error fetching URL: {e}")
    sys.exit(1)

soup = BeautifulSoup(r.text, "html.parser")
textarea = soup.find("textarea", id="bookmarkletCode")

# Hardcoded static values from the JavaScript
encrypted_flag = "àÒÆÞ¦È¬ëÙ£ÖÓÚåÛÑ¢ÕÓÒËÉ§©í"
key = "picoctf"

# Decrypt
flag = decrypt_flag(encrypted_flag, key)
print(f"[+] Decrypted Flag: {flag}")
