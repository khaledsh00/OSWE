import requests 
import sys
from bs4 import BeautifulSoup
import base64
if len(sys.argv) != 2 :
    print(f"Please Usage of script ::: {sys.argv[0]} URL ")
    sys.exit(1)

url = sys.argv[1]

if not url.startswith(("http://", "https://")):
    url = "http://" + url
if not url.endswith("/about.html"):
    if not url.endswith("/"):
        url += "/"
    url += "about.html"

try:
    r = requests.get(url)
    soup = BeautifulSoup(r.text,'html.parser')
    sec = soup.find("section", class_="about")
    if sec and sec.has_attr("notify_true"):
        flag =  sec["notify_true"]
        decode = base64.b64decode(f"{flag}").decode("utf-8")
        print(decode)
    else:
        print("notify_true attribute not found.")
        

except requests.exceptions.RequestException as e:
     print(f"Request filed {e}")
