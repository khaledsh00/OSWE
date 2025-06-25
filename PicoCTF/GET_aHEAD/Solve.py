import requests
import sys


if len(sys.argv) != 2:
    print(f"Run as  {sys.argv[0]} url")
    sys.exit(1)
url = sys.argv[1]

r = requests.head(url)

headers = r.headers 
if "flag" in headers:
    print(f"Your flag is {headers["flag"]}")
