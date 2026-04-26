import os
import requests
from dotenv import load_dotenv

load_dotenv()
api_keys = os.getenv("GEMINI_API_KEYS", "").split(",")
proxies = os.getenv("GEMINI_PROXIES", "").split(",")
proxy_dict = {"http": proxies[0].strip(), "https": proxies[0].strip()} if proxies and proxies[0] else None

print(f"Testing keys with proxy: {proxy_dict}")
for idx, key in enumerate(api_keys):
    key = key.strip()
    if not key: continue
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key={key}"
    data = {"contents": [{"parts": [{"text": "Hello, answer with exactly 1 word."}]}]}
    try:
        res = requests.post(url, json=data, proxies=proxy_dict, timeout=10)
        print(f"Key {idx+1} (...{key[-4:]}): Status {res.status_code}")
        if res.status_code == 200:
            print("  SUCCESS!")
        else:
            print("  FAIL:", res.text[:200])
    except Exception as e:
        print(f"Key {idx+1} (...{key[-4:]}): ERROR {e}")
