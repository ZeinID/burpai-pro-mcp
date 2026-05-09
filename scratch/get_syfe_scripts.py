
import httpx
import re

def get_scripts():
    r = httpx.get("https://www.syfe.com/login")
    scripts = re.findall(r'src=["\'](.*?\.js)["\']', r.text)
    for s in scripts:
        print(s)

if __name__ == "__main__":
    get_scripts()
