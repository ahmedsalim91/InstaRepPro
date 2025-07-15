from cryptography.fernet import Fernet
import json
import logging
from time import sleep
from random import uniform
import requests
import os
import re
import uuid
import time
import hashlib
import datetime
import hmac
from rich.console import Console
from rich.text import Text
import random
from functools import wraps
import requests.exceptions
INSTA_KEY = "CqQZhVRW-D3vVUpswbQYrkscuV1Lgst5Ng_BqkxGF3g="
try:
    import requests, rich, datetime, hashlib, uuid, re, time, os, random, logging, hmac
except ImportError as e:
    print(f"Missing dependency: {e}. Please install required libraries.")
    exit()

# Logging configuration
logging.basicConfig(filename='report_bot.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = Console(record=True)

def handle_api_errors(max_attempts=3):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.ConnectionError as e:
                    console.print(f"[red]Connection error: {e}. Retrying...[/red]")
                    logging.error(f"Connection error in {func.__name__}: {e}")
                    attempts += 1
                    sleep(uniform(5, 10))
                except requests.exceptions.Timeout as e:
                    console.print(f"[red]Request timed out: {e}. Retrying...[/red]")
                    logging.error(f"Timeout in {func.__name__}: {e}")
                    attempts += 1
                    sleep(uniform(5, 10))
                except Exception as e:
                    console.print(f"[red]Unexpected error in {func.__name__}: {e}[/red]")
                    logging.error(f"Unexpected error in {func.__name__}: {e}")
                    raise
            console.print(f"[red]Max attempts reached in {func.__name__}.[/red]")
            logging.error(f"Max attempts reached in {func.__name__}")
            raise Exception(f"Failed after {max_attempts} attempts")
        return wrapper
    return decorator

def handle_rate_limit(response, max_retries=5, max_wait_time=300):
    retries = 0
    total_wait_time = 0
    while response.status_code in (429, 403) and retries < max_retries and total_wait_time < max_wait_time:
        wait_time = min(uniform(20, 40) * (2 ** retries), max_wait_time - total_wait_time)
        console.print(f"[yellow]Rate limited or forbidden. Retrying in {wait_time:.2f} seconds... (Attempt {retries + 1}/{max_retries})[/yellow]")
        logging.info(f"Rate limited or forbidden. Retrying in {wait_time:.2f} seconds, attempt {retries + 1}/{max_retries}")
        sleep(wait_time)
        total_wait_time += wait_time
        response = requests.request(response.request.method, response.url, headers=response.request.headers, data=response.request.body)
        retries += 1
    if response.status_code in (429, 403):
        console.print("[red]Max retries or wait time exceeded for rate limit or forbidden error.[/red]")
        logging.error("Max retries or wait time exceeded for rate limit or forbidden error")
    return response

@handle_api_errors(max_attempts=3)
def fetch_encrypted_config(url):
    response = requests.get(url)
    if response.status_code == 200:
        encrypted_data = response.text.strip().encode()
        cipher = Fernet(INSTA_KEY.encode())
        decrypted_data = cipher.decrypt(encrypted_data).decode()
        config = {}
        for line in decrypted_data.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                config[k.strip()] = v.strip()
        return config
    else:
        console.print(f"[red]Failed to fetch encrypted config. Status code: {response.status_code}[/red]")
        exit()

CONFIG_URL = "https://pastebin.com/raw/A7SGrQ8b"
config = fetch_encrypted_config(CONFIG_URL)
correct_key = config.get("KEY")
expiration_date = datetime.datetime.strptime(config.get("EXPIRATION_DATE"), "%Y-%m-%d")

def generate_key_hash(key):
    return hashlib.sha256(key.encode('utf-8')).hexdigest()

def verify_access_key():
    user_key = console.input("[green]Enter the access key: [/green]").strip()
    hashed_input_key = generate_key_hash(user_key)
    stored_key_hash = generate_key_hash(correct_key)
    if hashed_input_key != stored_key_hash:
        console.print("[red]Invalid key! Access denied.[/red]")
        logging.error("Invalid access key provided")
        exit()
    console.print("[green]Access key verified successfully[/green]")
    logging.info("Access key verified successfully")
    return True

def verify_expiration_date():
    if datetime.datetime.now() > expiration_date:
        console.print("[red]Tool expired. Please contact Daddy to renew access![/red]")
        logging.error("Tool subscription expired")
        exit()

def human_behavior_simulation():
    delay = random.uniform(1.0, 3.0)
    console.print(f"[yellow]WAIT {delay:.2f} seconds...[/yellow]")
    logging.info(f"Simulating human behavior with {delay:.2f} seconds delay")
    sleep(delay)

def bot_signature():
    console.print("[green]A THE TOOL IS FOUNDED BY REHAN CHACHU CREATED BY AHMED DADDY![/green]")
    logging.info("Bot signature displayed")

def header():
    os.system("cls" if os.name == 'nt' else "clear")
    console.print(f"""
[cyan]============================================================[/cyan]
                     [red]The REPORT BOT[/red]
                                by [magenta]@OgRehan[/magenta]
 Developer : [cyan]@tipsandgamer[/cyan]
[cyan]============================================================[/cyan]
    """)
    logging.info("Header displayed")

def generate_signed_body(data):
    message = '&'.join([f"{k}={v}" for k, v in sorted(data.items())])
    secret = "f65e6b7a8b7c4e3d9e0f2a1b5c7d8e9f"
    signature = hmac.new(secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()
    signed_body = f"{signature}.{message}"
    return signed_body

def encrypt_password(password):
    time_str = str(int(time.time()))
    enc_password = f"#PWD_INSTAGRAM_BROWSER:0:{time_str}:{password}"
    return enc_password

@handle_api_errors(max_attempts=3)
def fetch_csrf_token(max_attempts=3):
    endpoints = [
        'https://www.instagram.com/accounts/login/',
        'https://i.instagram.com/api/v1/web/login_page/',
        'https://www.instagram.com/data/shared_data/',
        'https://www.instagram.com/api/v1/web/get_web_graphql/'
    ]
    user_agents = [
        'Instagram 324.0.0.35.123 Android (34/14; 480dpi; 1080x2400; samsung; SM-G998B; zfold3; exynos2100; en_US)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 324.0.0.35.123'
    ]
    session = requests.Session()
    for attempt in range(max_attempts):
        for endpoint in endpoints:
            for user_agent in user_agents:
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'X-IG-App-ID': '936619743392459',
                    'X-IG-Capabilities': '3brTvw==',
                    'X-IG-Connection-Type': 'WIFI',
                    'Host': 'i.instagram.com' if 'i.instagram.com' in endpoint else 'www.instagram.com',
                    'X-Ig-Device-Id': str(uuid.uuid4()),
                    'X-Ig-Android-Id': ''.join(random.choices('0123456789abcdef', k=16)),
                    'X-Mid': str(uuid.uuid4()),
                    'X-IG-WWW-Claim': '0',
                    'X-Requested-With': 'XMLHttpRequest'
                }
                try:
                    response = session.get(endpoint, headers=headers)
                    response.raise_for_status()
                    cookies = response.cookies
                    csrf_token = cookies.get('csrftoken', None)
                    if csrf_token:
                        console.print("[green]Fetched CSRF token successfully[/green]")
                        logging.info(f"Fetched CSRF token: {csrf_token} from {endpoint} with user-agent: {user_agent}")
                        return csrf_token, session
                    if 'data/shared_data' in endpoint:
                        try:
                            data = response.json()
                            csrf_token = data.get('config', {}).get('csrf_token', None)
                            if csrf_token:
                                console.print("[green]Fetched CSRF token from JSON response[/green]")
                                logging.info(f"Fetched CSRF token from JSON: {csrf_token} from {endpoint}")
                                return csrf_token, session
                        except ValueError:
                            pass
                    if 'www.instagram.com' in endpoint:
                        try:
                            match = re.search(r'"csrf_token":"([A-Za-z0-9]+)"', response.text)
                            if match:
                                csrf_token = match.group(1)
                                console.print("[green]Fetched CSRF token from HTML[/green]")
                                logging.info(f"Fetched CSRF token from HTML: {csrf_token} from {endpoint}")
                                return csrf_token, session
                        except Exception:
                            pass
                    console.print(f"[yellow]No CSRF token found at {endpoint} with user-agent {user_agent}. Trying next...[/yellow]")
                    logging.warning(f"No CSRF token found at {endpoint} with user-agent {user_agent}. Response headers: {dict(response.headers)}")
                except Exception as e:
                    console.print(f"[red]Failed to fetch CSRF token from {endpoint} with user-agent {user_agent}: {e}[/red]")
                    logging.error(f"Failed to fetch CSRF token from {endpoint} with user-agent {user_agent}: {e}. Response headers: {dict(response.headers) if 'response' in locals() else 'None'}")
        sleep(uniform(5, 10))
    csrf_token = 'missing'
    console.print("[yellow]No CSRF token retrieved after attempts. Using 'missing' as fallback.[/yellow]")
    logging.warning("No CSRF token retrieved. Using 'missing' as fallback")
    return csrf_token, session

@handle_api_errors(max_attempts=3)
def reauthenticate(user, pess, uid, max_retries=5):
    console.print("[yellow]Session invalid. Attempting re-authentication...[/yellow]")
    logging.info("Attempting re-authentication")
    retries = 0
    while retries < max_retries:
        csrf_token, session = fetch_csrf_token()
        enc_password = encrypt_password(pess)
        data = {
            'username': user,
            'enc_password': enc_password,
            'device_id': uid,
            'from_reg': 'false',
            '_csrftoken': csrf_token,
            'login_attempt_count': str(retries)
        }
        signed_body = generate_signed_body(data)
        headers = {
            'User-Agent': random.choice([
                'Instagram 324.0.0.35.123 Android (34/14; 480dpi; 1080x2400; samsung; SM-G998B; zfold3; exynos2100; en_US)',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 324.0.0.35.123'
            ]),
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-Connection-Type': 'WIFI',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Host': 'i.instagram.com',
            'X-IG-App-ID': '936619743392459',
            'X-Mid': str(uuid.uuid4()),
            'X-Instagram-AJAX': '1000000000',
            'X-IG-WWW-Claim': '0',
            'X-ASBD-ID': '198387',
            'X-Ig-Device-Id': uid,
            'X-Ig-Android-Id': ''.join(random.choices('0123456789abcdef', k=16)),
            'X-CSRFToken': csrf_token,
            'X-Requested-With': 'XMLHttpRequest'
        }
        try:
            r1 = session.post('https://i.instagram.com/api/v1/accounts/login/', headers=headers, data=signed_body, allow_redirects=True)
            r1 = handle_rate_limit(r1)
            logging.info(f"Login response: Status {r1.status_code}, Headers: {dict(r1.headers)}, Body: {r1.text[:200]}, Cookies: {dict(r1.cookies)}")
            if 'logged_in_user' in r1.text:
                console.print("[green]Re-authentication successful[/green]")
                logging.info("Re-authentication successful")
                if 'sessionid' not in r1.cookies or 'csrftoken' not in r1.cookies:
                    console.print("[red]Missing sessionid or csrftoken in response cookies.[/red]")
                    logging.error(f"Missing sessionid or csrftoken in response cookies: {dict(r1.cookies)}")
                    retries += 1
                    sleep(uniform(20, 40))
                    continue
                save_session(r1.cookies['sessionid'], r1.cookies['csrftoken'])
                return r1.cookies['sessionid'], r1.cookies['csrftoken']
            else:
                try:
                    response_json = r1.json()
                    error_message = response_json.get('message', 'Unknown error')
                    error_type = response_json.get('error_type', 'Unknown')
                    full_response = json.dumps(response_json, indent=2)
                except ValueError:
                    error_message = r1.text[:200]
                    error_type = 'Unknown'
                    full_response = r1.text[:200]
                    if '<html' in r1.text.lower():
                        match = re.search(r'https://i\.instagram\.com/challenge/[^\s"]+', r1.text)
                        if match:
                            challenge_url = match.group(0)
                            error_message = f"Challenge required at {challenge_url}"
                            error_type = 'challenge_required'
                console.print(f"[red]Re-authentication failed: {error_message} (Error Type: {error_type}, Status: {r1.status_code})[/red]")
                console.print(f"[red]Full response: {full_response}[/red]")
                logging.error(f"Re-authentication failed: {error_message} (Error Type: {error_type}, Status: {r1.status_code}, Response: {full_response}, Headers: {dict(r1.headers)})")
                if 'needs_upgrade' in error_type:
                    console.print("[yellow]App version outdated. Switching user-agent and retrying...[/yellow]")
                    retries += 1
                    sleep(uniform(20, 40))
                    continue
                elif 'challenge_required' in error_type or 'checkpoint_challenge_required' in error_type:
                    challenge_url = response_json.get('challenge', {}).get('url', r1.headers.get('Location', error_message if 'challenge' in error_message else 'Unknown'))
                    console.print(f"[red]Challenge required. Please complete verification at {challenge_url} in a browser, then press Enter to retry.[/red]")
                    console.print(f"[yellow]Instructions: Open the URL, complete the CAPTCHA or verification (email/SMS), and ensure you can log in manually before retrying.[/yellow]")
                    logging.error(f"Challenge required at {challenge_url} (Status: {r1.status_code}, Response: {full_response})")
                    console.input("[yellow]Press Enter after completing verification...[/yellow]")
                    retries += 1
                    continue
                retries += 1
                sleep(uniform(20, 40))
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error during re-authentication: {e}[/red]")
            logging.error(f"Network error during re-authentication: {e}")
            retries += 1
            sleep(uniform(20, 40))
    console.print("[red]Max re-authentication retries reached.[/red]")
    logging.error("Max re-authentication retries reached")
    exit()

@handle_api_errors(max_attempts=3)
def validate_session(sessionid, csrftoken, max_retries=3):
    user_agents = [
        'Instagram 324.0.0.35.123 Android (34/14; 480dpi; 1080x2400; samsung; SM-G998B; zfold3; exynos2100; en_US)',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 324.0.0.35.123'
    ]
    retries = 0
    session = requests.Session()
    while retries < max_retries:
        csrf_token, _ = fetch_csrf_token()
        try:
            response = session.get(
                'https://i.instagram.com/api/v1/accounts/current_user/',
                headers={
                    'User-Agent': random.choice(user_agents),
                    'Cookie': f'sessionid={sessionid}; csrftoken={csrftoken}',
                    'X-IG-App-ID': '936619743392459',
                    'Accept': 'application/json',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'X-Ig-Device-Id': str(uuid.uuid4()),
                    'X-Ig-Android-Id': ''.join(random.choices('0123456789abcdef', k=16)),
                    'X-CSRFToken': csrf_token,
                    'X-IG-WWW-Claim': '0',
                    'X-Mid': str(uuid.uuid4()),
                    'X-Requested-With': 'XMLHttpRequest'
                }
            )
            response = handle_rate_limit(response)
            if response.status_code == 200:
                console.print("[green]Session validated successfully[/green]")
                logging.info("Session validated successfully")
                return True
            elif response.status_code == 403:
                console.print("[yellow]Session validation failed: Forbidden (403). Possible bot detection.[/yellow]")
                logging.warning(f"Session validation failed: 403 Forbidden, Response: {response.text[:200]}, Headers: {dict(response.headers)}")
            elif response.status_code == 400:
                console.print("[yellow]Session validation failed: Bad Request (400).[/yellow]")
                logging.warning(f"Session validation failed: 400 Bad Request, Response: {response.text[:200]}, Headers: {dict(response.headers)}")
            retries += 1
            sleep(uniform(20, 40))
        except Exception as e:
            console.print(f"[red]Session validation error: {e}[/red]")
            logging.error(f"Session validation error: {e}")
            retries += 1
            sleep(uniform(20, 40))
    console.print("[yellow]Session validation failed after retries.[/yellow]")
    logging.warning("Session validation failed after retries")
    return False

@handle_api_errors(max_attempts=3)
def fetch_target_id(target, sessionid, csrftoken):
    try:
        human_behavior_simulation()
        console.print(f"[cyan]Attempting to fetch ID for {target} via API...[/cyan]")
        session = requests.Session()
        response = session.get(
            f'https://i.instagram.com/api/v1/users/web_profile_info/?username={target}',
            headers={
                'User-Agent': 'Instagram 324.0.0.35.123 Android (34/14; 480dpi; 1080x2400; samsung; SM-G998B; zfold3; exynos2100; en_US)',
                'Cookie': f'csrftoken={csrftoken}; sessionid={sessionid}',
                'X-IG-App-ID': '936619743392459',
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9',
                'X-CSRFToken': csrftoken,
                'X-IG-WWW-Claim': '0',
                'X-Mid': str(uuid.uuid4()),
                'X-Requested-With': 'XMLHttpRequest'
            }
        )
        response.raise_for_status()
        response_json = response.json()
        
        target_id = response_json.get('data', {}).get('user', {}).get('id')
        if not target_id:
            console.print(f"[red]API Error: No user ID found for {target}. Response: {response.text[:200]}[/red]")
            logging.error(f"API fetch failed for {target}: No user ID found. Response: {response.text[:200]}")
            raise ValueError(f"No user ID found for {target} via API.")
        
        console.print(f"[green]Fetched target ID {target_id} for {target} via API[/green]")
        logging.info(f"Fetched target ID {target_id} for {target} via API")
        return target_id
    except Exception as e:
        console.print(f"[yellow]API failed for {target}: {e}. Trying fallback method...[/yellow]")
        logging.warning(f"API fetch failed for {target}: {e}. Trying fallback.")
        
        try:
            session = requests.Session()
            profile_response = session.get(
                f'https://www.instagram.com/{target}/?__a=1&__d=dis',
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
                    'Accept': 'application/json',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            )
            profile_response.raise_for_status()
            profile_data = profile_response.json()
            
            target_id = profile_data.get('graphql', {}).get('user', {}).get('id')
            if not target_id:
                console.print(f"[red]Fallback failed: No user ID found for {target}. Response: {profile_response.text[:200]}[/red]")
                logging.error(f"Fallback failed for {target}: No user ID found. Response: {profile_response.text[:200]}")
                raise ValueError(f"No user ID found for {target} via fallback method.")
            
            console.print(f"[green]Fetched target ID {target_id} for {target} via fallback[/green]")
            logging.info(f"Fetched target ID {target_id} for {target} via fallback")
            return target_id
        except Exception as e:
            console.print(f"[red]Failed to fetch ID for {target}: {e}. Please verify the username exists and is accessible.[/red]")
            logging.error(f"Fallback failed for {target}: {e}")
            raise ValueError(f"Failed to fetch ID for {target}: {e}")

@handle_api_errors(max_attempts=3)
def Report_Instagram(target_id, sessionid, csrftoken, reportType, user, pess, uid, max_retries=5):
    excluded_accounts = ["gh4t4k"]
    if str(target_id).lower() in [account.lower() for account in excluded_accounts]:
        console.print(f"[red]Cannot report {target_id}: account in exception list![/red]")
        logging.warning(f"Attempted to report excluded account {target_id}")
        return False, sessionid, csrftoken

    user_agents = [
        'Instagram 324.0.0.35.123 Android (34/14; 480dpi; 1080x2400; samsung; SM-G998B; zfold3; exynos2100; en_US)',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 324.0.0.35.123',
        'Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36'
    ]

    retries = 0
    current_sessionid, current_csrftoken = sessionid, csrftoken
    session = requests.Session()
    while retries < max_retries:
        try:
            if not validate_session(current_sessionid, current_csrftoken):
                console.print("[yellow]Session invalid before report. Re-authenticating...[/yellow]")
                current_sessionid, current_csrftoken = reauthenticate(user, pess, uid)

            headers = {
                'User-Agent': random.choice(user_agents),
                'Host': 'i.instagram.com',
                'Cookie': f'sessionid={current_sessionid}; csrftoken={current_csrftoken}',
                'X-CSRFToken': current_csrftoken,
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-IG-App-ID': '936619743392459',
                'X-Instagram-AJAX': '1000000000',
                'X-IG-WWW-Claim': '0',
                'X-ASBD-ID': '198387',
                'X-Ig-Device-Id': str(uuid.uuid4()),
                'X-Ig-Android-Id': ''.join(random.choices('0123456789abcdef', k=16)),
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US,en;q=0.9',
                'X-Mid': str(uuid.uuid4()),
                'X-Requested-With': 'XMLHttpRequest'
            }
            response = session.post(
                f"https://i.instagram.com/users/{target_id}/flag/",
                headers=headers,
                data=f'source_name=&reason_id={reportType}&frx_context=',
                allow_redirects=False
            )
            response = handle_rate_limit(response, max_retries)
            logging.info(f"Report response for {target_id}: Status {response.status_code}, Headers: {dict(response.headers)}, Body: {response.text[:200]}")

            if response.status_code == 200:
                console.print(f"[green]Report successfully sent for {target_id}.[/green]")
                logging.info(f"Report sent successfully for {target_id}")
                sleep(uniform(20, 40))
                return True, current_sessionid, current_csrftoken
            elif response.status_code == 302:
                redirect_url = response.headers.get('Location', 'Unknown')
                console.print(f"[yellow]Redirected to: {redirect_url}[/yellow]")
                logging.warning(f"302 Redirect for {target_id} to {redirect_url}")
                if 'accounts/login' in redirect_url:
                    console.print("[yellow]Session invalid. Re-authenticating...[/yellow]")
                    current_sessionid, current_csrftoken = reauthenticate(user, pess, uid)
                    retries += 1
                    continue
                elif 'challenge' in redirect_url:
                    console.print(f"[red]CAPTCHA detected. Please solve it manually in a browser at {redirect_url} and then press Enter to retry.[/red]")
                    logging.error(f"CAPTCHA detected for {target_id}: {redirect_url}")
                    console.input("[yellow]Press Enter after solving CAPTCHA...[/yellow]")
                    retries += 1
                    continue
                return False, current_sessionid, current_csrftoken
            elif response.status_code == 403:
                console.print("[yellow]Report failed: Forbidden (403). Possible bot detection or session issue.[/yellow]")
                logging.warning(f"Report failed for {target_id}: 403 Forbidden, Response: {response.text[:200]}, Headers: {dict(response.headers)}")
                if '<html' in response.text.lower():
                    match = re.search(r'https://i\.instagram\.com/challenge/[^\s"]+', response.text)
                    if match:
                        challenge_url = match.group(0)
                        console.print(f"[red]Challenge detected. Please complete verification at {challenge_url} in a browser, then press Enter to retry.[/red]")
                        console.print(f"[yellow]Instructions: Open the URL, complete the CAPTCHA or verification (email/SMS), and ensure you can log in manually before retrying.[/yellow]")
                        logging.error(f"Challenge detected for {target_id}: {challenge_url}")
                        console.input("[yellow]Press Enter after completing verification...[/yellow]")
                        retries += 1
                        continue
                console.print("[yellow]Re-authenticating due to 403 error...[/yellow]")
                current_sessionid, current_csrftoken = reauthenticate(user, pess, uid)
                retries += 1
                continue
            elif response.status_code == 500:
                console.print(f"[red]Target not found. Status code: {response.status_code}[/red]")
                logging.error(f"Target {target_id} not found: Status 500")
                return False, current_sessionid, current_csrftoken
            else:
                console.print(f"[red]Unexpected error: {response.status_code}, Response: {response.text[:100]}...[/red]")
                logging.error(f"Unexpected error for {target_id}: Status {response.status_code}, Response: {response.text[:100]}, Headers: {dict(response.headers)}")
                return False, current_sessionid, current_csrftoken
        except Exception as e:
            console.print(f"[red]Error reporting {target_id}: {e}[/red]")
            logging.error(f"Error reporting {target_id}: {e}")
            return False, current_sessionid, current_csrftoken
    console.print(f"[red]Max retries reached for {target_id}.[/red]")
    logging.error(f"Max retries reached for {target_id}")
    return False, current_sessionid, current_csrftoken

def handle_2fa_login(user, pess, uid, max_attempts=3):
    console.print("[yellow]Two-factor authentication required.[/yellow]")
    logging.info("Two-factor authentication prompted")
    csrf_token, session = fetch_csrf_token()
    attempts = 0
    while attempts < max_attempts:
        verification_code = console.input(f"[green]Enter the OTP sent to your phone/email (Attempt {attempts + 1}/{max_attempts}): [/green]").strip()
        if not verification_code:
            console.print("[red]OTP cannot be empty![/red]")
            logging.error("Empty OTP provided")
            attempts += 1
            continue

        try:
            data = {
                'username': user,
                'verificationCode': verification_code,
                'device_id': uid,
                '_csrftoken': csrf_token
            }
            signed_body = generate_signed_body(data)
            response = session.post(
                'https://i.instagram.com/api/v1/accounts/two_factor_login/',
                headers={
                    'User-Agent': 'Instagram 324.0.0.35.123 Android (34/14; 480dpi; 1080x2400; samsung; SM-G998B; zfold3; exynos2100; en_US)',
                    'Accept': 'application/json',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'X-IG-Capabilities': '3brTvw==',
                    'X-IG-Connection-Type': 'WIFI',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Host': 'i.instagram.com',
                    'X-IG-App-ID': '936619743392459',
                    'X-Mid': str(uuid.uuid4()),
                    'X-Instagram-AJAX': '1000000000',
                    'X-IG-WWW-Claim': '0',
                    'X-ASBD-ID': '198387',
                    'X-Ig-Device-Id': uid,
                    'X-Ig-Android-Id': ''.join(random.choices('0123456789abcdef', k=16)),
                    'X-CSRFToken': csrf_token,
                    'X-Requested-With': 'XMLHttpRequest'
                },
                data=signed_body,
                allow_redirects=True
            )
            response = handle_rate_limit(response)
            logging.info(f"2FA response: Status {response.status_code}, Headers: {dict(response.headers)}, Body: {response.text[:200]}, Cookies: {dict(response.cookies)}")
            if 'logged_in_user' in response.text:
                console.print("[green]2FA login successful[/green]")
                logging.info(f"2FA login successful for {user}")
                if 'sessionid' not in response.cookies or 'csrftoken' not in response.cookies:
                    console.print("[red]Missing sessionid or csrftoken in 2FA response cookies.[/red]")
                    logging.error(f"Missing sessionid or csrftoken in 2FA response cookies: {dict(response.cookies)}")
                    attempts += 1
                    continue
                save_session(response.cookies['sessionid'], response.cookies['csrftoken'])
                return response
            else:
                try:
                    response_json = response.json()
                    error_message = response_json.get('message', 'Unknown error')
                    error_type = response_json.get('error_type', 'Unknown')
                    full_response = json.dumps(response_json, indent=2)
                except ValueError:
                    error_message = response.text[:200]
                    error_type = 'Unknown'
                    full_response = response.text[:200]
                console.print(f"[red]2FA login failed: {error_message} (Error Type: {error_type}, Status: {response.status_code})[/red]")
                console.print(f"[red]Full response: {full_response}[/red]")
                logging.error(f"2FA login failed for {user}: {error_message} (Error Type: {error_type}, Status: {response.status_code}, Response: {full_response}, Headers: {dict(response.headers)})")
                attempts += 1
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error during 2FA login: {e}[/red]")
            logging.error(f"Network error during 2FA login: {e}")
            attempts += 1
            sleep(uniform(20, 40))
    
    console.print("[red]Max 2FA attempts reached. Exiting.[/red]")
    logging.error("Max 2FA attempts reached")
    exit()

def load_session(filename='session.json'):
    try:
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            with open(filename, 'r') as f:
                session = json.load(f)
                if validate_session(session['sessionid'], session['csrftoken']):
                    console.print("[green]Session Loaded Successfully[/green]")
                    logging.info("Loaded valid session from file")
                    return session['sessionid'], session['csrftoken']
                else:
                    console.print("[yellow]Session invalid. Proceeding with login...[/yellow]")
                    logging.info("Invalid session found")
        else:
            console.print("[yellow]No valid session file found. Proceeding with login...[/yellow]")
            logging.info("No valid session file found or file is empty")
    except json.JSONDecodeError:
        console.print("[yellow]Corrupted session file. Deleting and proceeding with login...[/yellow]")
        logging.error("Corrupted session file detected")
        if os.path.exists(filename):
            os.remove(filename)
            logging.info("Deleted corrupted session file")
    except Exception as e:
        console.print(f"[red]Error loading session: {e}[/red]")
        logging.error(f"Error loading session: {e}")
    return None, None

def save_session(sessionid, csrftoken, filename='session.json'):
    try:
        with open(filename, 'w') as f:
            json.dump({'sessionid': sessionid, 'csrftoken': csrftoken}, f, indent=2)
        console.print("[green]Session saved to file[/green]")
        logging.info("Session saved to file")
    except Exception as e:
        console.print(f"[red]Error saving session: {e}[/red]")
        logging.error(f"Error saving session: {e}")

@handle_api_errors(max_attempts=3)
def starter():
    console.print(Text("Login System!", style="bold underline"))
    verify_access_key()
    verify_expiration_date()
    
    sessionid, csrftoken = load_session()
    if sessionid and csrftoken:
        user = None
        pess = None
        uid = str(uuid.uuid4())
    else:
        user = console.input("[green]Enter reporter ID Username : [/green]").strip()
        if not user:
            console.print("[red]You must write the username![/red]", style="bold red")
            logging.error("Empty username provided")
            exit()
        
        pess = console.input("[green]Enter report ID Password : [/green]").strip()
        if not pess:
            console.print("[red]You must write the password![/red]", style="bold red")
            logging.error("Empty password provided")
            exit()
        
        human_behavior_simulation()
        uid = str(uuid.uuid4())
        max_retries = 5
        retries = 0
        session = requests.Session()
        
        while retries < max_retries:
            csrf_token, session = fetch_csrf_token()
            try:
                enc_password = encrypt_password(pess)
                data = {
                    'username': user,
                    'enc_password': enc_password,
                    'device_id': uid,
                    'from_reg': 'false',
                    '_csrftoken': csrf_token,
                    'login_attempt_count': str(retries)
                }
                signed_body = generate_signed_body(data)
                headers = {
                    'User-Agent': random.choice([
                        'Instagram 324.0.0.35.123 Android (34/14; 480dpi; 1080x2400; samsung; SM-G998B; zfold3; exynos2100; en_US)',
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
                        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 324.0.0.35.123'
                    ]),
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'X-IG-Capabilities': '3brTvw==',
                    'X-IG-Connection-Type': 'WIFI',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Host': 'i.instagram.com',
                    'X-IG-App-ID': '936619743392459',
                    'X-Mid': str(uuid.uuid4()),
                    'X-Instagram-AJAX': '1000000000',
                    'X-IG-WWW-Claim': '0',
                    'X-ASBD-ID': '198387',
                    'X-Ig-Device-Id': uid,
                    'X-Ig-Android-Id': ''.join(random.choices('0123456789abcdef', k=16)),
                    'X-CSRFToken': csrf_token,
                    'X-Requested-With': 'XMLHttpRequest'
                }
                r1 = session.post('https://i.instagram.com/api/v1/accounts/login/', headers=headers, data=signed_body, allow_redirects=True)
                r1 = handle_rate_limit(r1)
                logging.info(f"Login response: Status {r1.status_code}, Headers: {dict(r1.headers)}, Body: {r1.text[:200]}, Cookies: {dict(r1.cookies)}")
                try:
                    response_json = r1.json()
                    error_message = response_json.get('message', 'Unknown error')
                    error_type = response_json.get('error_type', 'Unknown')
                    full_response = json.dumps(response_json, indent=2)
                except ValueError:
                    error_message = r1.text[:200]
                    error_type = 'Unknown'
                    full_response = r1.text[:200]
                    if '<html' in r1.text.lower():
                        match = re.search(r'https://i\.instagram\.com/challenge/[^\s"]+', r1.text)
                        if match:
                            error_message = f"Challenge required at {match.group(0)}"
                            error_type = 'challenge_required'

                if 'logged_in_user' in r1.text:
                    console.print("Logged in [green]successfully[/green]")
                    logging.info(f"Logged in successfully as {user}")
                    if 'sessionid' not in r1.cookies or 'csrftoken' not in r1.cookies:
                        console.print("[red]Missing sessionid or csrftoken in response cookies.[/red]")
                        logging.error(f"Missing sessionid or csrftoken in response cookies: {dict(r1.cookies)}")
                        retries += 1
                        sleep(uniform(20, 40))
                        continue
                    sessionid = r1.cookies['sessionid']
                    csrftoken = r1.cookies['csrftoken']
                    save_session(sessionid, csrftoken)
                    break
                elif 'two_factor_required' in r1.text:
                    r1 = handle_2fa_login(user, pess, uid)
                    if 'logged_in_user' in r1.text:
                        console.print("[green]2FA login successful[/green]")
                        logging.info(f"2FA login successful for {user}")
                        sessionid = r1.cookies.get('sessionid')
                        csrftoken = r1.cookies.get('csrftoken')
                        if not sessionid or not csrftoken:
                            console.print("[red]Missing sessionid or csrftoken in 2FA response cookies.[/red]")
                            logging.error(f"Missing sessionid or csrftoken in 2FA response cookies: {dict(r1.cookies)}")
                            exit()
                        save_session(sessionid, csrftoken)
                        break
                    else:
                        console.print(f"[red]2FA login failed: {r1.text[:200]} (Status: {r1.status_code})[/red]")
                        logging.error(f"2FA login failed for {user}: {r1.text[:200]} (Status: {r1.status_code})")
                        exit()
                elif 'bad_password' in error_type or 'invalid_credentials' in error_type:
                    console.print("[red]Login failed: Incorrect username or password. Please verify your credentials.[/red]")
                    logging.error(f"Login failed for {user}: Incorrect username or password (Status: {r1.status_code}, Response: {full_response}, Headers: {dict(r1.headers)})")
                    exit()
                elif 'challenge_required' in error_type or 'checkpoint_challenge_required' in error_type:
                    challenge_url = response_json.get('challenge', {}).get('url', r1.headers.get('Location', error_message if 'challenge' in error_message else 'Unknown'))
                    console.print(f"[red]Challenge required. Please complete verification at {challenge_url} in a browser, then press Enter to retry.[/red]")
                    console.print(f"[yellow]Instructions: Open the URL, complete the CAPTCHA or verification (email/SMS), and ensure you can log in manually before retrying.[/yellow]")
                    logging.error(f"Login failed for {user}: Challenge required at {challenge_url} (Status: {r1.status_code}, Response: {full_response}, Headers: {dict(r1.headers)})")
                    console.input("[yellow]Press Enter after completing verification...[/yellow]")
                    retries += 1
                    continue
                elif 'needs_upgrade' in error_type:
                    console.print("[yellow]App version outdated. Switching user-agent and retrying...[/yellow]")
                    logging.error(f"Login failed for {user}: App version outdated (Status: {r1.status_code}, Response: {full_response}, Headers: {dict(r1.headers)})")
                    retries += 1
                    sleep(uniform(20, 40))
                    continue
                elif r1.status_code == 429:
                    console.print("[red]Login failed: Rate limit exceeded. Please wait 15-30 minutes and try again.[/red]")
                    logging.error(f"Login failed for {user}: Rate limit exceeded (Status: 429, Response: {full_response}, Headers: {dict(r1.headers)})")
                    exit()
                else:
                    console.print(f"[red]Login failed: {error_message} (Error Type: {error_type}, Status: {r1.status_code})[/red]")
                    console.print(f"[red]Full response: {full_response}[/red]")
                    logging.error(f"Login failed for {user}: {error_message} (Error Type: {error_type}, Status: {r1.status_code}, Response: {full_response}, Headers: {dict(r1.headers)})")
                    retries += 1
                    sleep(uniform(20, 40))
            except requests.exceptions.RequestException as e:
                console.print(f"[red]Network error during login: {e}[/red]")
                logging.error(f"Network error during login for {user}: {e}")
                retries += 1
                sleep(uniform(20, 40))
        
        if retries >= max_retries:
            console.print("[red]Max login retries reached. Exiting.[/red]")
            logging.error(f"Max login retries reached for {user}")
            exit()

    mode = console.input(f"[cyan]Select Mode: \n1 - Battle Arc Mode (gand fad mode)\n2 - Noti Claiming Mode (singles report)\nEnter your choice: [/cyan]").strip()
    if mode == '1':
        battle_arc_mode(sessionid, csrftoken, user, pess, uid)
    elif mode == '2':
        noti_claiming_mode(sessionid, csrftoken, user, pess, uid)
    else:
        console.print("[red]Invalid choice! Exiting.[/red]")
        logging.error("Invalid mode selected")
        exit()

def noti_claiming_mode(sessionid, csrftoken, user, pess, uid):
    console.print(Text("NOTI CLAIMING MODE HAS BEEN ACTIVATED!", style="bold italic blue"))
    logging.info("Noti Claiming Mode activated")
    current_sessionid, current_csrftoken = sessionid, csrftoken

    try:
        num_reports = int(console.input(f"[yellow]How many targets do you want to report? (kitne dushman hai?) : [/yellow]").strip())
        if num_reports <= 0:
            console.print("[red]Please enter a positive number.[/red]")
            logging.error("Non-positive number of reports entered")
            return
    except ValueError:
        console.print("[red]Invalid input. Please enter a valid number.[/red]")
        logging.error("Invalid input for number of reports")
        return

    targets = []
    for i in range(num_reports):
        target = console.input(f"[cyan]Enter username of target {i + 1}: [/cyan]").strip()
        if target:
            targets.append(target)
        else:
            console.print("[red]Username cannot be empty! Skipping this target.[/red]")
            logging.warning(f"Empty username for target {i + 1}")

    console.print("[cyan]Choose Report Type:[/cyan]")
    report_options = [
        "1 - Spam",
        "2 - Self",
        "3 - Drugs",
        "4 - Nudity",
        "5 - Violence",
        "6 - Hate",
        "7 - Bullying",
        "8 - Impersonation"
    ]
    for option in report_options:
        console.print(f"[yellow]{option}[/yellow]")

    while True:
        try:
            reportType = int(console.input(f"[blue]Choose Report Type (1-8): [/blue]").strip())
            if 1 <= reportType <= 8:
                console.print(f"[green]You selected: {reportType}[/green]")
                logging.info(f"Selected report type: {reportType}")
                break
            else:
                console.print("[red]Invalid input. Please choose a number between 1 and 8.[/red]")
                logging.error("Invalid report type selected")
        except ValueError:
            console.print("[red]Invalid input. Please enter a valid number.[/red]")
            logging.error("Invalid input for report type")

    for target in targets:
        try:
            console.print(f"[cyan]Fetching ID for {target}...[/cyan]")
            target_id = fetch_target_id(target, current_sessionid, current_csrftoken)
            console.print(f"[green]Target ID for {target}: {target_id}[/green]")
            success, current_sessionid, current_csrftoken = Report_Instagram(
                target_id, current_sessionid, current_csrftoken, reportType, user, pess, uid
            )
            if not success:
                console.print(f"[red]Failed to report {target}.[/red]")
                logging.error(f"Failed to report {target}")
        except Exception as e:
            console.print(f"[red]Error reporting {target}: {e}[/red]")
            logging.error(f"Error reporting {target}: {e}")

    console.print("[green]All reports have been sent![/green]")
    logging.info("All reports sent in Noti Claiming Mode")

def battle_arc_mode(sessionid, csrftoken, user, pess, uid):
    console.print(Text("BATTLE ARC MODE HAS BEEN ACTIVATED!", style="bold italic blue"))
    logging.info("Battle Arc Mode activated")
    current_sessionid, current_csrftoken = sessionid, csrftoken

    while True:
        try:
            target = console.input("[green]Enter Target Username: [/green]").strip()
            if not target:
                console.print("[red]Username cannot be empty![/red]")
                logging.error("Empty target username entered")
                continue

            target_id = fetch_target_id(target, current_sessionid, current_csrftoken)
            console.print(f"[yellow]Target ID for {target}: {target_id}[/yellow]")

            console.print("[cyan]Choose Report Type:[/cyan]")
            report_options = [
                "1 - Spam",
                "2 - Self",
                "3 - Drugs",
                "4 - Nudity",
                "5 - Violence",
                "6 - Hate",
                "7 - Bullying",
                "8 - Impersonation"
            ]
            for option in report_options:
                console.print(f"[yellow]{option}[/yellow]")

            while True:
                try:
                    reportType = int(console.input(f"[blue]Choose Report Type (1-8): [/blue]").strip())
                    if 1 <= reportType <= 8:
                        console.print(f"[green]You selected: {reportType}[/green]")
                        logging.info(f"Selected report type: {reportType}")
                        break
                    else:
                        console.print("[red]Invalid input. Please choose a number between 1 and 8.[/red]")
                        logging.error("Invalid report type selected")
                except ValueError:
                    console.print("[red]Invalid input. Please enter a valid number.[/red]")
                    logging.error("Invalid input for report type")

            while True:
                try:
                    num_reports = int(console.input("[yellow]Enter the number of reports to send: [/yellow]").strip())
                    if num_reports > 0:
                        console.print(f"[yellow]Preparing to send {num_reports} reports...[/yellow]")
                        logging.info(f"Preparing to send {num_reports} reports for {target_id}")
                        break
                    else:
                        console.print("[red]Please enter a positive number.[/red]")
                        logging.error("Non-positive number of reports entered")
                except ValueError:
                    console.print("[red]Invalid input. Please enter a valid number.[/red]")
                    logging.error("Invalid input for number of reports")

            success_count = 0
            for i in range(num_reports):
                try:
                    success, current_sessionid, current_csrftoken = Report_Instagram(
                        target_id, current_sessionid, current_csrftoken, reportType, user, pess, uid
                    )
                    if success:
                        console.print(f"[green]Report {i + 1} successfully sent.[/green]")
                        success_count += 1
                    else:
                        console.print(f"[red]Report {i + 1} failed.[/red]")
                        logging.error(f"Report {i + 1} failed for {target_id}")
                        break
                except Exception as e:
                    console.print(f"[red]Error sending report {i + 1} for {target_id}: {e}[/red]")
                    logging.error(f"Error sending report {i + 1} for {target_id}: {e}")
                    break
                sleep(uniform(20, 40))

            console.print(f"[green]All reports have been submitted. Successfully sent {success_count}/{num_reports} reports.[/green]")
            logging.info(f"Completed reporting for {target_id}: {success_count}/{num_reports} reports successful")

            continue_reporting = console.input("[green]Do you want to continue reporting? (yes/no): [/green]").strip().lower()
            if continue_reporting != 'yes':
                console.print("[red]Exiting the Battle Arc Mode...[/red]", style="bold italic red")
                logging.info("Exiting Battle Arc Mode")
                break
        except ValueError as error:
            console.print(f"[red]Error: {error}[/red]")
            logging.error(f"Error in Battle Arc Mode: {error}")
            continue
        except Exception as e:
            console.print(f"[red]Unexpected error in Battle Arc Mode: {e}[/red]")
            logging.error(f"Unexpected error in Battle Arc Mode: {e}")
            continue

header()
starter()
bot_signature()