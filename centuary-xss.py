import asyncio
import aiohttp
import urllib.parse
import random
import json
import os
import re
import platform
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from argparse import ArgumentParser
import pyfiglet
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, NoAlertPresentException
from tqdm import tqdm  # Import tqdm for progress bar

# Constants
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 10

# colors lmao
cyan = '\033[96m'
purple = '\033[95m'
orange = '\033[33m'
red = '\033[91m'
green = '\033[92m'
boldgreen = '\033[1;32m'
yellow = '\033[93m'
blue = '\033[94m'
boldwhite = '\033[1;97m'
reset = '\033[0m'

results = []

# tool_example Payloads
def eg_payloads(payload_input):
    payloads = []
    if os.path.isfile(payload_input):
        try:
            with open(payload_input, 'r') as file:
                payloads = [line.strip() for line in file if line.strip()]
                if not payloads:
                    raise ValueError(f"{boldwhite}The payloads file is empty.{reset}")
        except FileNotFoundError:
            print(f"{boldwhite}Error: The payload file '{payload_input}' was not found.{reset}")
            return[]
        except PermissionError:
            print(f"{boldwhite}Error: Insufficent permission to read the payload file '{payload_input}'.{reset}")
            return[]
        except ValueError as ve:
            print(f"{boldwhite}Error {ve}{reset}")
            return[]
        except Exception as e:
            print(f"{boldwhite}Error: An unexpected error while reading payload file '{payload_input}'. Error: {e}{reset}")
            return[]
    else:
        payloads = [payload_input]

    return payloads

# Asynchronous Scanner Engine with retry and extended timeout
async def scan(url, payloads, semaphore, stealth_mode=False, method='GET', data=None, timeout=DEFAULT_TIMEOUT, delay=0.5):
    async with semaphore:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            tasks = []
            for payload in payloads:
                if method.upper() == 'POST':
                    tasks.append(scan_post(session, url, payload, data, timeout))
                else:
                    tasks.append(scan_get(session, url, payload, timeout))
            responses = await asyncio.gather(*tasks)

            for response in responses:
                if response:
                    url, payload, text, headers = response

                    if is_false_positive(text, payload, headers):
                        print(f"{purple}[+] False positive avoided for payload: {payload} on {url}{reset}")
                    else:
                        print(f"{green}[✔️] Possible XSS detected with payload: {payload} on {url}{reset}")
                else:
                    print(f"{yellow}[!] No response or failed for payload: {payload} on {url}{reset}")

                if stealth_mode:
                    await asyncio.sleep(delay)

async def scan_post(session, url, payload, data, timeout):
    for attempt in range(MAX_RETRIES):
        try:
            async with session.post(url, data={**data, 'input': payload}) as response:
                text = await response.text()
                headers = response.headers
                return url, payload, text, response.headers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(f"{red}[!] POST request failed for payload: {payload} on {url}. Error: {e}{reset}")
            return None

async def scan_get(session, url, payload, timeout):
    target_url = f"{url}?input={payload}"
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(target_url) as response:
                text = await response.text()
                headers = response.headers
                return target_url, payload, text, response.headers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(f"{red}[!] GET request failed for payload: {payload} on {url}. Error: {e}{reset}")
            return None

# Contextual False Positive Detection
def is_false_positive(text, payload, headers):
    if headers is None:
        headers = {}
    if in_safe_context(text, payload):
        return True
    if is_non_executable_context(text):
        return True
    if is_sanitized(text, payload):
        return True
    if has_strong_csp(headers):
        return True
    return False

def in_safe_context(text, payload):
    soup = BeautifulSoup(text, 'html.parser')
    safe_tags = ['<textarea>', '<pre>', '<code>', '&lt;', '&gt;']
    for tag in safe_tags:
        if soup.find_all(tag):
            return True
    if any(payload in str(tag) for tag in soup.find_all()):
        return True
    return False

def is_non_executable_context(text):
    return "<!--" in text or "-->" in text

def is_sanitized(text, payload):
    encoded_payload = urllib.parse.quote_plus(payload) 
    sanitized_payload = payload.replace('<', '&lt;').replace('>', '&gt;') 

    if encoded_payload in text or sanitized_payload in text:
        return True

    html_entity_payloads = payload.replace('<', '&#60').replace('>', '&#62')
    if html_entity_payloads in text:
        return True

    if re.search(re.escape(payload), text, re.IGNORECASE):
        return True

    return False

def has_strong_csp(headers):
    csp = headers.get('Content-Security-Policy', '')
    strong_policies = [
        "script-src 'self'"
        "script-src 'nonce-"
        "script-src 'strict-dynamic'"
    ]
    return any(policy in csp for policy in strong_policies)

# DOM-Based XSS Detection with Improved Dynamic Content Handling
def check_dom_xss(url, payloads, browser='chrome', chromedriver_path=None, geckodriver_path=None, edgedriver_path=None):
    options, service = get_browser_options(browser, chromedriver_path, geckodriver_path, edgedriver_path)

    driver = webdriver.Chrome(service=service, options=options) if browser == 'chrome' else (
        webdriver.Firefox(service=service, options=options) if browser == 'firefox' else 
        webdriver.Edge(service=service, options=options)
    )

    for payload in payloads:
        driver.get(f"{url}?input={payload}")
        try:
            # Wait for specific dynamic content or JavaScript executions
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, "element_id"))  # Adjust the condition as needed
            )
            # Capture JavaScript errors or dynamic changes
            logs = driver.get_log('browser')
            for log in logs:
                if 'error' in log['message'].lower():
                    print(f"{red}[!] JavaScript error detected for payload: {payload} on {url}. Error: {log['message']}{reset}")

                if "unexpected behavior" in driver.page_source.lower():
                    print(f"{green}[✔️] DOM XSS detected with payload: {payload} on {url}{reset}")
            try:
                alert = driver.switch_to.alert
                print(f"{green}[✔️] DOM XSS detected with payload: {payload} on {url}{reset}")
                alert.accept()
            except NoAlertPresentException:
                print(f"{cyan}[+] Safe for DOM payload: {payload} on {url}{reset}")

        except TimeoutException:
            print(f"{cyan}[+] Safe for DOM payload: {payload} on {url}{reset}")
        except Exception as e:
            print(f"{red}[!] Error detecting DOM XSS with payload: {payload} on {url}. Error: {e}{reset}")

    driver.quit()

def get_browser_options(browser, chromedriver_path=None, geckodriver_path=None, edgedriver_path=None):
    if browser == 'firefox':
        options = FirefoxOptions()
        service = FirefoxService(geckodriver_path) if geckodriver_path else FirefoxService('/usr/local/bin/geckodriver')
    elif browser == 'edge':
        options = EdgeOptions()
        service = EdgeService(edgedriver_path) if edgedriver_path else EdgeService('/usr/local/bin/edgedriver')
    else:
        options = Options()
        service = ChromeService(chromedriver_path) if chromedriver_path else ChromeService('/usr/local/bin/chromedriver')

    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    return options, service

# Server-Side Environment Detection
def detect_server_environment(url):
    # Placeholder logic for detecting server environment
    if 'php' in url.lower():
        return 'PHP'
    elif 'aspx' in url.lower():
        return 'ASP.NET'
    elif 'js' in url.lower():
        return 'Node.js'
    return 'Unknown'

# Path-Based Analysis
async def path_based_analysis(url, payloads, paths, semaphore, stealth_mode=False):
    for path in paths:
        full_url = f"{url}/{path}"
        print(f"{blue}[*] Scanning path: {full_url}{reset}")
        await scan(full_url, payloads, semaphore, stealth_mode)

# Advanced Parameter Analysis
async def analyze_parameters(url, payloads, parameters, semaphore, stealth_mode=False, timeout=DEFAULT_TIMEOUT, delay=0.5):
    async with semaphore:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            tasks = []
            for param in parameters:
                for payload in payloads:
                    tampered_data = {param: payload}
                    tasks.append(scan_param(session, url, tampered_data, payload, timeout))
            total_tasks = len(tasks)
            for i, response in enumerate(await asyncio.gather(*tasks)):
                print(f"Debug - Response received: {response}")
                if response:
                    if len(response) == 4:
                        url, param, payload, text = response
                        headers  = {}
                    elif len(response) == 5:
                        url, param, payload, text, headers = response
                    else:
                        continue

                    if headers is None:
                        headers = {}

                    if is_false_positive(text, payload, response.headers):
                        print(f"{purple}[+] False positive avoided for parameter tampering: {param}={payload} on {url}{reset}")
                    else:
                        print(f"{green}[✔️] Possible XSS detected with parameter tampering: {param}={payload} on {url}{reset}")
                else:
                    print(f"{yellow}[!] No response or failed for parameter tampering: {param}={payload} on {url}{reset}")

                if stealth_mode:
                    await asyncio.sleep(delay)

                # Update progress bar
                tqdm.write(f"{boldwhite}Progress: {i + 1}/{total_tasks}{reset}")

async def scan_param(session, url, data, payload, timeout):
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(url, params=data) as response:
                text = await response.text()
                headers = response.headers
            return url, list(data.keys())[0], payload, text, headers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(f"{red}[!] GET request with parameter failed for {list(data.keys())[0]}={payload} on {url}. Error: {e}{reset}")
            return None

# Reporting Module
def generate_report(results, output_file):
    output_format = output_file.split('.')[-1]
    with open(output_file, 'w') as report_file:
        if output_format == 'json':
            json.dump(results, report_file, indent=4)
        else:
            for result in results:
                report_file.write(f"{result}\n")

# Extension-Based XSS Detection
def extension_based_detection(url, payloads, browser='chrome'):
    check_dom_xss(url, payloads, browser)

# Main function with CLI
async def main():
    # Print ASCII art for "centuary-xss"
    ascii_banner = pyfiglet.figlet_format("centuary-xss")
    print(f"{red}{ascii_banner}{reset}")

    parser = ArgumentParser(description="Advanced XSS Detection and Exploitation Tool")
    parser.add_argument('-u', '--url', type=str, help="Target URL")
    parser.add_argument('-f', '--file', type=str, help="File containing list of URLs")
    parser.add_argument('-m', '--mode', type=str, default='standard', choices=['standard', 'stealth', 'dom', 'path', 'extension', 'params', 'all'], help="Scan mode (standard, stealth, dom, path, extension, params, all)")
    parser.add_argument('-o', '--output', type=str, default='xss_report.json', help="Output report file name")
    parser.add_argument('-p', '--payloads', type=str, help="File containing custom XSS payloads or a single payload")
    parser.add_argument('-d', '--delay', type=float, default=0.5, help="Custom delay between requests (in seconds)")
    parser.add_argument('--method', type=str, default='GET', choices=['GET', 'POST'], help="HTTP method for requests")
    parser.add_argument('--data', type=json.loads, help="Data for POST requests (JSON format)")
    parser.add_argument('--paths', type=str, nargs='+', help="Paths for path-based analysis")
    parser.add_argument('--params', type=str, nargs='+', help="Parameters for advanced parameter analysis")
    parser.add_argument('--browser', type=str, default='chrome', choices=['chrome', 'firefox', 'edge'], help="Browser for DOM XSS detection")
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help="Timeout for requests (in seconds)")
    parser.add_argument('--concurrency', type=int, default=5, help="Limit of concurrent requests")
    parser.add_argument('--chromedriver', type=str, help="Path to chromedriver")
    parser.add_argument('--geckodriver', type=str, help="Path to geckodriver")
    parser.add_argument('--edgedriver', type=str, help="Path to edgedriver")

    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file, 'r') as file:
            urls.extend([line.strip() for line in file])


    mode = args.mode
    output_file = args.output
    delay = args.delay
    method = args.method
    data = args.data
    paths = args.paths
    params = args.params
    browser = args.browser
    timeout = args.timeout
    concurrency = args.concurrency
    chromedriver_path = args.chromedriver
    geckodriver_path = args.geckodriver
    edgedriver_path = args.edgedriver

    payloads = eg_payloads(args.payloads)
    
    if not payloads:
        print(f"{orange}Error: No payloads were loaded. Exiting...{reset}")

    semaphore = asyncio.Semaphore(concurrency)

    for url in urls:
        server_env = detect_server_environment(url)
        print(f"{yellow}[*] Detected server environment: {server_env}{reset}")

        if mode in ['standard', 'stealth', 'all']:
            print(f"{blue}[*] Starting {'stealth ' if mode == 'stealth' else ''}scan on {url}...{reset}")
            # Create a progress bar for scanning
            for _ in tqdm(range(len(payloads)), desc=f"{boldwhite}Scanning payloads{reset}"):
                await scan(url, payloads, semaphore, stealth_mode=(mode == 'stealth'), method=method, data=data, timeout=timeout, delay=delay)

        if mode in ['dom', 'all']:
            print(f"{blue}[*] Performing DOM-based XSS detection on {url} using {browser}...{reset}")
            check_dom_xss(url, payloads, browser, chromedriver_path, geckodriver_path, edgedriver_path)

        if mode in ['path', 'all'] and paths:
            print(f"{blue}[*] Performing path-based analysis on {url}...{reset}")
            await path_based_analysis(url, payloads, paths, semaphore, stealth_mode=(mode == 'stealth'))

        if mode in ['params', 'all'] and params:
            print(f"{blue}[*] Performing advanced parameter analysis on {url}...{red}")
            await analyze_parameters(url, payloads, params, semaphore, stealth_mode=(mode == 'stealth'), timeout=timeout, delay=delay)

        if mode in ['extension', 'all']:
            print(f"{blue}[*] Performing extension-based XSS detection on {url}...{reset}")
            extension_based_detection(url, payloads, browser)

        results.append(f"{green} Scan complete for {url}{reset}")

    generate_report(results, output_file)
    print(f"{boldgreen}[*] Scan complete. Report saved to {output_file}.{reset}")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{boldwhite}[!] Process interupted by user. Exiting.....{reset}")
        exit(0)

