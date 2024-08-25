import asyncio
import aiohttp
import urllib.parse
import random
import json
import os
import platform
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from argparse import ArgumentParser
from termcolor import colored
import pyfiglet
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, NoAlertPresentException

# Constants
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 10

# Generate Payloads
def generate_payloads(payloads=None):
    default_payloads = [
        "alert('XSS')",
        "<img src='x' onerror='alert(1)'>",
        "<img src='x' onerror='this.onerror=null;alert(1)'>",  # CSP bypass
        "<sCript>alert`1`</scrIpt>"  # WAF bypass
    ]
    encoded_default_payloads = [urllib.parse.quote_plus(payload) for payload in default_payloads]

    if payloads:
        # Do not encode user-provided payloads
        return payloads + encoded_default_payloads

    return default_payloads + encoded_default_payloads

# Asynchronous Scanner Engine with retry and extended timeout
async def scan(url, payloads, semaphore, stealth_mode=False, method='GET', data=None, timeout=DEFAULT_TIMEOUT):
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
                    url, payload, text = response
                    if is_false_positive(text, payload, response.headers):
                        print(colored(f"[+] False positive avoided for payload: {payload} on {url}", 'yellow'))
                    else:
                        print(colored(f"[!] Possible XSS detected with payload: {payload} on {url}", 'red'))
                else:
                    print(colored(f"[!] No response or failed for payload: {payload} on {url}", 'yellow'))

                if stealth_mode:
                    delay = random.uniform(0.5, 2.0)
                    await asyncio.sleep(delay)

async def scan_post(session, url, payload, data, timeout):
    for attempt in range(MAX_RETRIES):
        try:
            async with session.post(url, data={**data, 'input': payload}) as response:
                text = await response.text()
            return url, payload, text, response.headers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(colored(f"[!] POST request failed for payload: {payload} on {url}. Error: {e}", 'red'))
            return None

async def scan_get(session, url, payload, timeout):
    target_url = f"{url}?input={payload}"
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(target_url) as response:
                text = await response.text()
            return target_url, payload, text, response.headers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(colored(f"[!] GET request failed for payload: {payload} on {url}. Error: {e}", 'red'))
            return None

# Contextual False Positive Detection
def is_false_positive(text, payload, headers):
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
    safe_contexts = ['<textarea>', '<pre>', '<code>', '&lt;', '&gt;']
    for context in safe_contexts:
        if context in text:
            return True
    return False

def is_non_executable_context(text):
    return "<!--" in text or "-->" in text

def is_sanitized(text, payload):
    return urllib.parse.quote_plus(payload) in text or payload.replace('<', '&lt;').replace('>', '&gt;') in text

def has_strong_csp(headers):
    csp = headers.get('Content-Security-Policy', '')
    return "script-src 'self'" in csp or "script-src 'nonce-" in csp

# DOM-Based XSS Detection with Improved Dynamic Content Handling
def check_dom_xss(url, payloads, browser='chrome', chromedriver_path=None, geckodriver_path=None, edgedriver_path=None):
    options, service = get_browser_options(browser, chromedriver_path, geckodriver_path, edgedriver_path)

    driver = webdriver.Chrome(service=service, options=options) if browser == 'chrome' else (
             webdriver.Firefox(service=service, options=options) if browser == 'firefox' else 
             webdriver.Edge(service=service, options=options))

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
                    print(colored(f"[!] JavaScript error detected for payload: {payload} on {url}. Error: {log['message']}", 'red'))

            try:
                alert = driver.switch_to.alert
                print(colored(f"[!] DOM XSS detected with payload: {payload} on {url}", 'red'))
                alert.accept()
            except NoAlertPresentException:
                print(colored(f"[+] Safe for DOM payload: {payload} on {url}", 'green'))

        except TimeoutException:
            print(colored(f"[+] Safe for DOM payload: {payload} on {url}", 'green'))
        except Exception as e:
            print(colored(f"[!] Error detecting DOM XSS with payload: {payload} on {url}. Error: {e}", 'red'))

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
    tasks = [scan(f"{url}/{path}", payloads, semaphore, stealth_mode) for path in paths]
    await asyncio.gather(*tasks)

# Advanced Parameter Analysis
async def analyze_parameters(url, payloads, parameters, semaphore, stealth_mode=False, timeout=DEFAULT_TIMEOUT):
    async with semaphore:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            tasks = []
            for param in parameters:
                for payload in payloads:
                    tampered_data = {param: payload}
                    tasks.append(scan_param(session, url, tampered_data, payload, timeout))
            responses = await asyncio.gather(*tasks)

            for response in responses:
                if response:
                    url, param, payload, text = response
                    if is_false_positive(text, payload, response.headers):
                        print(colored(f"[+] False positive avoided for parameter tampering: {param}={payload} on {url}", 'yellow'))
                    else:
                        print(colored(f"[!] Possible XSS detected with parameter tampering: {param}={payload} on {url}", 'red'))
                else:
                    print(colored(f"[!] No response or failed for parameter tampering: {param}={payload} on {url}", 'yellow'))

                if stealth_mode:
                    delay = random.uniform(0.5, 2.0)
                    await asyncio.sleep(delay)

async def scan_param(session, url, data, payload, timeout):
    for attempt in range(MAX_RETRIES):
        try:
            async with session.get(url, params=data) as response:
                text = await response.text()
            return url, list(data.keys())[0], payload, text, response.headers
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < MAX_RETRIES - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            print(colored(f"[!] GET request with parameter failed for {list(data.keys())[0]}={payload} on {url}. Error: {e}", 'red'))
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
    print(colored(ascii_banner, 'cyan'))

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

    payloads = []
    if args.payloads:
        if os.path.isfile(args.payloads):
            # Read payloads from file
            with open(args.payloads, 'r') as file:
                payloads = [line.strip() for line in file]
        else:
            # Treat as a single payload
            payloads.append(args.payloads)

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

    payloads = generate_payloads(payloads)
    results = []

    semaphore = asyncio.Semaphore(concurrency)

    for url in urls:
        server_env = detect_server_environment(url)
        print(colored(f"[*] Detected server environment: {server_env}", 'yellow'))

        if mode in ['standard', 'stealth', 'all']:
            print(colored(f"[*] Starting {'stealth ' if mode == 'stealth' else ''}scan on {url}...", 'blue'))
            await scan(url, payloads, semaphore, stealth_mode=(mode == 'stealth'), method=method, data=data, timeout=timeout)

        if mode in ['dom', 'all']:
            print(colored(f"[*] Performing DOM-based XSS detection on {url} using {browser}...", 'blue'))
            check_dom_xss(url, payloads, browser, chromedriver_path, geckodriver_path, edgedriver_path)

        if mode in ['path', 'all'] and paths:
            print(colored(f"[*] Performing path-based analysis on {url}...", 'blue'))
            await path_based_analysis(url, payloads, paths, semaphore, stealth_mode=(mode == 'stealth'))

        if mode in ['params', 'all'] and params:
            print(colored(f"[*] Performing advanced parameter analysis on {url}...", 'blue'))
            await analyze_parameters(url, payloads, params, semaphore, stealth_mode=(mode == 'stealth'), timeout=timeout)

        if mode in ['extension', 'all']:
            print(colored(f"[*] Performing extension-based XSS detection on {url}...", 'blue'))
            extension_based_detection(url, payloads, browser)

    generate_report(results, output_file)
    print(colored(f"[*] Scan complete. Report saved to {output_file}.", 'green'))

if __name__ == '__main__':
    asyncio.run(main())
