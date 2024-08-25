# centuary-xss

`centuary-xss` is an advanced cross-site scripting (XSS) detection and exploitation tool designed for security professionals and penetration testers. The tool incorporates various scanning techniques, including DOM-based, path-based, and parameter-based analyses, and supports both GET and POST methods. It is capable of avoiding false positives through contextual analysis and can generate detailed reports in multiple formats.

## Features

- **Payload Generation:** Generates a variety of XSS payloads, including those designed to bypass CSPs and WAFs.
- **Asynchronous Scanning:** Utilizes asyncio and aiohttp for high-performance, non-blocking scans.
- **Stealth Mode:** Introduces random delays to avoid detection during testing.
- **DOM-Based XSS Detection:** Uses Selenium to detect XSS vulnerabilities in dynamic content.
- **Path and Parameter Analysis:** Analyzes URL paths and parameters for potential XSS vulnerabilities.
- **False Positive Avoidance:** Contextual analysis to reduce false positives in detection.
- **Multi-Browser Support:** Supports Chrome, Firefox, and Edge for DOM-based scanning.
- **Customizable Timeouts and Retries:** Configurable options for handling slow or unreliable servers.

## Requirements

- Python 3.7+
- aiohttp
- selenium
- urllib
- pyfiglet
- termcolor

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Itachi-don/centuary-xss.git
    cd centuary-xss
    ```

2. **Install the dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3. **Ensure you have the appropriate browser drivers installed:**
   - ChromeDriver for Chrome
   - GeckoDriver for Firefox
   - EdgeDriver for Edge

## Usage

### Basic Usage

```bash
python centuary-xss.py -u https://example.com -m standard
```

### Options

- `-u, --url`: Target URL to scan.
- `-f, --file`: File containing a list of URLs to scan.
- `-m, --mode`: Scan mode (`standard`, `stealth`, `dom`, `path`, `extension`, `params`, `all`).
- `-o, --output`: Output report file name (default: `xss_report.json`).
- `-p, --payloads`: Custom payloads file or single payload.
- `-d, --delay`: Delay between requests in seconds (default: 0.5s).
- `--method`: HTTP method for requests (`GET` or `POST`).
- `--data`: Data for POST requests in JSON format.
- `--paths`: Paths for path-based analysis.
- `--params`: Parameters for advanced parameter analysis.
- `--browser`: Browser for DOM XSS detection (`chrome`, `firefox`, `edge`).
- `--timeout`: Timeout for requests in seconds (default: 10s).
- `--concurrency`: Limit of concurrent requests (default: 5).
- `--chromedriver`: Path to ChromeDriver.
- `--geckodriver`: Path to GeckoDriver.
- `--edgedriver`: Path to EdgeDriver.

### Example Commands

#### Stealth Mode Scan

```bash
python centuary-xss.py -u https://example.com -m stealth
```

#### DOM-Based XSS Detection

```bash
python centuary-xss.py -u https://example.com -m dom --browser firefox --geckodriver /path/to/geckodriver
```

#### Advanced Parameter Analysis

```bash
python centuary-xss.py -u https://example.com -m params --params id name --data '{"id": "1"}'
```

## Reporting

The tool generates reports in JSON format by default. You can specify a different output file format or name using the `-o` option.

```bash
python centuary-xss.py -u https://example.com -o custom_report.txt
```

## Contribution

Contributions are welcome! Please fork this repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
```

This `README.md` file provides a clear overview of your tool, its features, usage, and options. It also includes installation instructions and examples to help users get started quickly.
