# Nginx Log Analyzer

**A powerful, interactive Streamlit dashboard for analyzing Nginx access logs and PHP error logs, with features for security, performance, and operational insight.**

**Supports Pantheon/Terminus integration for site and environment selection.**

## Features

- **Site & Environment Dropdowns:** Select Pantheon sites and environments dynamically.
- **Log Collection:** Download logs from all app servers for the selected site/environment.
- **Log Clearing:** Clear cached logs to start a fresh analysis.
- **Traffic Overview:** Visualize total requests, unique IPs, error rates, and request trends.
- **Request Analysis:** See top paths, status codes, user agents, visitor IPs/hostnames, and top referrers.
- **Error Analysis:** Drill into 4xx/5xx errors and their sources.
- **Security Tab:** Detect suspicious activity (high error rates, 404s, brute-force attempts).
- **File Types Tab:** Analyze top requested file extensions and files, with charts.
- **Bot & Crawler Detection:** Identify bot and crawler activity, including request counts, paths, and error rates.
- **Advanced Security Analysis:**
    - Detects potential brute force attacks.
    - Detects potential SQL injection attempts.
    - Detects potential XSS attacks.
    - **AbuseIPDB Integration:** Check IPs with high error rates against the AbuseIPDB database.
- **PHP Error Log Analysis:**
    - View and filter PHP errors by severity (Fatal Error, Warning, Info/Notice).
    - Dropdown filter for error type in the PHP Errors tab.
    - Download PHP error logs as CSV.
- **Downloadable Reports:**
    - Export all log data as CSV.
    - Generate detailed HTML reports using `goaccess`.
- **Standalone Nginx Dashboard:**
    - A separate dashboard to quickly analyze a single Nginx log file.
    - Run with `streamlit run main.py`.

## Requirements

- Python 3.8+
- [Terminus CLI](https://docs.pantheon.io/terminus/install) (for Pantheon integration)
- `dig` (for DNS lookups)
- SFTP access to Pantheon app servers
- [goaccess](https://goaccess.io/download) (for generating HTML reports)

## Python packages

See `requirements.txt`:

```
streamlit
pandas
plotly
requests
```

Install with:

```
pip install -r requirements.txt
```

## Usage

1.  **Clone this repository and install requirements:**
    ```
    git clone https://github.com/curthayman/nginx-loganalyzer.git
    cd nginx-loganalyzer
    pip install -r requirements.txt
    ```
2.  **Ensure you have Terminus installed and authenticated:**
    ```
    terminus auth:login
    ```
3.  **Run the Streamlit app:**
    ```
    streamlit run main.py
    ```

## In the sidebar:

- Select a site and environment from the dropdowns.
- Click **"Collect Logs"** to fetch and analyze logs.
- Click **"Clear Logs"** to remove all downloaded logs.
- Click **"Generate Report"** to create a `goaccess` HTML report.

## Explore the tabs:

- **Overview:** Traffic summary and trends.
- **Requests:** Top paths, status codes, user agents, IPs, referrers.
- **Errors:** All 4xx/5xx errors.
- **Security:** Suspicious activity detection.
- **File Types:** Top file extensions/files, with charts.
- **Bot & Crawler Detection:** Bot and crawler activity breakdown.
- **Advanced Security:** Brute force, SQLi, XSS detection, and AbuseIPDB checks.
- **PHP Errors:**
    - View all PHP errors from all app servers.
    - Filter by Fatal Error, Warning, or Info (Notice) using the dropdown.
    - Download filtered PHP error logs as CSV.

## Customization

- **Log Format:** The parser is tailored for Pantheon Nginx logs with GoAccess-style formatting. If your log format differs, adjust the `parse_nginx_log` function.
- **PHP Error Log Format:** The PHP error parser supports standard PHP error log lines. For custom formats, adjust the `parse_php_error_log` function.
- **Hostname Resolution:** The dashboard attempts to resolve IPs to hostnames; this may be slow for many IPs.

## Troubleshooting

- If site or environment dropdowns do not populate, ensure Terminus is installed, authenticated, and in your `PATH`.
- If you see "No valid access logs found," check that logs were collected and are in the expected format.
- If PHP errors do not appear, ensure the `php-error.log` files are present in each app server directory.
- For custom log formats, update the parser as needed.
- If you have questions or want to contribute, open an issue or pull request.
