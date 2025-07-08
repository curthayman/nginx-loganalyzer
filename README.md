# Nginx Log Analyzer
** A powerful, interactive Streamlit dashboard for analyzing Nginx access logs and PHP error logs, with features for security, performance, and operational insight.

** Supports Pantheon/Terminus integration for site and environment selection.

## Features
- **Site & Environment Dropdowns:** Select Pantheon sites and environments dynamically.
- **Log Collection:** Download logs from all app servers for the selected site/environment.
- **Traffic Overview:** Visualize total requests, unique IPs, error rates, and request trends.
- **Request Analysis:** See top paths, status codes, user agents, visitor IPs/hostnames, and top referrers.
- **Error Analysis:** Drill into 4xx/5xx errors and their sources.
- **Security Tab:** Detect suspicious activity (high error rates, 404s, brute-force attempts).
- **File Types Tab:** Analyze top requested file extensions and files, with charts.
- **Bot & Crawler Detection:** Identify bot and crawler activity, including request counts, paths, and error rates.
- **Advanced Security Analysis:** Detect potential brute force attacks, SQL injection attempts, and XSS attacks.
## **PHP Error Log Analysis:**
- View and filter PHP errors by severity (Fatal Error, Warning, Info/Notice).
- Dropdown filter for error type in the PHP Errors tab.
- Download PHP error logs as CSV.
- **Downloadable Reports:** Export all log data as CSV or generate detailed HTML reports using goaccess.
- **User-Friendly Labels:** Root requests and direct referrers are clearly labeled.
- **No Date Range Filter:** The dashboard always analyzes the full 24-hour log window for simplicity.

## Requirements
Python 3.8+
Terminus CLI (for Pantheon integration)
dig (for DNS lookups)
SFTP access to Pantheon app servers
goaccess (for generating HTML reports)


## Python packages
See requirements.txt:
```
streamlit
pandas
plotly
```
## Install with:

```
pip install -r requirements.txt
```
## Usage
Clone this repository and install requirements:
```
git clone https://github.com/curthayman/pantheon-loganalyzer.git
cd pantheon-loganalyzer
pip install -r requirements.txt
```
Ensure you have Terminus installed and authenticated:
```
terminus auth:login
```
Run the Streamlit app:
```
streamlit run nginx_dashboard.py
```
## In the sidebar:
- Select a site and environment from the dropdowns.
- Click "Collect Logs" to fetch and analyze logs.
  
## Explore the tabs:
- **Overview:** Traffic summary and trends.
- **Requests:** Top paths, status codes, user agents, IPs, referrers.
- **Errors:** All 4xx/5xx errors.
- **Security:** Suspicious activity detection.
- **File Types:** Top file extensions/files, with charts.
- **Bot & Crawler Detection:** Bot and crawler activity breakdown.
- **Advanced Security:** Brute force, SQLi, and XSS detection.
## PHP Errors:
- View all PHP errors from all app servers.
- Filter by Fatal Error, Warning, or Info (Notice) using the dropdown.
- Download filtered PHP error logs as CSV.
- Download CSV: Use the download button in the Overview tab to export all log data.


## Customization
- **Log Format:** The parser is tailored for Pantheon Nginx logs with GoAccess-style formatting. If your log format differs, adjust the parse_nginx_log function.
- **PHP Error Log Format:** The PHP error parser supports standard PHP error log lines. For custom formats, adjust the parse_php_error_log function.
- **Hostname Resolution:** The dashboard attempts to resolve IPs to hostnames; this may be slow for many IPs.
## Troubleshooting
- If site or environment dropdowns do not populate, ensure Terminus is installed, authenticated, and in your PATH.
- If you see "No valid access logs found," check that logs were collected and are in the expected format.
- If PHP errors do not appear, ensure the php-error.log files are present in each app server directory.
- For custom log formats, update the parser as needed.
- If you have questions or want to contribute, open an issue or pull request.
