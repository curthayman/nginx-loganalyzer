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

### Option 1: Local Development

1.  **Clone this repository:**

    ```bash
    git clone https://github.com/curthayman/nginx-loganalyzer.git
    cd nginx-loganalyzer
    ```

2.  **Set up virtual environment (recommended):**

    ```bash
    ./setup-dev.sh
    # Or manually:
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

3.  **Ensure you have Terminus installed and authenticated:**

    ```bash
    terminus auth:login
    ```

4.  **Run the Streamlit app:**
    ```bash
    streamlit run main.py
    ```

### Option 2: Docker Deployment

1.  **Pull from DockerHub:**

    ```bash
    docker pull curthayman/nginx-loganalyzer:latest
    ```

2.  **Run the container:**

    ```bash
    docker run -d \
      -p 8501:8501 \
      -v ~/.ssh:/home/appuser/.ssh:ro \
      -v ~/site-logs:/home/appuser/site-logs \
      --name nginx-loganalyzer \
      curthayman/nginx-loganalyzer:latest
    ```

3.  **Access the application:**
    Open http://localhost:8501 in your browser

### Option 3: Build from Source

1.  **Clone and build:**

    ```bash
    git clone https://github.com/curthayman/nginx-loganalyzer.git
    cd nginx-loganalyzer
    ./docker-build.sh v1.0.0
    ```

2.  **Run locally built image:**
    ```bash
    docker run -d -p 8501:8501 nginx-loganalyzer:latest
    ```

### Option 4: Docker Compose with Traefik (Production)

1.  **Copy files to your server:**

    ```bash
    git clone https://github.com/curthayman/nginx-loganalyzer.git
    cd nginx-loganalyzer
    ```

2.  **Configure environment:**

    ```bash
    cp .env.example .env
    nano .env  # Set HOSTNAME to your domain
    ```

3.  **Run automated setup:**

    ```bash
    ./docker-deploy.sh
    ```

    Or manually:

    ```bash
    docker network create proxy  # If not exists
    docker compose pull
    docker compose up -d
    ```

4.  **Access via your domain:**
    Open https://your-hostname.com

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed production deployment guide.

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

## CI/CD and Docker

This project includes automated CI/CD workflows for building and publishing Docker images:

- **DockerHub**: Automatically publishes to DockerHub on tagged releases
- **AWS ECR**: Supports publishing to private AWS ECR repositories
- **Multi-platform**: Builds for both `linux/amd64` and `linux/arm64`

See [.github/workflows/README.md](.github/workflows/README.md) for setup instructions.

### Available Docker Images

- **DockerHub**: `curthayman/nginx-loganalyzer:latest`
- **AWS ECR**: Configure your own private registry

### Building Locally

```bash
# Quick build
./docker-build.sh

# Build with version tag
./docker-build.sh v1.0.0

# Test the build
./docker-test.sh
```

## Development

### Project Structure

```
.
├── main.py              # Main Streamlit application
├── log_parser.py        # Log parsing functions
├── analysis.py          # Security analysis functions
├── terminus.py          # Pantheon/Terminus integration
├── ui.py               # External tool integration (GoAccess)
├── requirements.txt     # Python dependencies
├── Dockerfile          # Container definition
├── docker-compose.yml  # Docker Compose configuration
└── .github/
    └── workflows/      # GitHub Actions CI/CD
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Submit a pull request
