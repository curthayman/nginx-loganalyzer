# Nginx Log Analyzer - AI Coding Agent Instructions

## Project Overview

A Streamlit dashboard for analyzing Nginx access logs and PHP error logs from Pantheon hosting environments. Integrates with Terminus CLI to fetch logs from multiple app servers and provides security, performance, and operational insights.

## Architecture & Data Flow

### Core Module Responsibilities

- **`main.py`**: Streamlit UI orchestration, tab management, session state handling
- **`log_parser.py`**: Raw log parsing with regex (Nginx + PHP error logs) → pandas DataFrames
- **`analysis.py`**: Security detection algorithms (brute force, SQL injection, XSS, AbuseIPDB API)
- **`terminus.py`**: Pantheon API integration via subprocess calls to `terminus` CLI
- **`ui.py`**: External tool integration (GoAccess HTML report generation)

### Critical Data Flow Pattern

1. User selects site/env → `terminus.py` fetches app server IPs via `dig` DNS lookup
2. `collect_logs()` uses SFTP over port 2222 to download logs from each app server
3. Logs stored in `~/site-logs/{site_name}_{env}/app_server_{ip}/` structure
4. Parser functions read all server logs → concat into single DataFrame
5. DataFrame enriched with computed fields (`extension`, `is_bot`, etc.) for analysis tabs

### Session State Management

**Critical**: Site/environment selections stored in `st.session_state['site_name']` and `st.session_state['env']`. These drive `logs_dir` path construction. Caching pattern: `env_list_{site_name}` keys prevent redundant Terminus API calls.

## Key Conventions & Patterns

### Log Parsing Specifics

- **Nginx format**: Pantheon-specific with 4 quoted fields: `[request] [referrer] [user_agent] [proxy_chain]`
- **Real IP extraction**: Always use first IP from `proxy_chain` field (behind load balancer)
- **IPv4/IPv6 validation**: Regex `^\d{1,3}(\.\d{1,3}){3}$|^[a-fA-F0-9:]+$` filters valid IPs
- **PHP error types**: Map "fatal error" → "Fatal Error (Critical)", "notice" → "Info" for UI consistency

### Caching Strategy

Use `@st.cache_data` decorator on parsing functions (`parse_nginx_log`, `parse_php_error_log`) to prevent re-parsing on every Streamlit rerun. **Never** cache functions with side effects (file writes, subprocess calls).

### Extension Detection Pattern

```python
def get_extension(path):
    path = path.split('?', 1)[0]  # Strip query params first
    if '.' in path.split('/')[-1]:
        return path.split('.')[-1].lower()
    return ""
```

Always strip query strings before extracting extensions to avoid false positives.

## Development Workflows

### Running the Application

**Local Development:**

```bash
# With virtual environment
source venv/bin/activate
streamlit run main.py

# Or use setup script
./setup-dev.sh
```

**Docker:**

```bash
# Build and test
./docker-build.sh v1.0.0
./docker-test.sh

# Production with Traefik
./docker-deploy.sh  # Automated setup
# Or: docker compose up -d
```

Access at `http://localhost:8501`. Sidebar controls drive all state changes.

**Docker Compose Notes:**

- Uses external `proxy` network for Traefik integration
- Traefik labels auto-configure HTTPS with Let's Encrypt
- Volumes: `site-logs/` for persistence, `~/.ssh` for SFTP keys
- Configure `HOSTNAME` in `.env` for domain routing
- See `DEPLOYMENT.md` for full production setup guide

### Testing Log Collection Locally

Requires:

1. Authenticated Terminus CLI: `terminus auth:login`
2. SFTP key in `~/.ssh/` for Pantheon servers
3. `dig` command installed (DNS lookups)

**Manual log collection test**:

```bash
terminus env:list <site-name>  # Verify access
dig +short -4 appserver.dev.<site-uuid>.drush.in  # Get server IPs
```

### Adding New Analysis Tabs

1. Add tab to `st.tabs()` list in `main.py` (line ~92)
2. Process DataFrame under `with tab{N}:` context manager
3. Follow existing pattern: header → metrics/dataframe → optional chart → download button

### Security Detection Additions

Place new detection functions in `analysis.py`. Return filtered DataFrame with same schema as input. Example pattern:

```python
def detect_new_threat(df):
    threat_condition = df['path'].str.contains('pattern', case=False)
    return df[threat_condition]
```

## External Dependencies

### Terminus CLI Integration

All `terminus.py` functions use `subprocess.run()` with `--format=json` flag. Error handling pattern:

```python
try:
    result = subprocess.run([...], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)
except Exception as e:
    st.warning(f"Error message: {e}")
    return default_value
```

### SFTP Collection Protocol

Port 2222, StrictHostKeyChecking disabled for automated runs. Command structure:

```bash
echo "get logs/{subdir}/{filename}" | sftp -o Port=2222 {env}.{uuid}@{server}
```

Yields progress lines for streaming UI updates.

### GoAccess Report Generation

Requires `goaccess` installed on system. Combines all server logs into single file before processing:

```python
combined_log_path = os.path.join(logs_dir, "combined_nginx_access.log")
# Write all nginx-access.log files to combined file
generate_goaccess_report(combined_log_path, report_path)
```

## Common Gotchas

1. **Empty DataFrame checks**: Always test `if not df.empty:` before operations to prevent crashes
2. **Time parsing failures**: Use `errors='coerce'` with `pd.to_datetime()` - some log lines have malformed timestamps
3. **Status code types**: Convert to numeric with `pd.to_numeric(df['status'], errors='coerce')` for comparison operations
4. **Hostname resolution**: `socket.gethostbyaddr()` can be slow (DNS timeouts). Consider caching or async for production
5. **Log directory paths**: Use `os.path.expanduser()` for tilde expansion in home directory paths

## Project-Specific Patterns

### Error Rate Calculation

```python
error_rate = len(df[df['status'] >= 400]) / len(df)  # 4xx + 5xx
```

Standard threshold: 50% error rate with >10 requests considered suspicious.

### Bot Detection Keywords

Maintained list in `main.py` tab6 (~280): includes common bots (googlebot, bingbot) and security scanners. Use `str.contains('|'.join(keywords))` for efficient detection.

### AbuseIPDB Integration

Optional API key in session state. Check high-error IPs against abuse database. Rate limit: ~1 request/second. Always wrap in try/except and display errors to user.

## File Organization

```
~/site-logs/{site_name}_{env}/
├── app_server_{ip1}/
│   ├── nginx-access.log
│   ├── error.log
│   └── php-error.log
├── app_server_{ip2}/
│   └── ...
├── combined_nginx_access.log  # Generated for GoAccess
└── report.html                # GoAccess output
```
