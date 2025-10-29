import subprocess
import json
import streamlit as st
import os
import shutil

def get_site_list():
    try:
        result = subprocess.run(
            ["terminus", "site:list", "--format=json"],
            capture_output=True, text=True, check=True
        )
        sites = json.loads(result.stdout)
        return sorted([v["name"] for v in sites.values()])
    except Exception as e:
        st.warning(f"Could not fetch site list: {e}")
        return []

def get_env_list(site_name):
    try:
        result = subprocess.run(
            ["terminus", "env:list", site_name, "--format=json"],
            capture_output=True, text=True, check=True
        )
        envs = json.loads(result.stdout)
        return sorted(envs.keys())
    except Exception as e:
        st.warning(f"Could not fetch environment list: {e}")
        return []

def get_site_uuid(site_name):
    try:
        result = subprocess.run(
            ["terminus", "site:list", "--format=json"],
            capture_output=True, text=True, check=True
        )
        sites = json.loads(result.stdout)
        return next((k for k, v in sites.items() if v["name"].lower() == site_name.lower()), None)
    except Exception as e:
        st.error(f"Error getting site UUID: {str(e)}")
        return None

def collect_logs(site_uuid, env, site_name):
    logs_dir = os.path.expanduser(f"~/site-logs/{site_name}_{env}")
    if os.path.exists(logs_dir):
        shutil.rmtree(logs_dir)
    os.makedirs(logs_dir, exist_ok=True)

    app_servers = subprocess.check_output(
        ["dig", "+short", "-4", f"appserver.{env}.{site_uuid}.drush.in"]
    ).decode().splitlines()

    for server in filter(None, app_servers):
        server_dir = os.path.join(logs_dir, f"app_server_{server}")
        os.makedirs(server_dir, exist_ok=True)
        for log, log_subdir in [("nginx-access.log", "nginx"), ("error.log", "nginx"), ("php-error.log", "php")]:
            cmd = (
                f'echo "get logs/{log_subdir}/{log}" | '
                f'sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o Port=2222 '
                f'{env}.{site_uuid}@{server}'
            )
            yield f"Connecting to {server} for {log}..."
            process = subprocess.Popen(cmd, shell=True, cwd=server_dir, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                if "Warning: Permanently added" in line:
                    continue
                if "Connected to" in line or "Fetching" in line or "sftp>" in line or log in line or "100%" in line:
                    yield f"[{server}] {line.strip()}"
            process.wait()
            yield f"[{server}] Finished {log}"
