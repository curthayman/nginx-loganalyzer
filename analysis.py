import pandas as pd
import requests
import streamlit as st

def detect_brute_force(df):
    brute_force_df = df[df['path'].str.contains('login', case=False) & df['status'].isin([401, 403])]
    brute_force_group = brute_force_df.groupby(['ip', 'path']).size().reset_index(name='count')
    return brute_force_group[brute_force_group['count'] > 5]

def detect_sql_injection(df):
    sql_keywords = ['SELECT', 'UNION', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'WHERE', 'OR', 'AND']
    df['potential_sql_injection'] = df['path'].str.contains('|'.join(sql_keywords), case=False, na=False) | \
                                    df['referrer'].str.contains('|'.join(sql_keywords), case=False, na=False)
    return df[df['potential_sql_injection']]

def detect_xss(df):
    xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=']
    df['potential_xss'] = df['path'].str.contains('|'.join(xss_patterns), case=False, na=False) | \
                          df['referrer'].str.contains('|'.join(xss_patterns), case=False, na=False)
    return df[df['potential_xss']]

def check_abuseipdb(ip, api_key):
    try:
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['data']
        else:
            st.error(f"Error checking IP {ip}: {response.text}")
            return None
    except Exception as e:
        st.error(f"An error occurred while checking IP {ip}: {str(e)}")
        return None
