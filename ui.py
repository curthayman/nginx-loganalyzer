import streamlit as st
import subprocess

def generate_goaccess_report(log_path, output_path):
    try:
        cmd = f"goaccess {log_path} > {output_path}"
        subprocess.run(cmd, shell=True, check=True)
        st.success(f"Report generated successfully at {output_path}")
    except subprocess.CalledProcessError as e:
        st.error(f"Failed to generate report: {str(e)}")
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
