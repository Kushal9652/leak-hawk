import streamlit as st
import subprocess
import os
import shutil
import json
from datetime import datetime
import base64

# =============== UTILITY FUNCTIONS ===============

def clone_repo(repo_url, clone_dir="repo-temp"):
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
    subprocess.run(["git", "clone", repo_url, clone_dir], check=True)
    return clone_dir

def run_trufflehog(repo_url):
    try:
        result = subprocess.run(["trufflehog", repo_url], capture_output=True, text=True)
        return result.stdout or "No output from TruffleHog."
    except FileNotFoundError:
        return "[✗] TruffleHog not installed."

def run_gitleaks(local_path):
    try:
        subprocess.run(
            ["gitleaks", "detect", "--source", local_path, "--report-format", "json", "--report-path", "gitleaks-report.json"],
            capture_output=True, text=True
        )
        if os.path.exists("gitleaks-report.json"):
            with open("gitleaks-report.json", "r") as f:
                data = f.read()
                return json.loads(data) if data.strip() else []
        return []
    except FileNotFoundError:
        return "[✗] Gitleaks not installed."

def download_button(data, filename, label):
    b64 = base64.b64encode(data.encode()).decode()
    href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">{label}</a>'
    st.markdown(href, unsafe_allow_html=True)

# =============== STREAMLIT UI ===============

st.set_page_config(
    page_title="LeakHawk Scanner",
    page_icon="🦅",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
        .main { background: linear-gradient(135deg, #0f2027, #203a43, #2c5364); color: white; }
        h1, h2, h3, h4, h5, h6, p, .stMarkdown { color: white !important; }
        .stButton>button { background: #ff4b4b; color: white; border-radius: 10px; font-size: 16px; padding: 0.6em 1.2em; border: none; }
        .stButton>button:hover { background: #ff0000; color: white; }
        .result-box { background-color: rgba(255, 255, 255, 0.05); padding: 15px; border-radius: 10px; margin-top: 10px; font-family: monospace; }
    </style>
""", unsafe_allow_html=True)

st.title("🦅 LeakHawk – GitHub Secret Scanner")
st.markdown("Detect secrets & sensitive data in public/private repositories using **TruffleHog** & **Gitleaks**.")

repo_url = st.text_input("Enter GitHub Repository URL", placeholder="https://github.com/user/repo")

if st.button("🚀 Run Scan", use_container_width=True):
    if not repo_url.strip():
        st.error("Please enter a valid GitHub repository URL.")
    else:
        with st.spinner("Running  scan..."):
            trufflehog_output = run_trufflehog(repo_url)

        st.subheader("🔍  Results")
        with st.expander("📜 View Raw Output"):
            st.markdown(f"<div class='result-box'>{trufflehog_output}</div>", unsafe_allow_html=True)
            download_button(trufflehog_output, "trufflehog_output.txt", "📥 Download TruffleHog Output")

        with st.spinner("Cloning repository and running Gitleaks..."):
            try:
                local_path = clone_repo(repo_url)
                gitleaks_results = run_gitleaks(local_path)
                shutil.rmtree(local_path)
            except subprocess.CalledProcessError:
                st.error("Failed to clone repository.")
                gitleaks_results = []

        st.subheader("🛡️ Gitleaks Results")
        if isinstance(gitleaks_results, list) and gitleaks_results:
            st.write(f"Found **{len(gitleaks_results)}** potential leaks:")
            st.dataframe([{
                "Rule": f.get("RuleID", "N/A"),
                "File": f.get("File", "N/A"),
                "Secret": f.get("Secret", "N/A"),
                "Commit": f.get("Commit", "N/A")
            } for f in gitleaks_results])
            
            with st.expander("📜 View Full JSON Output"):
                json_str = json.dumps(gitleaks_results, indent=2)
                st.code(json_str, language="json")
                download_button(json_str, "gitleaks_results.json", "📥 Download Gitleaks JSON")
        elif isinstance(gitleaks_results, str):
            st.error(gitleaks_results)
        else:
            st.success("✅ No leaks found by Gitleaks.")

        st.markdown(f"**Scan completed:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
