
import streamlit as st
import subprocess
import os
import shutil
import json
import base64
from datetime import datetime
from pathlib import Path
import pandas as pd

# ========= Optional ML (Secondary Feature) =========
MODEL_PATH = Path("leakhawk_model.pkl")
ENCODER_PATH = Path("label_encoder.pkl")
model = None
label_encoder = None
ml_ready = False
try:
    import joblib
    if MODEL_PATH.exists() and ENCODER_PATH.exists():
        model = joblib.load(MODEL_PATH)
        label_encoder = joblib.load(ENCODER_PATH)
        ml_ready = True
except Exception:
    ml_ready = False

# ========= Helpers =========
def clone_repo(repo_url, clone_dir="repo-temp"):
    if os.path.exists(clone_dir):
        shutil.rmtree(clone_dir)
    subprocess.run(
        ["git", "clone", repo_url, clone_dir],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return clone_dir

def run_trufflehog(repo_url):
    try:
        # Using basic trufflehog command without --no-update
        result = subprocess.run(
            ["trufflehog", repo_url],
            capture_output=True,
            text=True,
            check=False
        )
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        return out if out else (err if err else "No output from TruffleHog.")
    except FileNotFoundError:
        return "[✗] LeakHawk detection engine not installed or not in PATH."

def run_gitleaks(local_path):
    try:
        report_path = "gitleaks-report.json"
        if os.path.exists(report_path):
            os.remove(report_path)

        result = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", local_path,
                "--report-format", "json",
                "--report-path", report_path
            ],
            capture_output=True,
            text=True,
            check=False
        )

        # Prefer the file if present
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                data = f.read().strip()
                return json.loads(data) if data and data != "[]" else []
        # Fallback: try stdout
        if result.stdout:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return []
        return []
    except FileNotFoundError:
        return "[✗] LeakHawk analysis engine not installed or not in PATH."

def to_json_str(obj) -> str:
    try:
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception:
        return str(obj)

def download_text_button(text_data: str, filename: str, label: str):
    b64 = base64.b64encode(text_data.encode()).decode()
    href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">{label}</a>'
    st.markdown(href, unsafe_allow_html=True)

def download_bytes_button(bytes_data: bytes, filename: str, label: str, mime: str = "text/plain"):
    b64 = base64.b64encode(bytes_data).decode()
    href = f'<a href="data:{mime};base64,{b64}" download="{filename}">{label}</a>'
    st.markdown(href, unsafe_allow_html=True)

def extract_text_for_ml(finding: dict) -> str:
    """
    Build the text fed to the ML model from a LeakHawk finding.
    Prioritize matched content, then context.
    """
    parts = []
    for key in ("Match", "Secret", "Description"):
        v = finding.get(key)
        if v:
            parts.append(str(v))
    for k in ("RuleID", "File", "Message", "Commit"):
        v = finding.get(k)
        if v:
            parts.append(str(v))
    text = " | ".join(parts).strip()
    return text if text else str(finding)

def prob_to_risk(prob: float) -> int:
    if prob >= 0.90: return 10
    if prob >= 0.80: return 9
    if prob >= 0.70: return 8
    if prob >= 0.60: return 7
    if prob >= 0.50: return 6
    if prob >= 0.40: return 5
    if prob >= 0.30: return 4
    if prob >= 0.20: return 3
    if prob >= 0.10: return 2
    return 1

def flag_anomaly(rule_id: str, pred_label: str, confidence: float) -> bool:
    if confidence < 0.25:
        return True
    if rule_id and pred_label:
        rid = str(rule_id).lower()
        weird_pairs = [
            ("generic-api-key", "Payment Info"),
            ("high-entropy", "Payment Info"),
            ("password", "Payment Info"),
        ]
        if any(rid.startswith(p0) and pred_label == p1 for p0, p1 in weird_pairs):
            return True
    return False

def save_scan_artifacts(repo_url: str, trufflehog_out: str, gitleaks_list: list):
    """Save scan outputs locally as artifacts."""
    artifacts_dir = Path("scan_artifacts")
    artifacts_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_name = repo_url.replace("://", "_").replace("/", "_")
    # trufflehog
    truf_path = artifacts_dir / f"trufflehog_{safe_name}_{ts}.txt"
    truf_path.write_text(trufflehog_out, encoding="utf-8")
    # gitleaks json
    gl_json_path = artifacts_dir / f"gitleaks_{safe_name}_{ts}.json"
    gl_json_path.write_text(to_json_str(gitleaks_list), encoding="utf-8")
    # gitleaks compact csv
    compact_rows = []
    for f in gitleaks_list:
        compact_rows.append({
            "Rule": f.get("RuleID", "N/A"),
            "File": f.get("File", "N/A"),
            "Line": f.get("StartLine", ""),
            "Match_Secret": f.get("Match") or f.get("Secret") or "",
            "Commit": f.get("Commit", "N/A"),
            "Link": f.get("Link", "")
        })
    pd.DataFrame(compact_rows).to_csv(artifacts_dir / f"gitleaks_compact_{safe_name}_{ts}.csv", index=False)

# ========= Streamlit UI =========
st.set_page_config(
    page_title="LeakHawk Scanner",
    page_icon="🦅",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(
    """
    <style>
        .main { background: linear-gradient(135deg, #0f2027, #203a43, #2c5364); color: white; }
        h1, h2, h3, h4, h5, h6, p, .stMarkdown { color: white !important; }
        .stButton>button {
            background: #ff4b4b;
            color: white;
            border-radius: 10px;
            font-size: 16px;
            padding: 0.6em 1.2em;
            border: none;
        }
        .stButton>button:hover { background: #ff0000; color: white; }
        .result-box {
            background-color: rgba(255, 255, 255, 0.05);
            padding: 15px;
            border-radius: 10px;
            margin-top: 10px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .small-muted { opacity: 0.7; font-size: 0.9em; }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🦅 LeakHawk — GitHub Secret Scanner")
st.markdown("Paste a repository URL, run **LeakHawk** secret detection (primary). Use **ML classification** as an optional secondary step.")

# Sidebar
st.sidebar.header("Display Options")
show_raw_trufflehog = st.sidebar.checkbox("🔍 Show raw engine output", value=False)
show_full_gitleaks_json = st.sidebar.checkbox("📄 Show full JSON results", value=False)

st.sidebar.header("ML Options")
enable_ml = st.sidebar.checkbox("Enable ML post-processing", value=True if ml_ready else False)
st.sidebar.markdown(
    f"<span class='small-muted'>ML status: {'✅ Loaded' if ml_ready else '⚠️ Missing leakhawk_model.pkl / label_encoder.pkl'}</span>",
    unsafe_allow_html=True
)

st.sidebar.header("Offline ML on Existing JSON")
uploaded_scan_json = st.sidebar.file_uploader("Upload LeakHawk JSON results", type=["json"])

# Main input & actions
repo_url = st.text_input("Enter GitHub Repository URL", placeholder="https://github.com/user/repo")
col_run, col_clear = st.columns([1, 1])
run_clicked = col_run.button("🚀 Run Scan", use_container_width=True)
clear_clicked = col_clear.button("🧹 Clear Results", use_container_width=True)

if clear_clicked:
    st.rerun()

gitleaks_results = []

# ========= Primary: Run Tools =========
if run_clicked:
    if not repo_url.strip():
        st.error("Please enter a valid GitHub repository URL.")
    else:
        # --- Secret Detection ---
        with st.spinner("Running LeakHawk secret detection…"):
            trufflehog_output = run_trufflehog(repo_url)

        st.subheader("🔍 Secret Detection Results")
        if show_raw_trufflehog:
            with st.expander("📜 Raw Output (toggle)", expanded=False):
                st.markdown(f"<div class='result-box'>{trufflehog_output}</div>", unsafe_allow_html=True)
                download_text_button(trufflehog_output, "leakhawk_engine_output.txt", "📥 Download Engine Output")
        else:
            st.caption("Raw engine output is hidden (enable in sidebar).")
            download_text_button(trufflehog_output, "leakhawk_engine_output.txt", "📥 Download Engine Output")

        # --- Repository Analysis ---
        with st.spinner("Cloning repository and running LeakHawk analysis…"):
            try:
                local_path = clone_repo(repo_url)
                gitleaks_results = run_gitleaks(local_path)
            except subprocess.CalledProcessError:
                st.error("Failed to clone repository. Check URL or access.")
                gitleaks_results = []
            finally:
                try:
                    if os.path.exists("repo-temp"):
                        shutil.rmtree("repo-temp")
                except Exception:
                    pass

        st.subheader("🛡️ Repository Analysis")
        if isinstance(gitleaks_results, list) and gitleaks_results:
            st.success(f"Found **{len(gitleaks_results)}** potential findings.")
            compact_rows = []
            for f in gitleaks_results:
                compact_rows.append({
                    "Rule": f.get("RuleID", "N/A"),
                    "File": f.get("File", "N/A"),
                    "Line": f.get("StartLine", ""),
                    "Match/Secret": f.get("Match") or f.get("Secret") or "",
                    "Commit": f.get("Commit", "N/A"),
                    "Link": f.get("Link", "")
                })
            df_compact = pd.DataFrame(compact_rows)
            st.dataframe(df_compact, use_container_width=True)

            if show_full_gitleaks_json:
                with st.expander("📦 Full Gitleaks JSON", expanded=False):
                    json_str = to_json_str(gitleaks_results)
                    st.code(json_str, language="json")
                    download_text_button(json_str, "leakhawk_results.json", "📥 Download LeakHawk JSON")
            else:
                st.caption("Full Gitleaks JSON is hidden (enable in sidebar).")
                json_str = to_json_str(gitleaks_results)
                download_text_button(json_str, "leakhawk_results.json", "📥 Download LeakHawk JSON")

            # Save artifacts locally
            try:
                save_scan_artifacts(repo_url, trufflehog_output, gitleaks_results)
            except Exception:
                pass

            # Also offer compact CSV download directly
            csv_bytes = df_compact.to_csv(index=False).encode()
            download_bytes_button(csv_bytes, "leakhawk_compact.csv", "📥 Download LeakHawk Compact CSV", mime="text/csv")
        elif isinstance(gitleaks_results, str):
            st.error(gitleaks_results)
            gitleaks_results = []
        else:
            st.info("✅ No secrets found by LeakHawk.")
            gitleaks_results = []

        st.markdown(f"**Scan completed:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# ========= Secondary: ML Classification =========
def classify_findings(findings: list):
    if not findings:
        st.info("No findings to classify.")
        return

    # Build feature vectors for ML (4 features expected by the model)
    ml_data = []
    for f in findings:
        # Extract the 4 features the model expects:
        # 1. Data_Snippet (text content)
        data_snippet = extract_text_for_ml(f)
        
        # 2. Pattern_Matched (rule ID or pattern)
        pattern_matched = f.get("RuleID", "unknown")
        
        # 3. Risk_Score (numerical - derive from available data)
        # For now, use a default risk score based on rule type
        risk_score = 5  # Default medium risk
        
        # 4. Anomaly_Flag (Yes/No - derive from context)
        anomaly_flag = "No"  # Default to No
        
        ml_data.append({
            'Data_Snippet': data_snippet,
            'Pattern_Matched': pattern_matched,
            'Risk_Score': risk_score,
            'Anomaly_Flag': anomaly_flag
        })
    
    # Convert to DataFrame (format expected by the model)
    import pandas as pd
    X_pred = pd.DataFrame(ml_data)

    try:
        # Predict using the trained pipeline
        preds = model.predict(X_pred)
        proba = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_pred)
    except Exception as e:
        st.error(f"ML prediction failed: {e}")
        return

    try:
        preds_decoded = (
            label_encoder.inverse_transform(preds)
            if hasattr(label_encoder, "inverse_transform") else preds
        )
    except Exception:
        preds_decoded = preds

    confidences = []
    if proba is not None:
        for row in proba:
            best = float(row.max()) if len(row) else 0.0
            confidences.append(best)
    else:
        confidences = [0.5] * len(preds_decoded)

    ml_rows = []
    for finding, pred_label, conf in zip(findings, preds_decoded, confidences):
        rule = finding.get("RuleID", "N/A")
        file_ = finding.get("File", "N/A")
        secret = finding.get("Match") or finding.get("Secret") or ""
        commit = finding.get("Commit", "N/A")
        link = finding.get("Link", "")
        risk = prob_to_risk(conf)
        anomaly = flag_anomaly(rule, pred_label, conf)
        ml_rows.append({
            "Rule": rule,
            "Predicted_Type": pred_label,
            "Confidence": round(conf, 3),
            "Risk_Score(1-10)": risk,
            "Anomaly_Flag": anomaly,
            "File": file_,
            "Line": finding.get("StartLine", ""),
            "Match/Secret": secret,
            "Commit": commit,
            "Link": link
        })

    df_ml = pd.DataFrame(ml_rows)
    st.dataframe(
        df_ml.sort_values(by=["Risk_Score(1-10)", "Confidence"], ascending=[False, False]),
        use_container_width=True
    )
    csv_bytes = df_ml.to_csv(index=False).encode()
    download_bytes_button(csv_bytes, "leakhawk_ml_results.csv", "📥 Download ML Results (CSV)", mime="text/csv")

if enable_ml and ml_ready:
    st.subheader("🧠 ML Classification (Secondary Feature)")
    # Case 1: classify fresh scan results (if we just ran)
    if gitleaks_results:
        classify_findings(gitleaks_results)
    # Case 2: classify uploaded JSON (offline, no scan)
    elif uploaded_scan_json is not None:
        try:
            findings = json.load(uploaded_scan_json)
            if isinstance(findings, dict):
                # single-finding dict case
                findings = [findings]
            if not isinstance(findings, list):
                st.error("Uploaded JSON must be a list of Gitleaks findings.")
            else:
                classify_findings(findings)
        except Exception as e:
            st.error(f"Failed to parse uploaded JSON: {e}")
else:
    st.caption("ML post-processing is disabled or artifacts are missing.")
