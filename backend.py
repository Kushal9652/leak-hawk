from flask import Flask, request, jsonify
import json
import os
import subprocess

app = Flask(__name__)

RESULTS_FILE = "latest_scan.json"  # Your scan script should update this

@app.route("/scan", methods=["POST"])
def scan_repo():
    data = request.json
    repo_url = data.get("repo_url")

    if not repo_url:
        return jsonify({"status": "error", "message": "Missing repo_url"}), 400

    try:
        # Run scan.py in background
        subprocess.Popen(
            ["python3", "scan.py", repo_url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "started", "message": f"Scan started for {repo_url}"}), 200


@app.route("/results", methods=["GET"])
def get_results():
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, "r") as f:
            results = json.load(f)
    else:
        results = {"status": "error", "message": "No scan results available."}
    return jsonify(results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
