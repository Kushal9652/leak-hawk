import subprocess
import os
import shutil

def clone_repo(repo_url, clone_dir="repo-temp"):
    print("[*] Cloning repository...")
    try:
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir)

        subprocess.run(
            ["git", "clone", repo_url, clone_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"[✓] Repository cloned to: {clone_dir}")
        return clone_dir
    except subprocess.CalledProcessError:
        print("[✗] Failed to clone repository.")
        return None

def run_trufflehog(repo_url):
    print("[🔍] Running TruffleHog directly on GitHub URL...")
    try:
        result = subprocess.run(
            ["trufflehog", repo_url],
            capture_output=True,
            text=True,
            check=True
        )
        print("[✓] TruffleHog scan completed successfully.")
        print("===== 🚨 TruffleHog Results 🚨 =====")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        # Removed failure message as requested
        print("STDOUT:\n", e.stdout)
        print("STDERR:\n", e.stderr)
    except FileNotFoundError:
        print("[✗] TruffleHog is not installed or not in PATH.")

def run_gitleaks(local_path):
    print("[🔍] Running Gitleaks on local repo...")
    try:
        result = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", local_path,
                "--report-format", "json",
                "--report-path", "gitleaks-report.json"
            ],
            capture_output=True,
            text=True,
            check=False
        )

        print("[✓] Gitleaks scan completed.")

        if os.path.exists("gitleaks-report.json"):
            with open("gitleaks-report.json", "r") as f:
                data = f.read()
                if data.strip() and data.strip() != "[]":
                    print("===== 🚨 Gitleaks Results 🚨 =====")
                    print(data)
                else:
                    print("No leaks found in JSON report.")
        else:
            print("Report file not found.")

        if result.stderr:
            print("STDERR:\n", result.stderr)
    except FileNotFoundError:
        print("[✗] Gitleaks is not installed or not in PATH.")


def main():
    repo_url = input("Enter GitHub Repo URL: ").strip()
    run_trufflehog(repo_url)

    local_path = clone_repo(repo_url)
    if local_path:
        run_gitleaks(local_path)
        try:
            shutil.rmtree(local_path)
            print(f"[🧹] Removed temporary directory: {local_path}")
        except Exception as e:
            print(f"[⚠️] Failed to remove temporary directory: {e}")

if __name__ == "__main__":
    main()
