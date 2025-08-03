import os
import subprocess
from pathlib import Path

# Step 1: Clone the repository from GitHub
def clone_repo(repo_url, destination):
    if os.path.exists(destination):
        print(f"[!] Folder '{destination}' already exists. Skipping clone.")
        return
    subprocess.run(['git', 'clone', repo_url, destination], check=True)
    print(f"[✓] Repository cloned to: {destination}")

# Step 2: Get a list of all commit hashes in the repo
def get_commit_list(repo_dir):
    os.chdir(repo_dir)
    result = subprocess.run(['git', 'log', '--pretty=format:%H'], capture_output=True, text=True)
    return result.stdout.strip().split('\n')

# Step 3: Scan all commits and inspect important files
def scan_all_commits(repo_dir):
    initial_dir = os.getcwd()
    os.chdir(repo_dir)
    
    commits = get_commit_list(repo_dir)
    scanned_files = set()
    
    for commit in commits:
        subprocess.run(['git', 'checkout', commit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"\n[🔍] Scanning commit: {commit}")
        
        for file in Path('.').rglob('*'):
            if file.is_file() and file.suffix in {'.js', '.py', '.ts', '.env', '.go'}:
                full_path = f"{commit}:{file}"
                if full_path not in scanned_files:
                    print(f"    → Found: {file}")
                    # 👇 You can pass the file to an ML model here
                    scanned_files.add(full_path)

    # Checkout back to main branch
    subprocess.run(['git', 'checkout', 'main'], stdout=subprocess.DEVNULL)
    os.chdir(initial_dir)
    print("\n[✓] Scanning complete.")

# Step 4: Main Function
if __name__ == "__main__":
    repo_url = input("Enter GitHub Repo URL: ").strip()
    destination_folder = "repo-temp"

    try:
        clone_repo(repo_url, destination_folder)
        scan_all_commits(destination_folder)
    except Exception as e:
        print(f"[✗] Error: {e}")

