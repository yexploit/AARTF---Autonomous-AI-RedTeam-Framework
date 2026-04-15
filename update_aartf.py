#!/usr/bin/env python3
"""
Cross-platform updater for AARTF.

Usage:
  python update_aartf.py
  python update_aartf.py --skip-deps
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def run_command(command, cwd):
    print(f"[>] {' '.join(command)}")
    process = subprocess.run(command, cwd=str(cwd))
    if process.returncode != 0:
        raise RuntimeError(f"Command failed ({process.returncode}): {' '.join(command)}")


def ensure_git_available():
    if shutil.which("git") is None:
        raise RuntimeError("Git is not installed or not available in PATH.")


def ensure_git_repo(repo_dir):
    git_dir = repo_dir / ".git"
    if not git_dir.exists():
        raise RuntimeError(f"{repo_dir} is not a git repository.")


def update_repository(repo_dir, branch):
    run_command(["git", "fetch", "origin"], cwd=repo_dir)
    run_command(["git", "pull", "--ff-only", "origin", branch], cwd=repo_dir)


def update_dependencies(repo_dir):
    requirements = repo_dir / "requirements.txt"
    if not requirements.exists():
        print("[i] requirements.txt not found. Skipping dependency update.")
        return
    run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=repo_dir)


def parse_args():
    parser = argparse.ArgumentParser(description="Update AARTF from GitHub (Windows/Linux/macOS).")
    parser.add_argument("--branch", default="main", help="Git branch to pull from (default: main)")
    parser.add_argument("--skip-deps", action="store_true", help="Skip pip install -r requirements.txt")
    return parser.parse_args()


def main():
    args = parse_args()
    repo_dir = Path(__file__).resolve().parent

    try:
        ensure_git_available()
        ensure_git_repo(repo_dir)
        print("[*] Updating repository...")
        update_repository(repo_dir, args.branch)

        if args.skip_deps:
            print("[i] Skipping dependency update (--skip-deps).")
        else:
            print("[*] Updating Python dependencies...")
            update_dependencies(repo_dir)

        print("[+] Update completed successfully.")
    except Exception as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
