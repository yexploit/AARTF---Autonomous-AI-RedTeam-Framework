# AARTF (AI-Driven Autonomous Security Workflow)

[![CI](https://github.com/yexploit/AARTF---Autonomous-AI-RedTeam-Framework/actions/workflows/ci.yml/badge.svg)](https://github.com/yexploit/AARTF---Autonomous-AI-RedTeam-Framework/actions/workflows/ci.yml)

AARTF is a Python-based cybersecurity workflow project with both CLI and GUI modes.  
It orchestrates reconnaissance, vulnerability correlation, prioritization, and report generation with a modular architecture.

> This project is intended for authorized labs and controlled environments (HTB, THM, private labs).

## Features

- Dual interface:
  - CLI (`aartf.py`)
  - GUI dashboard (`aartf.py --gui`)
- Modular execution engine across phases
- Multi-target/subnet mode with worker threads
- Report generation:
  - Text report
  - PDF report
  - Attack graph image
  - Timeline animation (`.mp4` / `.gif` fallback)
- Defensive runtime hardening:
  - Graceful handling for missing `nmap`, `msfrpcd`, or `pymetasploit3`
  - Cleaner error messages and non-crashing fallbacks

## Project Structure

```text
AARTF/
  aartf.py
  gui_dashboard.py
  core/
  modules/
  ai/
  reports/
```

## Requirements

- Python 3.10+ (recommended: 3.11)
- OS: Windows/Linux/macOS
- Optional external tools:
  - `nmap`
  - Metasploit RPC daemon (`msfrpcd`) for Metasploit module

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Environment Setup

If using OpenAI prioritization, create `.env` from `.env.example`:

```bash
copy .env.example .env
```

Then set:

```env
OPENAI_API_KEY=your_api_key_here
```

## Run

### CLI mode

```bash
python aartf.py -t 127.0.0.1
```

With reports:

```bash
python aartf.py -t 127.0.0.1 --report
```

Subnet mode:

```bash
python aartf.py -t 192.168.1.0/24 --threads 8 --report
```

### GUI mode

```bash
python aartf.py --gui
```

Alternative direct GUI launch:

```bash
python gui_dashboard.py
```

## Update Existing Clone (Windows + Linux)

For old clones, run the cross-platform updater from repo root:

```bash
python update_aartf.py
```

Optional flags:

```bash
python update_aartf.py --skip-deps
python update_aartf.py --branch main
```

What it does:
- Pulls latest code from GitHub with fast-forward only
- Installs/updates dependencies from `requirements.txt` (unless skipped)

## Output Artifacts

Generated in `reports/`:

- `attack_report_<target>.txt`
- `attack_report_<target>.pdf`
- `attack_graph_<target>.png`
- `attack_timeline_<target>.mp4` or `.gif` (or `.png` fallback)

## Troubleshooting

- `nmap command not found`
  - Install Nmap and ensure it is on PATH.
- `msfrpcd command not found`
  - Install Metasploit and RPC daemon; ensure PATH is set.
- `pymetasploit3 is not installed`
  - `pip install pymetasploit3`
- GUI not launching
  - Ensure Tkinter is available in your Python install.

## Authorized Use Policy

Use this project only on targets you own or where you have explicit written permission.  
Unauthorized scanning or exploitation attempts may violate law, policy, or platform terms.

## Disclaimer

This software is provided for educational and research use in authorized environments.  
The authors and contributors are not responsible for misuse.

## Release

For first public release steps, see `RELEASE_CHECKLIST.md`.
