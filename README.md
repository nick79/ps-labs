# PortSwigger Web Academy Labs - Python Scripts
Small, focused Python scripts grouped by topic (e.g., `sqli`, `xss`, `auth`) to assist with practicing
PortSwigger Web Security Academy labs.

> Use responsibly and only against lab targets you are authorized to test.

## Requirements
- Python 3.13+ recomended (3.10+ ok)
- `pip` virtual environment
- Ruff (installed via `pip`)

## Quick start
```bash
# Create and activate a venv (POSIX)
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install tools/deps
pip install -U pip
pip install -r requirements.txt
# or
pip install ruff

# Run a single lab script
python -m  ps-labs.sqli.lab01 --url https://<URL>
```
