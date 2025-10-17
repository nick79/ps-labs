# PortSwigger Web Academy Labs – Python Scripts

Python utilities that automate PortSwigger Web Security Academy labs. Each topic (SQLi, XSS, auth, etc.) gets its own folder of focused scripts so you can copy, adapt, and extend them while learning.

> Use responsibly and only against lab targets you are authorized to test.

## Requirements
- Python 3.10+ (3.13 recommended)
- `pip` with virtual environments
- Dependencies from `requirements.txt` (`requests`, `beautifulsoup4`, `ruff`)

## Setup
```bash
# Create and activate a virtual environment (POSIX)
python3 -m venv .venv
source .venv/bin/activate

# Install or upgrade tooling
pip install -U pip
pip install -r requirements.txt
```

## Running Labs
Each script is importable via the `src` package. Example: run the first SQLi helper against a target URL and payload.

```bash
python -m src.sqli.lab01 --url https://TARGET --payload "' OR '1'='1"
```

Most scripts share flags such as `--proxy http://127.0.0.1:8080`, `--header Name:Value`, and `--timeout 10`. See `--help` on any module for the full CLI.

## Development Workflow
- Format and lint with Ruff: `ruff check src` and `ruff format src`.
- New CLI helpers live under `src/common/`; labs should reuse them to avoid duplication.
- See `AGENTS.md` for contributor guidelines, testing expectations, and PR tips.

## Project Layout
- `src/common/` – HTTP and CLI utilities (shared requests session, argument helpers).
- `src/sqli/` – SQL injection labs (`lab01.py`, `lab02.py`) plus reusable payload logic.
- `requirements.txt` – minimal runtime and tooling dependencies.

