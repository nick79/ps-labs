from pathlib import Path

PASSWORDS_FILE = Path(__file__).with_name("lab06-passwords.txt")


def _print_usernames() -> None:
    print("###########The following are the usernames:###############")
    for i in range(150):
        if i % 3:
            print("carlos")
        else:
            print("wiener")


def _print_passwords(passwords: list[str]) -> None:
    print("##############The following are the passwords:############")
    for idx, password in enumerate(passwords):
        if idx % 3 == 0:
            print("peter")
        print(password)


def main() -> None:
    passwords = PASSWORDS_FILE.read_text(encoding="utf-8").splitlines()
    _print_usernames()
    _print_passwords(passwords)


if __name__ == "__main__":
    main()
