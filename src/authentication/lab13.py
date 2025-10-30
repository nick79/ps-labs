from pathlib import Path

PASSWORDS_FILE = Path(__file__).with_name("lab13-passwords.txt")

print("[", end='')

with open(PASSWORDS_FILE, 'r') as f:
    lines = f.readlines()

for pwd in lines:
    print('"' + pwd.rstrip("\n") + '",', end='')

print('"random"]', end='')
