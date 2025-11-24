
import os
import sqlite3
import getpass
import argparse
import json
import pyperclip
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

DB_FILENAME = 'vault.db'
SALT_FILENAME = 'vault_salt.bin'

def get_master_key():
    if not os.path.exists(SALT_FILENAME):
        print("Vault not initialized. Run `init` first.")
        exit(1)
    with open(SALT_FILENAME, 'rb') as f:
        salt = f.read()
    master_pass = getpass.getpass("Enter master password: ").encode()
    # derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_pass)
    return key

def init_vault():
    if os.path.exists(DB_FILENAME) or os.path.exists(SALT_FILENAME):
        print("Vault already exists!")
        exit(1)
    salt = secrets.token_bytes(16)
    with open(SALT_FILENAME, 'wb') as f:
        f.write(salt)
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE credentials (
          service TEXT PRIMARY KEY,
          username TEXT,
          password_enc BLOB,
          iv BLOB
        )
    ''')
    conn.commit()
    conn.close()
    print("Vault initialized. Set your master password now.")
    # Prompt user for master password
    mp = getpass.getpass("Set master password: ")
    mp2 = getpass.getpass("Confirm master password: ")
    if mp != mp2:
        print("Passwords do not match.")
        os.remove(DB_FILENAME)
        os.remove(SALT_FILENAME)
        exit(1)
    print("Master password set. Use `add`, `get`, `delete` commands.")

def encrypt(key: bytes, plaintext: str):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ct

def decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ciphertext) + decryptor.finalize()
    return pt.decode()

def add_credential(args):
    key = get_master_key()
    iv, ct = encrypt(key, args.password)
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('REPLACE INTO credentials(service, username, password_enc, iv) VALUES (?, ?, ?, ?)',
              (args.service, args.username, ct, iv))
    conn.commit()
    conn.close()
    print(f"Stored credentials for service '{args.service}'.")

def get_credential(args):
    key = get_master_key()
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('SELECT username, password_enc, iv FROM credentials WHERE service = ?', (args.service,))
    row = c.fetchone()
    conn.close()
    if not row:
        print("No credentials found for that service.")
        return
    username, ct, iv = row
    password = decrypt(key, iv, ct)
    print(f"Service: {args.service}")
    print(f"Username: {username}")
    print(f"Password: {password}")
    if args.copy:
        pyperclip.copy(password)
        print("(Password copied to clipboard)")

def delete_credential(args):
    key = get_master_key()  # ensure master password correct
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('DELETE FROM credentials WHERE service = ?', (args.service,))
    conn.commit()
    conn.close()
    print(f"Deleted credentials for service '{args.service}'.")

def list_services(args):
    key = get_master_key()
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute('SELECT service FROM credentials')
    rows = c.fetchall()
    conn.close()
    print("Stored services:")
    for r in rows:
        print(f" - {r[0]}")

def main():
    parser = argparse.ArgumentParser(description="Simple Password Vault")
    sub = parser.add_subparsers(dest='command')

    parser_init = sub.add_parser('init', help='Initialize vault')
    parser_add = sub.add_parser('add', help='Add credential')
    parser_add.add_argument('--service', required=True)
    parser_add.add_argument('--username', required=True)
    parser_add.add_argument('--password', required=True)
    parser_get = sub.add_parser('get', help='Get credential')
    parser_get.add_argument('--service', required=True)
    parser_get.add_argument('--copy', action='store_true', help='Copy password to clipboard')
    parser_del = sub.add_parser('delete', help='Delete credential')
    parser_del.add_argument('--service', required=True)
    parser_list = sub.add_parser('list', help='List stored services')

    args = parser.parse_args()
    if args.command == 'init':
        init_vault()
    elif args.command == 'add':
        add_credential(args)
    elif args.command == 'get':
        get_credential(args)
    elif args.command == 'delete':
        delete_credential(args)
    elif args.command == 'list':
        list_services(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()