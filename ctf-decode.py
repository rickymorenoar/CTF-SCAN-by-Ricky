#!/usr/bin/env python3
import base64
import codecs
import os
import sys
import urllib.parse

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
ORANGE = "\033[38;5;208m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = rf"""{ORANGE}{BOLD}
        _    __                                 
   ___ | |_ / _|      ___  ___  __ _ _ __       
  / __|| __| |_ _____/ __|/ __|/ _` | '_ \      
 | (__ | |_|  _|_____\__ \ (__| (_| | | | |     
  \___| \__|_|       |___/\___|\__,_|_| |_|     
{RESET}{ORANGE}  Multi-Decoder & Crypto Triage Toolkit by Ricky{RESET}
"""

def decode_base64(text):
    b64 = base64.b64decode(text + "=" * ((4 - len(text) % 4) % 4)).decode("utf-8")
    if b64.isprintable():
        return b64
    raise ValueError("Tidak terbaca")

def decode_base32(text):
    b32 = base64.b32decode(text.upper() + "=" * ((8 - len(text) % 8) % 8)).decode("utf-8")
    if b32.isprintable():
        return b32
    raise ValueError("Tidak terbaca")

def decode_hex(text):
    hx = bytes.fromhex(text.replace("0x", "").replace(" ", "")).decode("utf-8")
    if hx.isprintable():
        return hx
    raise ValueError("Tidak terbaca")

def decode_binary(text):
    clean = "".join(text.split())
    if not clean or any(c not in "01" for c in clean) or len(clean) % 8 != 0:
        raise ValueError("Format biner tidak valid (harus kelipatan 8 bit)")
    res = "".join(chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8))
    if res.isprintable():
        return res
    raise ValueError("Tidak terbaca")

def decode_url(text):
    return urllib.parse.unquote(text)

def decode_rot13(text):
    return codecs.decode(text, "rot_13")

def decode_vigenere(text, key):
    key = "".join(c.lower() for c in key if c.isalpha())
    if not key:
        raise ValueError("Key Vigenere harus berupa huruf")
    res = []
    idx = 0
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            shift = ord(key[idx % len(key)]) - 97
            res.append(chr((ord(c) - base - shift) % 26 + base))
            idx += 1
        else:
            res.append(c)
    return "".join(res)

def xor_hex(hex1, hex2):
    val1 = int(hex1.replace("0x", ""), 16)
    val2 = int(hex2.replace("0x", ""), 16)
    return hex(val1 ^ val2)

def decode_all(text):
    print(f"\nTarget: {CYAN}{text}{RESET}\n")
    methods = [
        ("Base64", decode_base64),
        ("Base32", decode_base32),
        ("Hex", decode_hex),
        ("Binary", decode_binary),
        ("URL Decode", decode_url),
        ("ROT13", decode_rot13),
    ]
    for name, func in methods:
        try:
            res = func(text)
            if name == "URL Decode" and res == text:
                continue
            color = YELLOW if name == "ROT13" else GREEN
            print(f"{color}[{name:<10}] :{RESET} {res}")
        except Exception:
            pass

def show_menu():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print(f"{CYAN}=== PILIH MODE DECODE ==={RESET}")
    print("1. Auto Decode All (Base64, Base32, Hex, Binary, URL, ROT13)")
    print("2. Base64")
    print("3. Base32")
    print("4. Hex ke ASCII")
    print("5. Binary ke ASCII")
    print("6. URL Decode")
    print("7. ROT13")
    print("8. Vigenère Cipher (Butuh Key)")
    print("9. XOR Dua Bilangan Hex")
    print("0. Keluar")

def main():
    while True:
        show_menu()
        choice = input(f"\n{YELLOW}Pilih mode [0-9]: {RESET}").strip()

        if choice == "0":
            print("Keluar...")
            break

        if choice not in [str(i) for i in range(1, 10)]:
            print(f"{RED}[!] Pilihan tidak valid.{RESET}")
            input(f"\n{YELLOW}Tekan Enter untuk kembali ke menu...{RESET}")
            continue

        try:
            if choice == "9":
                h1 = input(f"{CYAN}Masukkan Hex 1 (contoh 0xc4115): {RESET}").strip()
                h2 = input(f"{CYAN}Masukkan Hex 2 (contoh 0x4cf8) : {RESET}").strip()
                print(f"\n{GREEN}[Hasil XOR]  :{RESET} {xor_hex(h1, h2)}")
                input(f"\n{YELLOW}Tekan Enter untuk kembali ke menu...{RESET}")
                continue

            target = input(f"{CYAN}Masukkan string/kode target: {RESET}").strip()
            if not target:
                print(f"{RED}[!] Input tidak boleh kosong.{RESET}")
                input(f"\n{YELLOW}Tekan Enter untuk kembali ke menu...{RESET}")
                continue

            if choice == "1":
                decode_all(target)
            elif choice == "2":
                print(f"\n{GREEN}[Base64]     :{RESET} {decode_base64(target)}")
            elif choice == "3":
                print(f"\n{GREEN}[Base32]     :{RESET} {decode_base32(target)}")
            elif choice == "4":
                print(f"\n{GREEN}[Hex]        :{RESET} {decode_hex(target)}")
            elif choice == "5":
                print(f"\n{GREEN}[Binary]     :{RESET} {decode_binary(target)}")
            elif choice == "6":
                print(f"\n{GREEN}[URL Decode] :{RESET} {decode_url(target)}")
            elif choice == "7":
                print(f"\n{YELLOW}[ROT13]      :{RESET} {decode_rot13(target)}")
            elif choice == "8":
                key = input(f"{CYAN}Masukkan Key Vigenère: {RESET}").strip()
                print(f"\n{GREEN}[Vigenere]   :{RESET} {decode_vigenere(target, key)}")

        except Exception as e:
            print(f"\n{RED}[Error] Gagal decode: {e}{RESET}")

        input(f"\n{YELLOW}Tekan Enter untuk kembali ke menu...{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram dihentikan.")
        sys.exit(0)
