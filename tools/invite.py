#!/usr/bin/env python3
"""Manage invite codes for the My IPTV app.

An invite maps a secret code (e.g. "Abu_Alwaleed") to a NAME of a server stored (encrypted) in the
myiptv-servers repo. The invite itself is AES-256-GCM encrypted with a key derived from the code
(PBKDF2-HMAC-SHA256), so the public invites.json reveals nothing without the code.

  python3 tools/invite.py add    CODE --server NAME
  python3 tools/invite.py remove CODE
  python3 tools/invite.py count

Server keys are read from ../myiptv-servers/keys.local.json (override with env MYIPTV_KEYS).
Then:  git add invites.json && git commit -m "update invites" && git push

SECURITY: anyone can download invites.json and try guesses offline. Use a LONG random code (16+ chars):
  python3 -c "import secrets;print(secrets.token_urlsafe(12))"
A short or dictionary-word code can be brute-forced. To revoke an invite: `remove CODE` and push.
"""
import argparse, base64, hashlib, json, os, sys, unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "..", "invites.json")
KEYS = os.environ.get("MYIPTV_KEYS", os.path.join(HERE, "..", "..", "myiptv-servers", "keys.local.json"))
ITERATIONS = 600_000


def normalize(code: str) -> str:
    return unicodedata.normalize("NFKC", code).strip().lower()


def load():
    if os.path.exists(FILE):
        with open(FILE, encoding="utf-8") as f:
            return json.load(f)
    return {"version": 2, "salt": base64.b64encode(os.urandom(16)).decode(), "iterations": ITERATIONS, "invites": []}


def save(data):
    with open(FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def derive(code, data):
    salt = base64.b64decode(data["salt"])
    dk = hashlib.pbkdf2_hmac("sha256", normalize(code).encode(), salt, data["iterations"], dklen=48)
    return dk[:16].hex(), dk[16:]


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("code"); a.add_argument("--server", required=True)
    r = sub.add_parser("remove"); r.add_argument("code")
    sub.add_parser("count")
    args = ap.parse_args()

    data = load()
    if args.cmd == "count":
        print(len(data["invites"]), "invite(s)"); save(data); return

    invite_id, key = derive(args.code, data)
    data["invites"] = [e for e in data["invites"] if e["id"] != invite_id]

    if args.cmd == "add":
        if len(normalize(args.code)) < 12:
            print("WARNING: short code — easy to brute-force from the public file. Prefer 16+ random characters.", file=sys.stderr)
        with open(KEYS, encoding="utf-8") as f:
            server_keys = json.load(f)
        if args.server not in server_keys:
            sys.exit(f"unknown server '{args.server}' — create it first with myiptv-servers/tools/server.py")
        payload = json.dumps({"server": args.server, "key": server_keys[args.server]}, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, payload, None)
        data["invites"].append({"id": invite_id, "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()})
        print("added")
    else:
        print("removed (if it existed)")
    save(data)


if __name__ == "__main__":
    main()
