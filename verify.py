#!/usr/bin/env python3
"""verify.py - check a sbom-evidence bundle. Open source (MIT). Needs: pip install cryptography

  python verify.py evidence.json [--sbom my.cdx.json] [--fingerprint 8DC1CCF8C3052039]

Checks that (1) every entry still matches its hash, (2) the entries are linked in order,
(3) the signature over the chain head is valid, (4) optionally that the SBOM file is the one
the evidence was built from, and (5) optionally that the signing key is the one you trust.
Without --fingerprint this proves the file was not altered, not WHO signed it.
"""
import argparse
import base64
import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def entry_hash(seq, typ, data, prev):
    return sha256(canon({"seq": seq, "type": typ, "data": data, "prev": prev}))


def verify(b, sbom_path=None, want_fp=None):
    problems, prev = [], "0" * 64
    for i, e in enumerate(b.get("entries", [])):
        if e.get("seq") != i:
            problems.append("entry %d: wrong sequence number" % i)
        if e.get("prev") != prev:
            problems.append("entry %d: chain link broken" % i)
        if e.get("hash") != entry_hash(e.get("seq"), e.get("type"), e.get("data"), e.get("prev")):
            problems.append("entry %d (%s): content does not match its hash" % (i, e.get("type")))
        prev = e.get("hash")
    if prev != b.get("head"):
        problems.append("chain head does not match last entry")
    raw = b""
    try:
        raw = base64.b64decode(b["public_key"])
        Ed25519PublicKey.from_public_bytes(raw).verify(
            base64.b64decode(b["signature"]),
            canon({"head": b["head"], "created": b["created"], "tool": b["tool"], "format": b["format"]}))
    except (InvalidSignature, KeyError, ValueError):
        problems.append("signature is invalid")
    fp = sha256(raw)[:16].upper() if raw else ""
    if want_fp and fp != want_fp.upper():
        problems.append("signing key fingerprint %s is not the one you trust (%s)" % (fp, want_fp.upper()))
    if sbom_path:
        recorded = next((e["data"]["sha256"] for e in b.get("entries", []) if e.get("type") == "sbom"), None)
        if sha256(open(sbom_path, "rb").read()) != recorded:
            problems.append("SBOM file does not match the one this evidence was built from")
    return problems, fp


def main():
    ap = argparse.ArgumentParser(description="Verify a sbom-evidence bundle")
    ap.add_argument("bundle")
    ap.add_argument("--sbom")
    ap.add_argument("--fingerprint")
    a = ap.parse_args()
    try:
        bundle = json.load(open(a.bundle, encoding="utf-8"))
    except (OSError, ValueError) as e:
        print("cannot read bundle:", e)
        return 2
    problems, fp = verify(bundle, a.sbom, a.fingerprint)
    if problems:
        print("VERIFICATION FAILED")
        for p in problems:
            print(" -", p)
        return 1
    print("OK: chain intact, signature valid, key fingerprint", fp)
    if not a.fingerprint:
        print("note: no --fingerprint given, so this shows integrity, not who signed it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
