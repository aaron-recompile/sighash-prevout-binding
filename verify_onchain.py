#!/usr/bin/env python3
"""
Verify the on-chain claims of the sighash prevout-binding experiment.

Needs no keys and no node. Fetches the confirmed transactions from the
mempool.space signet API and checks, for each spend:

  1. the transaction is confirmed and has exactly 2 inputs;
  2. input 0 is a tapscript spend whose leaf script is 196 bytes and whose
     witness is [sig, post_c, post_b, post_a, pre, sha_prevouts, a_outpoint,
     script, control_block];
  3. the leaf script hardcodes the outpoint of input 1 (B);
  4. the witness-supplied outpoint equals the real outpoint of input 0 (A);
  5. SHA256(outpoint_A || outpoint_B), recomputed from the transaction's
     actual inputs, equals the sha_prevouts witness item;
  6. pre || sha_prevouts || post_a || post_b || post_c is 212 bytes and is
     byte-identical to the BIP-341/342 signature message recomputed
     independently from the transaction (so sha_prevouts sits at bytes 10..41);
  7. the 64-byte signature is a valid BIP-340 signature over
     TapSighash(preimage) for the public key hardcoded in the leaf
     (the key used by both OP_CHECKSIGFROMSTACK and OP_CHECKSIG);
  8. the leaf is committed in the Taproot output key of the spent output.

Also checks that the raw transaction hex (/tx/<txid>/hex) hashes to the txid
and carries the same witness as the API's JSON view.

Usage:  python3 verify_onchain.py
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import urllib.request

API = "https://mempool.space/signet/api"
UA = {"User-Agent": "Mozilla/5.0 (verify_onchain.py)"}

TXIDS = [
    "b7959a71b74b8bbed69d52c22a9b3b90af176391be2d0b7f33eb1a6473304606",
    "7311da6e30886fab6594b633bcb97e4436d49f02ecc244d4bc7c59cb1ea83558",
]
EXPECTED_LEAF_SIZE = 196

# ---------------------------------------------------------------- utilities


def fetch_json(path: str):
    req = urllib.request.Request(f"{API}{path}", headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def fetch_text(path: str) -> str:
    req = urllib.request.Request(f"{API}{path}", headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode().strip()


def parse_raw_tx(raw: bytes):
    """Return (txid computed from the non-witness serialization, per-input witness stacks)."""
    def varint(i):
        n = raw[i]
        if n < 0xFD:
            return n, i + 1
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[n]
        return int.from_bytes(raw[i + 1:i + 1 + size], "little"), i + 1 + size

    i = 4
    segwit = raw[4] == 0 and raw[5] == 1
    if segwit:
        i = 6
    start_io = i
    n_in, i = varint(i)
    for _ in range(n_in):
        i += 36
        ln, i = varint(i)
        i += ln + 4
    n_out, i = varint(i)
    for _ in range(n_out):
        i += 8
        ln, i = varint(i)
        i += ln
    end_io = i
    wits = []
    if segwit:
        for _ in range(n_in):
            cnt, i = varint(i)
            items = []
            for _ in range(cnt):
                ln, i = varint(i)
                items.append(raw[i:i + ln])
                i += ln
            wits.append(items)
    stripped = raw[:4] + raw[start_io:end_io] + raw[i:i + 4]
    txid = hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex()
    return txid, wits


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def outpoint(txid_hex: str, vout: int) -> bytes:
    return bytes.fromhex(txid_hex)[::-1] + struct.pack("<I", vout)


# ------------------------------------------------- minimal secp256k1 / BIP-340

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(pt, k: int):
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r


def lift_x(x: int):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else P - y)


def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    pt = lift_x(int.from_bytes(pubkey, "big"))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg), "big") % N
    R = point_add(point_mul(G, s), point_mul(pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def taproot_commits(leaf_script: bytes, control: bytes, spk_hex: str) -> bool:
    leaf_ver = control[0] & 0xFE
    k = tagged_hash("TapLeaf", bytes([leaf_ver]) + compact_size(len(leaf_script)) + leaf_script)
    for i in range(33, len(control), 32):
        e = control[i:i + 32]
        k = tagged_hash("TapBranch", k + e if k < e else e + k)
    internal = lift_x(int.from_bytes(control[1:33], "big"))
    t = int.from_bytes(tagged_hash("TapTweak", control[1:33] + k), "big")
    Q = point_add(internal, point_mul(G, t))
    spk = bytes.fromhex(spk_hex)
    return (spk[:2] == b"\x51\x20" and Q[0].to_bytes(32, "big") == spk[2:]
            and (Q[1] & 1) == (control[0] & 1))


# --------------------------------------------- BIP-341 SigMsg (script path)


def sigmsg_script_path(tx: dict, idx: int, leaf_script: bytes, leaf_ver: int,
                       hash_type: int = 0x00) -> bytes:
    """Epoch byte || SigMsg(SIGHASH_DEFAULT/ALL, ext_flag=1) || BIP-342 extension."""
    vin, vout = tx["vin"], tx["vout"]
    sha_prevouts = sha256(b"".join(outpoint(i["txid"], i["vout"]) for i in vin))
    sha_amounts = sha256(b"".join(struct.pack("<q", i["prevout"]["value"]) for i in vin))
    sha_spks = sha256(b"".join(
        compact_size(len(bytes.fromhex(i["prevout"]["scriptpubkey"])))
        + bytes.fromhex(i["prevout"]["scriptpubkey"]) for i in vin))
    sha_seqs = sha256(b"".join(struct.pack("<I", i["sequence"]) for i in vin))
    sha_outs = sha256(b"".join(
        struct.pack("<q", o["value"]) + compact_size(len(bytes.fromhex(o["scriptpubkey"])))
        + bytes.fromhex(o["scriptpubkey"]) for o in vout))
    m = b"\x00" + bytes([hash_type])
    m += struct.pack("<i", tx["version"]) + struct.pack("<I", tx["locktime"])
    m += sha_prevouts + sha_amounts + sha_spks + sha_seqs + sha_outs
    m += bytes([2])                      # spend_type: ext_flag=1, no annex
    m += struct.pack("<I", idx)
    m += tagged_hash("TapLeaf", bytes([leaf_ver]) + compact_size(len(leaf_script)) + leaf_script)
    m += b"\x00" + b"\xff\xff\xff\xff"   # key_version, codesep_pos
    return m


# ------------------------------------------------------------- leaf parsing


def parse_pushes(script: bytes) -> list:
    """Return the list of data pushes (direct pushes only) in script order."""
    out, i = [], 0
    while i < len(script):
        op = script[i]
        if 1 <= op <= 75:
            out.append(script[i + 1:i + 1 + op])
            i += 1 + op
        elif op == 0x4C:
            n = script[i + 1]
            out.append(script[i + 2:i + 2 + n])
            i += 2 + n
        else:
            i += 1
    return out


# ------------------------------------------------------------------- checks

results: list[bool] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    results.append(bool(ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))


def verify(txid: str) -> None:
    tx = fetch_json(f"/tx/{txid}")
    print(f"\n== {txid}")
    check("confirmed", tx["status"].get("confirmed", False),
          f"block {tx['status'].get('block_height')}")
    check("exactly 2 inputs", len(tx["vin"]) == 2, f"{len(tx['vin'])} inputs")

    raw_txid, raw_wits = parse_raw_tx(bytes.fromhex(fetch_text(f"/tx/{txid}/hex")))
    w = [bytes.fromhex(x) for x in tx["vin"][0].get("witness", [])]
    check("raw /hex hashes to the txid and its witness matches the API JSON",
          raw_txid == txid and raw_wits and raw_wits[0] == w)
    check("input 0 witness has 9 items (7 stack + script + control block)", len(w) == 9,
          f"sizes {[len(x) for x in w]}")
    if len(w) != 9:
        return
    sig, post_c, post_b, post_a, pre, sha_item, a_item, leaf, control = w
    check(f"leaf script is {EXPECTED_LEAF_SIZE} bytes", len(leaf) == EXPECTED_LEAF_SIZE,
          f"{len(leaf)} bytes")
    check("all stack items < 80 bytes (standardness)", all(len(x) < 80 for x in w[:7]))

    op_a = outpoint(tx["vin"][0]["txid"], tx["vin"][0]["vout"])
    op_b = outpoint(tx["vin"][1]["txid"], tx["vin"][1]["vout"])
    pushes = parse_pushes(leaf)
    check("leaf hardcodes outpoint of input 1 (B)", pushes and pushes[0] == op_b,
          f"{tx['vin'][1]['txid'][:16]}...:{tx['vin'][1]['vout']}")
    check("witness-supplied outpoint == real outpoint of input 0 (A)", a_item == op_a,
          f"{tx['vin'][0]['txid'][:16]}...:{tx['vin'][0]['vout']}")

    recomputed = sha256(op_a + op_b)
    check("SHA256(outpoint_A || outpoint_B) == sha_prevouts witness item",
          recomputed == sha_item, recomputed.hex()[:24] + "...")

    preimage = pre + sha_item + post_a + post_b + post_c
    check("reassembled preimage is 212 bytes", len(preimage) == 212, f"{len(preimage)} bytes")
    real = sigmsg_script_path(tx, 0, leaf, control[0] & 0xFE)
    check("reassembled preimage == BIP-341/342 SigMsg recomputed from the tx",
          preimage == real)
    check("sha_prevouts occupies preimage bytes 10..41", real[10:42] == sha_item)

    pk = pushes[-1]  # last push is the key for OP_CHECKSIG; the one before CSFS must match
    same_key = len(pk) == 32 and [p for p in pushes if len(p) == 32].count(pk) >= 2
    check("leaf uses the same 32-byte key for CSFS and CHECKSIG", same_key, pk.hex()[:16] + "...")
    digest = tagged_hash("TapSighash", preimage)
    check("64-byte sig is valid BIP-340 over TapSighash(preimage)",
          len(sig) == 64 and schnorr_verify(digest, pk, sig))
    check("leaf is committed in the spent output's Taproot key",
          taproot_commits(leaf, control, tx["vin"][0]["prevout"]["scriptpubkey"]))


def main() -> int:
    for t in TXIDS:
        try:
            verify(t)
        except Exception as e:  # network or parse error
            check(f"fetch/parse {t[:16]}...", False, repr(e))
    n_pass = sum(results)
    print(f"\n{n_pass}/{len(results)} checks passed")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
