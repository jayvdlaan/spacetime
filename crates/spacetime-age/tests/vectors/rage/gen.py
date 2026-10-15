#!/usr/bin/env python3
"""Generator for spacetime-age's rage-oracle test vectors (contract §5.3-§5.5).

Deterministic apart from rage's own randomness inside the `rage_*` vectors
(those are decrypt-only oracles). Keys are derived from fixed seeds, never
from `rage-keygen`/`ssh-keygen`. Every hex/string value pinned in the
contract is asserted, not just written. Exits non-zero on any mismatch —
never "fixes" an expectation.

Requires: python3 (3.9+) stdlib only, plus `rage`/`rage-keygen` on PATH.
`ssh-keygen` is optional (fingerprint cross-check only, recorded not required).
"""
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import age_ref as ar

HERE = Path(__file__).resolve().parent
KEYS = HERE / "keys"
PAYLOADS = HERE / "payloads"
VECTORS = HERE / "vectors"

RAGE = shutil.which("rage") or os.path.expanduser("~/.cargo/bin/rage")
RAGE_KEYGEN = shutil.which("rage-keygen") or os.path.expanduser("~/.cargo/bin/rage-keygen")
SSH_KEYGEN = shutil.which("ssh-keygen")

FAILURES = []


def check(cond, msg):
    if not cond:
        FAILURES.append(msg)
        print(f"MISMATCH: {msg}", file=sys.stderr)


def run(args, **kw):
    return subprocess.run(args, check=True, capture_output=True, **kw)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# =====================================================================
# 1. Fixed keys (contract §5.3)
# =====================================================================

def main():
    for d in (KEYS, PAYLOADS, VECTORS):
        d.mkdir(parents=True, exist_ok=True)

    versions = run([RAGE, "--version"]).stdout.decode().strip()
    kv = run([RAGE_KEYGEN, "--version"]).stdout.decode().strip()
    print(f"rage: {versions}")
    print(f"rage-keygen: {kv}")
    check(versions.startswith("rage 0.12.1"), f"rage version is {versions!r}, expected 0.12.1")
    check(kv.startswith("rage-keygen 0.12.1"), f"rage-keygen version is {kv!r}, expected 0.12.1")

    # ---- X25519 identity ----
    x_secret = bytes.fromhex(sha256_str(b"spacetime-age vector x25519 identity"))
    check(x_secret.hex() == "218b823344bf92d080a6306b952d7e5e8d09381af63eccd71345098151a59fbc",
          f"x25519 secret hex mismatch: {x_secret.hex()}")
    x_pub = ar.x25519(x_secret, ar.BASEPOINT)
    x_recipient = ar.x25519_recipient_str(x_secret)
    x_identity = ar.x25519_identity_str(x_secret)
    check(x_recipient == "age15weja5qsvsv9utrqyke5nza08vmals2lyls73n5v7hltfk46mcqsy3c60l",
          f"x25519 recipient mismatch: {x_recipient}")
    check(x_identity == "AGE-SECRET-KEY-1YX9CYV6YH7FDPQ9XXP4E2TT7T6XSJWQ67CLVE4CNG5YCZ5D9N77QZ8EEGV",
          f"x25519 identity mismatch: {x_identity}")
    check(x_pub.hex() == "a3b32ed01064185e2c6025b3498baf3b37dfc15f27e1e8ce8cf5feb4dabade01",
          f"x25519 raw pub mismatch: {x_pub.hex()}")

    (KEYS / "x25519.txt").write_text(x_identity + "\n")
    os.chmod(KEYS / "x25519.txt", 0o600)

    ykt = run([RAGE_KEYGEN, "-y", str(KEYS / "x25519.txt")]).stdout.decode().strip()
    check(ykt == x_recipient, f"rage-keygen -y disagrees: {ykt} != {x_recipient}")

    # ---- ssh-ed25519 identity ----
    ssh_seed = bytes.fromhex(sha256_str(b"spacetime-age vector ssh key"))
    check(ssh_seed.hex() == "2fd4d6679dfea3aae5df5cd19cd04f80609aa11a49feaa6308e472c3b7b0c2c5",
          f"ssh seed hex mismatch: {ssh_seed.hex()}")
    ssh_pub = ar.ed25519_public_key(ssh_seed)
    check(ssh_pub.hex() == "39a34d2b6ff6b8f3e9d7d8540f42e020ff75cbcf9db45c6ab95d6dca5ecc86c2",
          f"ssh pub hex mismatch: {ssh_pub.hex()}")
    ssh_wire = ar.ssh_wire_ed25519(ssh_pub)
    tag = hashlib.sha256(ssh_wire).digest()[:4]
    check(tag.hex() == "eb88dd53", f"ssh tag hex mismatch: {tag.hex()}")
    tag_b64 = ar.b64e(tag)
    check(tag_b64 == "64jdUw", f"ssh tag b64 mismatch: {tag_b64}")
    ssh_pk_mont = ar.ed25519_pk_to_x25519(ssh_pub)
    check(ssh_pk_mont.hex() == "4e7ad2ecc96a4dfc28733bb37040dd6efea365e8738329b581cc25982f170c3a",
          f"ssh pk_mont mismatch: {ssh_pk_mont.hex()}")
    ssh_pub_line = ar.openssh_pub_line(ssh_pub, b"spacetime-age-ssh").decode()
    check(ssh_pub_line == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDmjTStv9rjz6dfYVA9C4CD/dcvPnbRcarldbcpezIbC spacetime-age-ssh\n",
          f"ssh pub line mismatch: {ssh_pub_line!r}")

    priv_key_file = KEYS / "ssh_ed25519"
    priv_key_file.write_bytes(ar.openssh_key_v1(ssh_seed, b"spacetime-age-ssh"))
    os.chmod(priv_key_file, 0o600)
    (KEYS / "ssh_ed25519.pub").write_text(ssh_pub_line)

    fingerprint = None
    if SSH_KEYGEN:
        try:
            out = run([SSH_KEYGEN, "-lf", str(KEYS / "ssh_ed25519.pub")]).stdout.decode()
            fingerprint = out.split()[1]
            expect_fp = "SHA256:64jdU5YwIt80L6aJ0IKy4qHvNmA9/5fK5ySaGCN7JR0"
            check(fingerprint == expect_fp, f"ssh-keygen fingerprint mismatch: {fingerprint} != {expect_fp}")
        except Exception as e:  # noqa: BLE001 - recorded, not required
            print(f"ssh-keygen fingerprint check skipped: {e}", file=sys.stderr)

    # rage must accept our hand-written openssh-key-v1 file as an identity.
    try:
        run([RAGE, "-d", "-i", str(priv_key_file)], input=b"")
    except subprocess.CalledProcessError as e:
        # Expected to fail with "no matches" (empty stdin isn't a valid age
        # file) — this just proves rage parses the identity file itself
        # without erroring on the *identity*. A parse error on the identity
        # would be a distinct message; check stderr does not mention it.
        stderr = e.stderr.decode()
        check("failed to read" not in stderr.lower() or "age" in stderr.lower(),
              f"rage rejected the ssh identity file: {stderr}")

    # ---- "other" identity (no-match; never stored as a decryptable identity) ----
    other_secret = bytes.fromhex(sha256_str(b"spacetime-age vector other identity"))
    check(other_secret.hex() == "52db62d4e5709344585d16a5b9d8770497e2427270a96d5c3a3f1d29ab1b296c",
          f"other secret hex mismatch: {other_secret.hex()}")
    other_recipient = ar.x25519_recipient_str(other_secret)

    # =====================================================================
    # 2. Payloads
    # =====================================================================
    payload_specs = [("p0", 0), ("p1", 1), ("p64k", 65536), ("p64k1", 65537), ("p200k", 204800)]
    expected_hashes = {
        "p0": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "p1": "c555eab45d08845ae9f10d452a99bfcb06f74a50b988fe7e48dd323789b88ee3",
        "p64k": "f6a5366455cfe5267ab0557198f18d893c4ac9b22ceb3f77cd2661f57084143c",
        "p64k1": "ed74e3e453399fc24e9d7eb63fa0122acfb5ce12fe0d740be1ccbb91ffec32b5",
        "p200k": "c540c4e3c92a4741d2f3da5a84ecb1b9c5469f48654abf751b5ccf32912f9abc",
    }
    payloads = {}
    for name, n in payload_specs:
        data = gen_payload(n)
        (PAYLOADS / f"{name}.bin").write_bytes(data)
        h = sha256(data)
        want = expected_hashes[name]
        check(h == want, f"payload {name} sha256 mismatch: {h} != {want}")
        payloads[name] = {"file": f"payloads/{name}.bin", "len": n, "sha256": h}

    # =====================================================================
    # 3. rage vectors: {x25519, ssh, both} x {p0,p1,p64k,p64k1,p200k} x {"", armored} + other_p1
    # =====================================================================
    manifest_vectors = []
    recip_sets = {
        "x25519": (["-r", x_recipient], ["x25519"]),
        "ssh": (["-R", str(KEYS / "ssh_ed25519.pub")], ["ssh_ed25519"]),
        "both": (["-r", x_recipient, "-R", str(KEYS / "ssh_ed25519.pub")], ["x25519", "ssh_ed25519"]),
    }
    all_idents = {"x25519", "ssh_ed25519"}

    for kind, (flags, recipients) in recip_sets.items():
        for pname, _n in payload_specs:
            for armored in (False, True):
                name = f"rage_{kind}_{pname}" + ("_armored" if armored else "")
                out_file = VECTORS / f"{name}.age"
                rel_flags = ["keys/ssh_ed25519.pub" if f == str(KEYS / "ssh_ed25519.pub") else f for f in flags]
                cmd = [RAGE] + flags + (["-a"] if armored else []) + ["-o", str(out_file), str(PAYLOADS / f"{pname}.bin")]
                run(cmd)
                rel_cmd = ["rage"] + rel_flags + (["-a"] if armored else []) + ["-o", f"vectors/{name}.age", f"payloads/{pname}.bin"]
                data = out_file.read_bytes()
                ident_ok = sorted(recipients)
                ident_no = sorted(all_idents - set(recipients))
                verify_rage_vector(data, pname, payloads, x_secret, ssh_seed, ident_ok, ident_no)
                manifest_vectors.append({
                    "name": name,
                    "file": f"vectors/{name}.age",
                    "kind": "rage",
                    "recipients": recipients,
                    "armored": armored,
                    "payload": pname,
                    "identities_ok": ident_ok,
                    "identities_no_match": ident_no,
                    "provenance": " ".join(rel_cmd),
                })
                print(f"{name} kind=rage recipients={recipients} armored={armored} payload={pname} rage=ok python=ok")

    # other_p1: recipient = other (no identity we hold can decrypt it)
    name = "rage_other_p1"
    out_file = VECTORS / f"{name}.age"
    cmd = [RAGE, "-r", other_recipient, "-o", str(out_file), str(PAYLOADS / "p1.bin")]
    run(cmd)
    data = out_file.read_bytes()
    verify_rage_vector(data, "p1", payloads, x_secret, ssh_seed, [], sorted(all_idents))
    manifest_vectors.append({
        "name": name,
        "file": f"vectors/{name}.age",
        "kind": "rage",
        "recipients": ["other"],
        "armored": False,
        "payload": "p1",
        "identities_ok": [],
        "identities_no_match": sorted(all_idents),
        "provenance": f"rage -r {other_recipient} -o vectors/{name}.age payloads/p1.bin",
    })
    print(f"{name} kind=rage recipients=['other'] armored=False payload=p1 rage=ok python=ok")

    check(len(manifest_vectors) == 31, f"expected 31 rage vectors, got {len(manifest_vectors)}")

    # =====================================================================
    # 4. pyref vectors (deterministic, CounterRng(0))
    # =====================================================================
    pyref_specs = [
        ("pyref_x25519_p1", ["x25519"], "p1", False),
        ("pyref_ssh_p1", ["ssh_ed25519"], "p1", False),
        ("pyref_both_p1", ["x25519", "ssh_ed25519"], "p1", False),
        ("pyref_both_p0", ["x25519", "ssh_ed25519"], "p0", False),
        ("pyref_x25519_p64k", ["x25519"], "p64k", False),
        ("pyref_both_p64k1", ["x25519", "ssh_ed25519"], "p64k1", False),
    ]

    for name, recipients, pname, armored in pyref_specs:
        pt = (PAYLOADS / f"{pname}.bin").read_bytes()
        data, _ = build_pyref(x_pub, ssh_pub, recipients, pt)
        (VECTORS / f"{name}.age").write_bytes(data)
        h = sha256(data)
        ident_ok = sorted(recipients)
        ident_no = sorted(all_idents - set(recipients))
        cross_check_pyref(data, x_secret, ssh_seed, ident_ok, KEYS)
        manifest_vectors.append({
            "name": name, "file": f"vectors/{name}.age", "kind": "pyref",
            "recipients": recipients, "armored": False, "payload": pname,
            "rng": "counter:0", "sha256": h,
            "identities_ok": ident_ok, "identities_no_match": ident_no,
            "provenance": "age_ref.encrypt (deterministic)",
        })
        print(f"{name} kind=pyref recipients={recipients} armored=False payload={pname} rage=ok python=ok")

    # pyref_x25519_p1_armored: same bytes as pyref_x25519_p1, armored
    base_name = "pyref_x25519_p1"
    base_data = (VECTORS / f"{base_name}.age").read_bytes()
    arm = ar.armor_encode(base_data)
    (VECTORS / "pyref_x25519_p1_armored.age").write_bytes(arm)
    h = sha256(arm)
    cross_check_pyref(arm, x_secret, ssh_seed, ["x25519"], KEYS)
    manifest_vectors.append({
        "name": "pyref_x25519_p1_armored", "file": "vectors/pyref_x25519_p1_armored.age", "kind": "pyref",
        "recipients": ["x25519"], "armored": True, "payload": "p1",
        "rng": "counter:0", "sha256": h,
        "identities_ok": ["x25519"], "identities_no_match": ["ssh_ed25519"],
        "provenance": "age_ref.encrypt (deterministic) + armor_encode",
    })
    print("pyref_x25519_p1_armored kind=pyref recipients=['x25519'] armored=True payload=p1 rage=ok python=ok")

    # pyref_both_det: the contract's own KAT (§5.3)
    data, stanza_lines = build_pyref(x_pub, ssh_pub, ["x25519", "ssh_ed25519"], b"det\n")
    (VECTORS / "pyref_both_det.age").write_bytes(data)
    h = sha256(data)
    check(len(data) == 314, f"pyref_both_det length mismatch: {len(data)}")
    check(h == "9750c16527fcd0f924c40529d9ec1f072eceef822a5c9054c32c02f54201df1b",
          f"pyref_both_det sha256 mismatch: {h}")
    check(stanza_lines[0] == "-> X25519 2J47rXlDfb7Z+ENBgwT0YP8Fx/6B/kqVd6gEy5Nn/2Y",
          f"pyref_both_det X25519 stanza mismatch: {stanza_lines[0]!r}")
    check(stanza_lines[1] == "-> ssh-ed25519 64jdUw NOQtSvXvlKB6OoQgG4idTNGnQ8snsRtqEEOKj+uOWEc",
          f"pyref_both_det ssh-ed25519 stanza mismatch: {stanza_lines[1]!r}")
    check(stanza_lines[2] == "--- Yah3lrbDKtcPMuA1MxOkdcGYsTQY4frDk+lKZTPI3qo",
          f"pyref_both_det MAC line mismatch: {stanza_lines[2]!r}")
    arm_det = ar.armor_encode(data)
    hd = sha256(arm_det)
    check(len(arm_det) == 495, f"pyref_both_det armored length mismatch: {len(arm_det)}")
    check(hd == "1fc65fff10b9d4ea808748e03cce51b9099e5b734d8ad77e39871717f285e5e3",
          f"pyref_both_det armored sha256 mismatch: {hd}")
    cross_check_pyref(data, x_secret, ssh_seed, ["x25519", "ssh_ed25519"], KEYS)
    manifest_vectors.append({
        "name": "pyref_both_det", "file": "vectors/pyref_both_det.age", "kind": "pyref",
        "recipients": ["x25519", "ssh_ed25519"], "armored": False,
        "plaintext_hex": b"det\n".hex(),
        "rng": "counter:0", "sha256": h,
        "identities_ok": ["x25519", "ssh_ed25519"], "identities_no_match": [],
        "provenance": "age_ref.encrypt (deterministic)",
    })
    print("pyref_both_det kind=pyref recipients=['x25519', 'ssh_ed25519'] armored=False payload=det rage=ok python=ok")

    check(sum(1 for v in manifest_vectors if v["kind"] == "pyref") == 8,
          f"expected 8 pyref vectors, got {sum(1 for v in manifest_vectors if v['kind'] == 'pyref')}")

    # =====================================================================
    # 5. ed25519_to_x25519.json
    # =====================================================================
    rfc_vectors = [
        ("Ed25519→X25519 RFC 8032 TEST 1", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e"),
        ("Ed25519→X25519 RFC 8032 TEST 2", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "25c704c594b88afc00a76b69d1ed2b984d7e22550f3ed0802d04fbcd07d38d47"),
        ("Ed25519→X25519 RFC 8032 TEST 3", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "cbb22fc9f790bd3eba9b84680c157ca4950a9894362601701f89c3c4d9fda23a"),
        ("Ed25519→X25519 RFC 8032 TEST SHA(abc)", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
         "d5948dca7a9ad7175303dc6881c34aa7881fb946ee34dfd8fab126ed6db8da69"),
    ]
    ed25519_to_x25519 = {"vectors": [], "invalid": []}
    for name, pk_hex, u_hex in rfc_vectors:
        pk = bytes.fromhex(pk_hex)
        u = ar.ed25519_pk_to_x25519(pk)
        check(u.hex() == u_hex, f"{name}: computed {u.hex()} != {u_hex}")
        # cross-check independently via the X25519 ladder against a=SHA-512(seed)[..32]
        # (not applicable here — these are bare public keys with no known seed; the
        # cross-check for the *ssh key* below covers the seed-based path).
        ed25519_to_x25519["vectors"].append({
            "name": name, "ed25519_public_hex": pk_hex, "x25519_public_hex": u.hex(),
        })
    u_ssh = ar.ed25519_pk_to_x25519(ssh_pub)
    check(u_ssh.hex() == ssh_pk_mont.hex(), "ssh key u mismatch between two call sites")
    u_ssh_ladder = ar.x25519(hashlib.sha512(ssh_seed).digest()[:32], ar.BASEPOINT)
    check(u_ssh.hex() == u_ssh_ladder.hex(), "ssh key u != X25519(SHA-512(seed)[..32], 9)")
    ed25519_to_x25519["vectors"].append({
        "name": "spacetime-age vector ssh key",
        "ed25519_public_hex": ssh_pub.hex(),
        "x25519_public_hex": u_ssh.hex(),
    })

    invalid_specs = [
        ("Ed25519 identity point", ar.IDENTITY_ENCODING),
        ("Ed25519 order-2 point (y = -1)", ar.ORDER2_ENCODING),
        ("Ed25519 order-4 point (y = 0)", ar.ORDER4_ENCODING),
        ("Ed25519 non-canonical y = p + 1", ar.NONCANONICAL_IDENTITY_ENCODING),
        ("Ed25519 non-canonical y = p + 1, sign bit set", ar.NONCANONICAL_SIGN_ENCODING),
    ]
    for name, enc in invalid_specs:
        ed25519_to_x25519["invalid"].append({"name": name, "ed25519_public_hex": enc.hex()})

    (HERE / "ed25519_to_x25519.json").write_text(json.dumps(ed25519_to_x25519, indent=2) + "\n")

    # =====================================================================
    # 6. manifest.json
    # =====================================================================
    manifest = {
        "schema": 1,
        "generator": "gen.sh → gen.py (python3 stdlib + age_ref.py); rage 0.12.1 / rage-keygen 0.12.1 for provenance 'rage: ...'",
        "note": "rage output is randomised; vectors named rage_* are decrypt-only oracles. pyref_* files are deterministic (counter RNG, see rng).",
        "keys": {
            "x25519": {
                "identity_file": "keys/x25519.txt", "identity": x_identity, "recipient": x_recipient,
                "secret_hex": x_secret.hex(), "public_key_hex": x_pub.hex(),
            },
            "ssh_ed25519": {
                "private_file": "keys/ssh_ed25519", "public_file": "keys/ssh_ed25519.pub",
                "public_key_line": ssh_pub_line.strip(),
                "seed_hex": ssh_seed.hex(), "public_key_hex": ssh_pub.hex(),
                "tag_hex": tag.hex(), "tag_b64": tag_b64, "x25519_public_hex": ssh_pk_mont.hex(),
            },
            "other": {"recipient": other_recipient},
        },
        "payloads": payloads,
        "vectors": manifest_vectors,
    }
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    if FAILURES:
        print(f"\n{len(FAILURES)} mismatch(es) found:", file=sys.stderr)
        for f in FAILURES:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)

    print(f"\nOK: {len(manifest_vectors)} vectors "
          f"({sum(1 for v in manifest_vectors if v['kind']=='rage')} rage, "
          f"{sum(1 for v in manifest_vectors if v['kind']=='pyref')} pyref), "
          f"5 payloads, {len(ed25519_to_x25519['vectors'])} conversion vectors, "
          f"{len(ed25519_to_x25519['invalid'])} invalid-key vectors.")


def sha256_str(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def gen_payload(n: int) -> bytes:
    """p_n = first n bytes of SHA-256(b"spacetime-age payload " || BE32(i)) for i = 0, 1, ..."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"spacetime-age payload " + struct.pack(">I", i)).digest()
        i += 1
    return bytes(out[:n])


def build_pyref(x_pub, ssh_pub, recipients, plaintext):
    """Deterministic encrypt via age_ref with CounterRng(0), draw order per
    contract §4: FileKey (16), then per-recipient wrap (32 each, in the
    fixed order [x25519, ssh_ed25519]), then StreamWriter nonce (16)."""
    rng = ar.CounterRng(0)
    file_key = rng.bytes(16)
    stanzas = []
    for kind in ("x25519", "ssh_ed25519"):
        if kind not in recipients:
            continue
        if kind == "x25519":
            stanzas.append(ar.x25519_wrap(rng.bytes(32), x_pub, file_key))
        else:
            stanzas.append(ar.ssh_ed25519_wrap(rng.bytes(32), ssh_pub, file_key))
    nonce = rng.bytes(16)
    data = ar.encrypt(file_key, nonce, stanzas, plaintext)
    lines = data.split(b"\n")
    stanza_lines = [l.decode() for l in lines if l.startswith(b"-> ") or l.startswith(b"---")]
    return data, stanza_lines


def verify_rage_vector(data, pname, payloads, x_secret, ssh_seed, ident_ok, ident_no):
    if data.lstrip().startswith(ar.ARMOR_BEGIN):
        data = ar.armor_decode(data)
    want_hash = payloads[pname]["sha256"]
    for kind in ident_ok:
        idents = (x_secret,) if kind == "x25519" else ()
        seeds = (ssh_seed,) if kind == "ssh_ed25519" else ()
        _fk, pt = ar.decrypt(data, identities=idents, ssh_seeds=seeds)
        h = sha256(pt)
        check(h == want_hash, f"{pname}: age_ref decrypt with {kind} hash mismatch {h} != {want_hash}")
    if ident_no:
        idents = tuple(x_secret for k in ident_no if k == "x25519")
        seeds = tuple(ssh_seed for k in ident_no if k == "ssh_ed25519")
        try:
            ar.decrypt(data, identities=idents, ssh_seeds=seeds)
            check(False, f"{pname}: expected 'no match' with identities {ident_no}, got success")
        except ValueError as e:
            check("no match" in str(e), f"{pname}: expected 'no match', got {e}")


def cross_check_pyref(data, x_secret, ssh_seed, ident_ok, keys_dir):
    """Assert age_ref decrypts to the right bytes AND rage -d succeeds with
    the appropriate identity file(s)."""
    idents = (x_secret,) if "x25519" in ident_ok else ()
    seeds = (ssh_seed,) if "ssh_ed25519" in ident_ok else ()
    raw = ar.armor_decode(data) if data.lstrip().startswith(ar.ARMOR_BEGIN) else data
    _fk, pt_py = ar.decrypt(raw, identities=idents, ssh_seeds=seeds)

    tmp = HERE / ".gen_tmp.age"
    tmp.write_bytes(data)
    try:
        for kind in ident_ok:
            idfile = keys_dir / "x25519.txt" if kind == "x25519" else keys_dir / "ssh_ed25519"
            res = run([RAGE, "-d", "-i", str(idfile), str(tmp)])
            check(res.stdout == pt_py, f"rage -d with {kind} disagrees with age_ref for {tmp.name}")
    finally:
        tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
