#!/usr/bin/env python3
"""Generator for spacetime-sshsig test vectors (contract §5).

Deterministic: no timestamps, no randomness, fixed seeds. Requires only the
python3 stdlib plus the sibling `ed25519_ref.py` (also stdlib-only), and
`ssh-keygen` on PATH (OpenSSH >= 8.2; developed against OpenSSH_10.2p1) for
the vectors that are produced by the real oracle and for the cross-check
pass. Never invoked by the Rust test suite itself — `tests/vectors.rs` reads
only the committed output of this script.

Run via `./gen.sh` (checks prerequisites and prints the ssh-keygen version)
or directly as `python3 gen.py`. Idempotent: re-running overwrites every
generated file with byte-identical content and re-runs every cross-check.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import ed25519_ref as ref

HERE = Path(__file__).resolve().parent

NS = "spacetime-sshsig-test-v1"
NS_OTHER = "spacetime-sshsig-other-v1"
NS_B = NS.encode()
NS_OTHER_B = NS_OTHER.encode()

FAILURES: list[str] = []
SUMMARY: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"FAIL: {msg}", file=sys.stderr)


def check(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)


# ---------------------------------------------------------------------------
# Seeds, public keys, fingerprints (contract §5.2) — assert against the
# pinned values before doing anything else.
# ---------------------------------------------------------------------------

SEED_A = hashlib.sha256(b"spacetime-sshsig vector key A").digest()
SEED_B = hashlib.sha256(b"spacetime-sshsig vector key B").digest()
SEED_C = hashlib.sha256(b"spacetime-sshsig vector key C").digest()

EXPECT_SEED_A = "a7c884c52f11deb9f8fe0e803ad3229aa7e974dda980afe5aa815b8ee7ce2c65"
EXPECT_SEED_B = "bb6b36fb48b77829b69428f3d7be483e614e6ca5bb0150a05aa5727a1a04e958"
EXPECT_SEED_C = "08d5e9d838e4188e1cf4ff655b18f83b1f402eb5f380a6f724cd9d877003a417"
EXPECT_PK_A = "2f95df718ac66d75efdd62735246def130cb3c8f8e4a818407eeb1271502a5bb"
EXPECT_PK_B = "a240be8bf1dad5a485dd35dcade841d2ca9087b1513afd07dc971b4d6f61bb0d"
EXPECT_PK_C = "b556812f530cfe18c5905526c21122bf3be78b93263d3b44e569e03a94f91bc9"
EXPECT_FP_A = "SHA256:5FxuSKuU4+XupSaJNmRMPpy+07DhkxvYrylShCh0GVM"
EXPECT_FP_B = "SHA256:9QyLndDsouyFRirdn58g4s8u+ogYRpU3rRtE18LnlE8"
EXPECT_FP_C = "SHA256:78wb2B6GDw5YYHb3bz4ntk7FezhZoFkodDoFj5iDh7g"
EXPECT_SHA512_HELLO = (
    "9df41151eda3c4f4b0837ccfbfaffa4e4fed9b4d8c218892925ec8522597ffc"
    "02ffc6dcd60d1e0f0128efdcc1ae8b05ea10bbd5b5c761e4b6c569c7ab2eb6bd0"
)

PK_A = ref.public_key(SEED_A)
PK_B = ref.public_key(SEED_B)
PK_C = ref.public_key(SEED_C)
APPLICATION_C = b"ssh:"

PUBKEY_BLOB_A = ref.ed25519_pubkey_blob(PK_A)
PUBKEY_BLOB_B = ref.ed25519_pubkey_blob(PK_B)
PUBKEY_BLOB_C = ref.sk_ed25519_pubkey_blob(PK_C, APPLICATION_C)

FP_A = ref.fingerprint_sha256(PUBKEY_BLOB_A)
FP_B = ref.fingerprint_sha256(PUBKEY_BLOB_B)
FP_C = ref.fingerprint_sha256(PUBKEY_BLOB_C)

check(SEED_A.hex() == EXPECT_SEED_A, "seed A mismatch")
check(SEED_B.hex() == EXPECT_SEED_B, "seed B mismatch")
check(SEED_C.hex() == EXPECT_SEED_C, "seed C mismatch")
check(PK_A.hex() == EXPECT_PK_A, "public key A mismatch")
check(PK_B.hex() == EXPECT_PK_B, "public key B mismatch")
check(PK_C.hex() == EXPECT_PK_C, "public key C mismatch")
check(FP_A == EXPECT_FP_A, f"fingerprint A mismatch: {FP_A}")
check(FP_B == EXPECT_FP_B, f"fingerprint B mismatch: {FP_B}")
check(FP_C == EXPECT_FP_C, f"fingerprint C mismatch: {FP_C}")

# ---------------------------------------------------------------------------
# Messages.
# ---------------------------------------------------------------------------

MSG_HELLO = b"spacetime-sshsig test message\n"
MSG_EMPTY = b""
MSG_LARGE = b"".join(
    hashlib.sha256(b"spacetime-sshsig large " + i.to_bytes(4, "big")).digest()
    for i in range(8192)
)
check(len(MSG_LARGE) == 262144, f"large.bin wrong length: {len(MSG_LARGE)}")
check(hashlib.sha512(MSG_HELLO).hexdigest() == EXPECT_SHA512_HELLO, "SHA-512(hello) mismatch")


def write_bytes(rel: str, data: bytes) -> Path:
    p = HERE / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


MSG_PATHS = {
    "hello": write_bytes("msgs/hello.txt", MSG_HELLO),
    "empty": write_bytes("msgs/empty.bin", MSG_EMPTY),
    "large": write_bytes("msgs/large.bin", MSG_LARGE),
}
MSG_BYTES = {"hello": MSG_HELLO, "empty": MSG_EMPTY, "large": MSG_LARGE}

# ---------------------------------------------------------------------------
# Key files.
# ---------------------------------------------------------------------------

KEY_A_PATH = write_bytes("keys/a", ref.openssh_key_v1(SEED_A, b"spacetime-sshsig-a"))
KEY_A_PUB_PATH = write_bytes("keys/a.pub", ref.openssh_pub_line(PK_A, b"spacetime-sshsig-a"))
KEY_B_PATH = write_bytes("keys/b", ref.openssh_key_v1(SEED_B, b"spacetime-sshsig-b"))
KEY_B_PUB_PATH = write_bytes("keys/b.pub", ref.openssh_pub_line(PK_B, b"spacetime-sshsig-b"))
KEY_C_PUB_PATH = write_bytes("keys/c.pub", ref.sk_openssh_pub_line(PK_C, APPLICATION_C, b"spacetime-sshsig-c"))

for p in (KEY_A_PATH, KEY_B_PATH):
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — ssh-keygen refuses group/world-readable keys


def check_expected_pub_line(path: Path, expected: str) -> None:
    got = path.read_text().strip()
    check(got == expected, f"{path.name}: public key line mismatch\n  got: {got}\n  want: {expected}")


check_expected_pub_line(
    KEY_A_PUB_PATH,
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC+V33GKxm11791ic1JG3vEwyzyPjkqBhAfusScVAqW7 spacetime-sshsig-a",
)
check_expected_pub_line(
    KEY_B_PUB_PATH,
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKJAvovx2tWkhd013K3oQdLKkIexUTr9B9yXG01vYbsN spacetime-sshsig-b",
)
check_expected_pub_line(
    KEY_C_PUB_PATH,
    "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAILVWgS9TDP4YxZBVJsIRIr8754uTJj07ROVp4DqU+RvJAAAABHNzaDo= spacetime-sshsig-c",
)


# ---------------------------------------------------------------------------
# ssh-keygen oracle helpers.
# ---------------------------------------------------------------------------


def ssh_keygen_sign(key_path: Path, namespace: str, msg_path: Path, extra_opts: list[str] | None = None) -> bytes:
    sig_path = msg_path.with_name(msg_path.name + ".sig")
    if sig_path.exists():
        sig_path.unlink()
    cmd = ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", namespace]
    if extra_opts:
        cmd += extra_opts
    cmd += [str(msg_path)]
    r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if r.returncode != 0 or not sig_path.exists():
        fail(f"ssh-keygen -Y sign failed for {msg_path.name}: {r.returncode}\n{r.stdout}\n{r.stderr}")
        return b""
    data = sig_path.read_bytes()
    sig_path.unlink()
    return data


def ssh_keygen_verify(allowed_signers_line: str, namespace: str, sig_armored: bytes, message: bytes) -> bool:
    """Returns True (accept) / False (reject). None on tool failure is
    treated as reject with a recorded failure."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sshsig-oracle-") as td:
        tdp = Path(td)
        allowed = tdp / "allowed_signers"
        allowed.write_text(allowed_signers_line + "\n")
        sig = tdp / "s.sig"
        sig.write_bytes(sig_armored)
        cmd = [
            "ssh-keygen", "-Y", "verify",
            "-f", str(allowed), "-I", "v", "-n", namespace, "-s", str(sig),
        ]
        r = subprocess.run(cmd, input=message, capture_output=True)
        return r.returncode == 0


def ssh_keygen_verify_ns_refused(namespace: str) -> bool:
    """True iff ssh-keygen -Y sign itself refuses this namespace (used only
    to document why neg_empty_namespace_in_sig has no oracle equivalent)."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sshsig-oracle-") as td:
        tdp = Path(td)
        msg = tdp / "m.txt"
        msg.write_bytes(b"x")
        r = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(KEY_A_PATH), "-n", namespace, str(msg)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
        )
        return r.returncode != 0


check(ssh_keygen_verify_ns_refused(""), "expected ssh-keygen to refuse an empty namespace (-n \"\")")


# ---------------------------------------------------------------------------
# Wire-blob surgery helpers (operate on already-built outer blobs to
# construct the structural negative vectors).
# ---------------------------------------------------------------------------


def parse_outer_raw(blob: bytes) -> dict:
    off = 6
    version, off = ref.read_u32(blob, off)
    pubkey_blob, off = ref.read_string(blob, off)
    namespace, off = ref.read_string(blob, off)
    reserved, off = ref.read_string(blob, off)
    hash_algorithm, off = ref.read_string(blob, off)
    sig_blob, off = ref.read_string(blob, off)
    if off != len(blob):
        raise AssertionError("parse_outer_raw: trailing bytes in well-formed source blob")
    return {
        "version": version,
        "pubkey_blob": pubkey_blob,
        "namespace": namespace,
        "reserved": reserved,
        "hash_algorithm": hash_algorithm,
        "sig_blob": sig_blob,
    }


def build_outer_raw(pubkey_blob: bytes, namespace: bytes, reserved: bytes, hash_algorithm: bytes, sig_blob: bytes, version: int = 1) -> bytes:
    return (
        ref.MAGIC
        + ref.u32(version)
        + ref.sstr(pubkey_blob)
        + ref.sstr(namespace)
        + ref.sstr(reserved)
        + ref.sstr(hash_algorithm)
        + ref.sstr(sig_blob)
    )


def parse_pubkey_blob_raw(blob: bytes) -> tuple[bytes, bytes]:
    """(type, payload) for a 2-field key blob (ssh-ed25519 shape)."""
    typ, off = ref.read_string(blob, 0)
    payload, off = ref.read_string(blob, off)
    return typ, payload


def parse_sig_blob_raw(blob: bytes) -> tuple[bytes, bytes]:
    typ, off = ref.read_string(blob, 0)
    payload, off = ref.read_string(blob, off)
    return typ, payload


def allowed_signers_line_for(pubkey_blob: bytes, embedded_type: bytes) -> str:
    return f"v {embedded_type.decode('ascii', 'replace')} {base64.b64encode(pubkey_blob).decode()}"


# ---------------------------------------------------------------------------
# The honest ssh-ed25519 baseline signature (key A over msgs/hello.txt,
# namespace NS): every synthetic negative vector below is derived from this
# one honest, oracle-produced blob so the corruption is the only variable.
# ---------------------------------------------------------------------------

vectors: list[dict] = []


def rel(p: Path) -> str:
    return str(p.relative_to(HERE)).replace(os.sep, "/")


def sig_path(name: str) -> Path:
    return HERE / "sigs" / f"{name}.sig"


def save_armored(name: str, armored: bytes) -> Path:
    p = sig_path(name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(armored)
    return p


def add_vector(
    name: str,
    kind: str,
    key,
    message: str,
    sig_rel: str,
    expected_namespace: str,
    parse_expect: str,
    verify_expect: str | None,
    ssh_keygen_expect: str,
    allowed_signers_line: str,
    provenance: str,
    require_uv: bool = False,
    deterministic_sign: bool = False,
    also_uv_required: bool = False,
):
    v = {
        "name": name,
        "kind": kind,
        "key": key,
        "message": message,
        "sig": sig_rel,
        "expected_namespace": expected_namespace,
        "policy": {"require_user_verification": require_uv},
        "expect": {"parse": parse_expect, "verify": verify_expect},
        "ssh_keygen": ssh_keygen_expect,
        "allowed_signers_line": allowed_signers_line,
        "provenance": provenance,
    }
    if deterministic_sign:
        v["deterministic_sign"] = True
    if also_uv_required:
        v["also_uv_required"] = True
    vectors.append(v)
    return v


def cross_check(v: dict) -> None:
    """Run the ssh-keygen -Y verify oracle for one vector and assert the
    observed result matches the table (v['ssh_keygen']). Records a
    divergence-table entry summary line either way; fails loudly (never
    silently drops a vector) if the observation disagrees with the manifest."""
    expect = v["ssh_keygen"]
    sig_bytes = (HERE / v["sig"]).read_bytes()
    msg = MSG_BYTES[v["message"]]
    if expect == "n/a":
        SUMMARY.append(f"{v['name']:32s} parse={v['expect']['parse']:24s} verify={str(v['expect']['verify']):26s} ssh-keygen=n/a")
        return
    observed = ssh_keygen_verify(v["allowed_signers_line"], v["expected_namespace"], sig_bytes, msg)
    observed_str = "accept" if observed else "reject"
    SUMMARY.append(f"{v['name']:32s} parse={v['expect']['parse']:24s} verify={str(v['expect']['verify']):26s} ssh-keygen={observed_str}")
    if observed_str != expect:
        fail(
            f"vector {v['name']}: ssh-keygen -Y verify observed {observed_str!r} but manifest/table says {expect!r} "
            f"(this is either a wrong table entry or a changed ssh-keygen behaviour — investigate, do not edit the vector to hide it)"
        )


# ---------------------------------------------------------------------------
# Positive vectors + determinism proof (D9 / R2).
# ---------------------------------------------------------------------------

for name, key_letter, seed, pubkey_blob, msg_key, cmd_path in (
    ("ok_ed25519_hello", "a", SEED_A, PUBKEY_BLOB_A, "hello", KEY_A_PATH),
    ("ok_ed25519_empty", "a", SEED_A, PUBKEY_BLOB_A, "empty", KEY_A_PATH),
    ("ok_ed25519_large", "a", SEED_A, PUBKEY_BLOB_A, "large", KEY_A_PATH),
    ("ok_ed25519_key_b", "b", SEED_B, PUBKEY_BLOB_B, "hello", KEY_B_PATH),
):
    msg_path = MSG_PATHS[msg_key]
    oracle = ssh_keygen_sign(cmd_path, NS, msg_path)
    # Determinism proof: sign a second time and require byte-identical output.
    oracle2 = ssh_keygen_sign(cmd_path, NS, msg_path)
    check(oracle == oracle2, f"{name}: ssh-keygen -Y sign is not deterministic across two runs")
    # Byte-identity against the pure-python reference builder (D9).
    ref_blob = ref.sign_ed25519_sshsig(seed, NS_B, MSG_BYTES[msg_key])
    ref_armored = ref.armor_encode(ref_blob)
    check(ref_armored == oracle, f"{name}: reference builder output differs from ssh-keygen -Y sign output")
    save_armored(name, oracle)
    msg_filename = {"hello": "hello.txt", "empty": "empty.bin", "large": "large.bin"}[msg_key]
    add_vector(
        name, "positive", key_letter, msg_key, f"sigs/{name}.sig", NS,
        parse_expect="ok", verify_expect="ok", ssh_keygen_expect="accept",
        allowed_signers_line=allowed_signers_line_for(pubkey_blob, b"ssh-ed25519"),
        provenance=f"ssh-keygen -Y sign -f keys/{key_letter} -n {NS} msgs/{msg_filename}",
        deterministic_sign=True,
    )

ok_hello_armored = (HERE / "sigs/ok_ed25519_hello.sig").read_bytes()
ok_hello_raw = ref.sign_ed25519_sshsig(SEED_A, NS_B, MSG_HELLO)  # proven byte-identical above
ok_hello_parts = parse_outer_raw(ok_hello_raw)
HONEST_SIG64 = parse_sig_blob_raw(ok_hello_parts["sig_blob"])[1]
HONEST_R = HONEST_SIG64[:32]
HONEST_S = HONEST_SIG64[32:64]
HONEST_S_INT = int.from_bytes(HONEST_S, "little")
HONEST_SIGNED_DATA = ref.signed_data(NS_B, b"", b"sha512", hashlib.sha512(MSG_HELLO).digest())

# ok_armor_76_cols: re-armor the honest blob at 76 columns.
armored_76 = ref.armor_encode(ok_hello_raw, line_len=76)
save_armored("ok_armor_76_cols", armored_76)
add_vector(
    "ok_armor_76_cols", "positive", "a", "hello", "sigs/ok_armor_76_cols.sig", NS,
    parse_expect="ok", verify_expect="ok", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="re-armor of sigs/ok_ed25519_hello.sig's blob at 76-column lines (PROTOCOL.sshsig max line width)",
)

# ok_armor_no_final_newline: strip the trailing \n.
no_nl = ok_hello_armored[:-1] if ok_hello_armored.endswith(b"\n") else ok_hello_armored
check(not no_nl.endswith(b"\n"), "ok_armor_no_final_newline: source did not end with a newline")
save_armored("ok_armor_no_final_newline", no_nl)
add_vector(
    "ok_armor_no_final_newline", "positive", "a", "hello", "sigs/ok_armor_no_final_newline.sig", NS,
    parse_expect="ok", verify_expect="ok", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="sigs/ok_ed25519_hello.sig with the final trailing newline after the END footer removed",
)


# ---------------------------------------------------------------------------
# sk-ssh-ed25519@openssh.com vectors (synthetic; D3, verify-only).
# ---------------------------------------------------------------------------


def build_sk_blob(application: bytes, flags: int, counter: int, signed: bytes, key_application_in_blob: bytes | None = None) -> tuple[bytes, bytes]:
    """Returns (raw_blob, sig64). `application` is what actually enters the
    Ed25519 message; `key_application_in_blob` (default = application) is
    what the public-key blob claims — letting neg_sk_wrong_application make
    them differ."""
    if key_application_in_blob is None:
        key_application_in_blob = application
    sk_msg = ref.sk_message(application, flags, counter, signed)
    sig64 = ref.sign(SEED_C, sk_msg)
    pk_blob = ref.sk_ed25519_pubkey_blob(PK_C, key_application_in_blob)
    sig_blob = ref.sk_ed25519_sig_blob(sig64, flags, counter)
    raw = ref.sshsig_blob(pk_blob, NS_B, b"", b"sha512", sig_blob)
    check(
        ref.verify_strict(PK_C, sk_msg, sig64),
        f"sk vector (flags={flags:#x} counter={counter}): reference strict verifier rejected an honestly-built signature",
    )
    return raw, sig64


sk_up_raw, _ = build_sk_blob(APPLICATION_C, 0x01, 7, HONEST_SIGNED_DATA)
save_armored("ok_sk_up", ref.armor_encode(sk_up_raw))
add_vector(
    "ok_sk_up", "positive", "c", "hello", "sigs/ok_sk_up.sig", NS,
    parse_expect="ok", verify_expect="ok", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_C, b"sk-ssh-ed25519@openssh.com"),
    provenance="synthetic: sk-ssh-ed25519@openssh.com, key C, application 'ssh:', flags=0x01 (UP), counter=7; "
    "Ed25519 signature computed by ed25519_ref.sign(seed_C, SHA256(application)||flags||counter_be32||SHA256(signed_data))",
)

sk_up_uv_raw, _ = build_sk_blob(APPLICATION_C, 0x05, 8, HONEST_SIGNED_DATA)
save_armored("ok_sk_up_uv", ref.armor_encode(sk_up_uv_raw))
add_vector(
    "ok_sk_up_uv", "positive", "c", "hello", "sigs/ok_sk_up_uv.sig", NS,
    parse_expect="ok", verify_expect="ok", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_C, b"sk-ssh-ed25519@openssh.com"),
    provenance="synthetic: as ok_sk_up but flags=0x05 (UP|UV), counter=8 — valid under both SkPolicy settings",
    also_uv_required=True,
)

add_vector(
    "neg_sk_uv_missing", "negative", "c", "hello", "sigs/ok_sk_up.sig", NS,
    parse_expect="ok", verify_expect="SkUserVerificationMissing", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_C, b"sk-ssh-ed25519@openssh.com"),
    provenance="reuses sigs/ok_sk_up.sig (flags=0x01, no UV) verified under SkPolicy{require_user_verification:true}",
    require_uv=True,
)

sk_flags_zero_raw, _ = build_sk_blob(APPLICATION_C, 0x00, 42, HONEST_SIGNED_DATA)
save_armored("neg_sk_flags_zero", ref.armor_encode(sk_flags_zero_raw))
add_vector(
    "neg_sk_flags_zero", "negative", "c", "hello", "sigs/neg_sk_flags_zero.sig", NS,
    parse_expect="ok", verify_expect="SkUserPresenceMissing", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_C, b"sk-ssh-ed25519@openssh.com"),
    provenance="synthetic: as ok_sk_up but flags=0x00 (neither UP nor UV), counter=42",
)

sk_wrong_app_raw, _ = build_sk_blob(b"ssh:other", 0x01, 2, HONEST_SIGNED_DATA, key_application_in_blob=APPLICATION_C)
save_armored("neg_sk_wrong_application", ref.armor_encode(sk_wrong_app_raw))
add_vector(
    "neg_sk_wrong_application", "negative", "c", "hello", "sigs/neg_sk_wrong_application.sig", NS,
    parse_expect="ok", verify_expect="SignatureInvalid", ssh_keygen_expect="reject",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_C, b"sk-ssh-ed25519@openssh.com"),
    provenance="synthetic: key blob declares application 'ssh:' but the inner Ed25519 message was built over "
    "SHA256(b'ssh:other') instead of SHA256(b'ssh:') — flags=0x01, counter=2",
)


# ---------------------------------------------------------------------------
# Strict-Ed25519 negative vectors (V8-V13): derived from the honest (R, S)
# and A of ok_ed25519_hello, or from the special point encodings.
# ---------------------------------------------------------------------------


def sig64(r: bytes, s_int: int) -> bytes:
    s_bytes = s_int.to_bytes(32, "little")
    return r + s_bytes


def build_ed25519_negative(name: str, key: str | None, pubkey_blob: bytes, embedded_type: bytes, sig: bytes, ssh_keygen_expect: str, provenance: str):
    raw = ref.sshsig_blob(pubkey_blob, NS_B, b"", b"sha512", ref.ed25519_sig_blob(sig))
    save_armored(name, ref.armor_encode(raw))
    add_vector(
        name, "negative", key, "hello", f"sigs/{name}.sig", NS,
        parse_expect="ok", verify_expect="SignatureInvalid", ssh_keygen_expect=ssh_keygen_expect,
        allowed_signers_line=allowed_signers_line_for(pubkey_blob, embedded_type),
        provenance=provenance,
    )


build_ed25519_negative(
    "neg_s_plus_l", "a", PUBKEY_BLOB_A, b"ssh-ed25519",
    sig64(HONEST_R, HONEST_S_INT + ref.L),
    "accept",
    "honest (R,A) of ok_ed25519_hello; S := S + L (little-endian 32-byte int) — passes the naive curve equation "
    "mod L but fails a strict S < L check",
)
build_ed25519_negative(
    "neg_s_zero", "a", PUBKEY_BLOB_A, b"ssh-ed25519",
    sig64(HONEST_R, 0),
    "reject",
    "honest R and A of ok_ed25519_hello; S forged to 0 (an ordinary invalid signature)",
)
build_ed25519_negative(
    "neg_small_order_a", None, ref.ed25519_pubkey_blob(ref.IDENTITY_ENCODING), b"ssh-ed25519",
    sig64(ref.IDENTITY_ENCODING, 0),
    "accept",
    "universal identity forgery: A := identity encoding (01 00...00), R := identity encoding, S := 0 — "
    "0*B == identity == R + 0*A holds trivially; rejected only by an explicit small-order check on A",
)
build_ed25519_negative(
    "neg_small_order_r", "a", PUBKEY_BLOB_A, b"ssh-ed25519",
    sig64(ref.ORDER4_ENCODING, 0),
    "reject",
    "honest A of key a; R := order-4 encoding (32 zero bytes, [8]R == identity but R != identity), S := 0",
)
build_ed25519_negative(
    "neg_noncanonical_a", None, ref.ed25519_pubkey_blob(ref.NONCANONICAL_IDENTITY_ENCODING), b"ssh-ed25519",
    sig64(ref.IDENTITY_ENCODING, 0),
    "accept",
    "A := non-canonical encoding of the identity (y = p+1, i.e. ee ff*30 7f little-endian), R := identity "
    "encoding, S := 0. Verified fact (this machine, OpenSSH_10.2p1/OpenSSL 3.5.8): ssh-keygen -Y verify "
    "ACCEPTS this — the contract's table (V12) anticipated 'reject' by analogy with an honest-signature "
    "non-canonical-A test, but this specific construction reduces A to the identity by mod-p reduction "
    "before the curve check, landing in the same universal-forgery class as neg_small_order_a (V10, also "
    "'accept'); a non-canonical encoding of a genuine large-order point paired with an otherwise-honest "
    "signature would behave differently, but the contract's construction (§5.2/§5.4) pins this exact "
    "identity-based encoding. Documented as an additional, empirically-confirmed divergence beyond §9.3.",
)
build_ed25519_negative(
    "neg_noncanonical_r", "a", PUBKEY_BLOB_A, b"ssh-ed25519",
    sig64(ref.NONCANONICAL_IDENTITY_ENCODING, 0),
    "reject",
    "honest A of key a; R := non-canonical encoding of the identity (y = p+1), S := 0",
)

# neg_wrong_message: reuses ok_ed25519_hello.sig verified against msgs/empty.bin.
add_vector(
    "neg_wrong_message", "negative", "a", "empty", "sigs/ok_ed25519_hello.sig", NS,
    parse_expect="ok", verify_expect="SignatureInvalid", ssh_keygen_expect="reject",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="reuses sigs/ok_ed25519_hello.sig (signed over msgs/hello.txt) but verified against msgs/empty.bin",
)


# ---------------------------------------------------------------------------
# Predicate negatives that don't touch curve math: reserved, hash_algorithm,
# namespace, signer.
# ---------------------------------------------------------------------------

# neg_reserved_nonempty: same honest signature (made over reserved=""), but
# the outer blob's reserved field is patched to "x" — verify must reject
# (ReservedNotEmpty) before ever reaching the signature check.
reserved_raw = build_outer_raw(ok_hello_parts["pubkey_blob"], NS_B, b"x", b"sha512", ok_hello_parts["sig_blob"])
save_armored("neg_reserved_nonempty", ref.armor_encode(reserved_raw))
add_vector(
    "neg_reserved_nonempty", "negative", "a", "hello", "sigs/neg_reserved_nonempty.sig", NS,
    parse_expect="ok", verify_expect="ReservedNotEmpty", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="sigs/ok_ed25519_hello.sig's blob with the outer reserved field patched to b'x' "
    "(the Ed25519 signature itself is untouched, still made over reserved=\"\")",
)

# neg_hash_sha256: direct oracle output with -O hashalg=sha256.
sha256_oracle = ssh_keygen_sign(KEY_A_PATH, NS, MSG_PATHS["hello"], extra_opts=["-O", "hashalg=sha256"])
save_armored("neg_hash_sha256", sha256_oracle)
add_vector(
    "neg_hash_sha256", "negative", "a", "hello", "sigs/neg_hash_sha256.sig", NS,
    parse_expect="ok", verify_expect="HashAlgorithmNotSha512", ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="ssh-keygen -Y sign -O hashalg=sha256 -f keys/a -n spacetime-sshsig-test-v1 msgs/hello.txt",
)

# neg_wrong_namespace: signed under NS_OTHER, verified against NS.
wrong_ns_oracle = ssh_keygen_sign(KEY_A_PATH, NS_OTHER, MSG_PATHS["hello"])
save_armored("neg_wrong_namespace", wrong_ns_oracle)
add_vector(
    "neg_wrong_namespace", "negative", "a", "hello", "sigs/neg_wrong_namespace.sig", NS,
    parse_expect="ok", verify_expect="NamespaceMismatch", ssh_keygen_expect="reject",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance=f"ssh-keygen -Y sign -f keys/a -n {NS_OTHER} msgs/hello.txt; verified with expected namespace {NS}",
)

# neg_empty_namespace_in_sig: fully honest signature made over namespace "".
empty_ns_raw = ref.sign_ed25519_sshsig(SEED_A, b"", MSG_HELLO)
save_armored("neg_empty_namespace_in_sig", ref.armor_encode(empty_ns_raw))
add_vector(
    "neg_empty_namespace_in_sig", "negative", "a", "hello", "sigs/neg_empty_namespace_in_sig.sig", NS,
    parse_expect="ok", verify_expect="NamespaceMismatch", ssh_keygen_expect="n/a",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="synthetic (ed25519_ref only): honest ssh-ed25519 signature by key a over msgs/hello.txt with "
    "blob namespace == \"\"; ssh-keygen -Y sign refuses -n \"\" (verified: exit != 0), hence no oracle equivalent "
    "for this specific construction — recorded n/a per contract",
)

# neg_signer_mismatch: reuses ok_ed25519_hello.sig (signed by a), expected signer b.
add_vector(
    "neg_signer_mismatch", "negative", "b", "hello", "sigs/ok_ed25519_hello.sig", NS,
    parse_expect="ok", verify_expect="SignerMismatch", ssh_keygen_expect="reject",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_B, b"ssh-ed25519"),
    provenance="reuses sigs/ok_ed25519_hello.sig (embedded key a) with expected signer key b; ssh-keygen "
    "cross-check uses -I for a principal whose allowed_signers key is b, which does not match the embedded key a",
)


# ---------------------------------------------------------------------------
# Structural parse-stage negatives (P1-P11): built from the honest outer
# blob by wire-level surgery, then re-armored.
# ---------------------------------------------------------------------------


def build_parse_negative(
    name: str,
    key,
    parse_expect: str,
    raw_blob: bytes,
    ssh_keygen_expect: str,
    provenance: str,
    embedded_pubkey_blob: bytes | None = None,
    embedded_type: bytes = b"ssh-ed25519",
):
    save_armored(name, ref.armor_encode(raw_blob))
    epb = embedded_pubkey_blob if embedded_pubkey_blob is not None else PUBKEY_BLOB_A
    add_vector(
        name, "negative", key, "hello", f"sigs/{name}.sig", NS,
        parse_expect=parse_expect, verify_expect=None, ssh_keygen_expect=ssh_keygen_expect,
        allowed_signers_line=allowed_signers_line_for(epb, embedded_type),
        provenance=provenance,
    )


# P2: version 2.
v2_raw = build_outer_raw(ok_hello_parts["pubkey_blob"], NS_B, b"", b"sha512", ok_hello_parts["sig_blob"], version=2)
build_parse_negative("neg_version_2", "a", "UnsupportedVersion", v2_raw, "reject", "outer version field patched from 1 to 2")

# P1: bad magic.
bad_magic_raw = b"SSHSIH" + ok_hello_raw[6:]
build_parse_negative("neg_bad_magic", "a", "BadMagic", bad_magic_raw, "reject", "outer magic patched from b'SSHSIG' to b'SSHSIH'")

# P3: truncated (last 10 bytes dropped).
trunc_raw = ok_hello_raw[:-10]
build_parse_negative("neg_truncated_blob", "a", "Truncated", trunc_raw, "reject", "last 10 bytes of the honest blob dropped")

# P4: trailing bytes after outer fields.
trailing_outer_raw = ok_hello_raw + b"\x00"
build_parse_negative("neg_trailing_outer", "a", "TrailingBytes(Outer)", trailing_outer_raw, "reject", "a single 0x00 byte appended after the well-formed outer blob")

# P5: trailing bytes inside the public-key blob (outer length auto-updates via sstr()).
trailing_key_pubkey_blob = ok_hello_parts["pubkey_blob"] + b"\x00"
trailing_key_raw = build_outer_raw(trailing_key_pubkey_blob, NS_B, b"", b"sha512", ok_hello_parts["sig_blob"])
build_parse_negative(
    "neg_trailing_key_blob", "a", "TrailingBytes(PublicKey)", trailing_key_raw, "reject",
    "a single 0x00 byte appended to the well-formed key blob payload (type+key); the outer \"string publickey\" "
    "length prefix is updated to include it",
    embedded_pubkey_blob=trailing_key_pubkey_blob,
)

# P6: trailing bytes inside the signature blob.
trailing_sig_sig_blob = ok_hello_parts["sig_blob"] + b"\x00"
trailing_sig_raw = build_outer_raw(ok_hello_parts["pubkey_blob"], NS_B, b"", b"sha512", trailing_sig_sig_blob)
build_parse_negative(
    "neg_trailing_sig_blob", "a", "TrailingBytes(Signature)", trailing_sig_raw, "reject",
    "a single 0x00 byte appended to the well-formed signature blob payload (type+sig); the outer \"string "
    "signature\" length prefix is updated to include it",
)

# P7: unknown key type — ssh-rsa.
_, key_payload_a = parse_pubkey_blob_raw(ok_hello_parts["pubkey_blob"])
rsa_pubkey_blob = ref.sstr(b"ssh-rsa") + ref.sstr(key_payload_a)
rsa_raw = build_outer_raw(rsa_pubkey_blob, NS_B, b"", b"sha512", ok_hello_parts["sig_blob"])
build_parse_negative(
    "neg_key_type_rsa", None, "UnknownKeyType", rsa_raw, "reject",
    "key blob type string replaced with b'ssh-rsa' (payload, the 32-byte value, unchanged)",
    embedded_pubkey_blob=rsa_pubkey_blob, embedded_type=b"ssh-rsa",
)

# P7: unknown key type — cert.
cert_pubkey_blob = ref.sstr(b"ssh-ed25519-cert-v01@openssh.com") + ref.sstr(key_payload_a)
cert_raw = build_outer_raw(cert_pubkey_blob, NS_B, b"", b"sha512", ok_hello_parts["sig_blob"])
build_parse_negative(
    "neg_key_type_cert", None, "UnknownKeyType", cert_raw, "reject",
    "key blob type string replaced with b'ssh-ed25519-cert-v01@openssh.com' (payload unchanged)",
    embedded_pubkey_blob=cert_pubkey_blob, embedded_type=b"ssh-ed25519-cert-v01@openssh.com",
)

# P8: unknown signature type.
_, sig_payload_a = parse_sig_blob_raw(ok_hello_parts["sig_blob"])
rsa_sig_blob = ref.sstr(b"ssh-rsa") + ref.sstr(sig_payload_a)
sig_type_raw = build_outer_raw(ok_hello_parts["pubkey_blob"], NS_B, b"", b"sha512", rsa_sig_blob)
build_parse_negative("neg_sig_type_unknown", "a", "UnknownSignatureType", sig_type_raw, "reject", "signature blob type string replaced with b'ssh-rsa' (payload unchanged)")

# P9: key family != sig family (ssh-ed25519 key, sk-layout signature).
sk_layout_sig_blob = ref.sk_ed25519_sig_blob(sig_payload_a, 1, 1)
sig_mismatch_raw = build_outer_raw(ok_hello_parts["pubkey_blob"], NS_B, b"", b"sha512", sk_layout_sig_blob)
build_parse_negative(
    "neg_sig_type_mismatch", "a", "KeyTypeMismatch", sig_mismatch_raw, "reject",
    "key blob is plain ssh-ed25519 (key a); signature blob rewritten into sk-ssh-ed25519@openssh.com layout "
    "(same 64-byte sig payload, flags=0x01, counter=1)",
)

# P10: key string 31 bytes.
short_key_blob = ref.sstr(b"ssh-ed25519") + ref.sstr(key_payload_a[:31])
short_key_raw = build_outer_raw(short_key_blob, NS_B, b"", b"sha512", ok_hello_parts["sig_blob"])
build_parse_negative(
    "neg_key_len_31", None, "BadKeyLength", short_key_raw, "reject", "key string payload truncated to 31 bytes",
    embedded_pubkey_blob=short_key_blob,
)

# P11: sig string 63 bytes.
short_sig_blob = ref.sstr(b"ssh-ed25519") + ref.sstr(sig_payload_a[:63])
short_sig_raw = build_outer_raw(ok_hello_parts["pubkey_blob"], NS_B, b"", b"sha512", short_sig_blob)
build_parse_negative("neg_sig_len_63", "a", "BadSignatureLength", short_sig_raw, "reject", "signature string payload truncated to 63 bytes")


# ---------------------------------------------------------------------------
# Armor-grammar negatives (A1-A5).
# ---------------------------------------------------------------------------

hello_text = ok_hello_armored.decode("ascii")
hello_lines = hello_text.splitlines(keepends=True)
check(hello_lines[0].rstrip("\n") == "-----BEGIN SSH SIGNATURE-----", "ok_ed25519_hello.sig: unexpected header line")
check(hello_lines[-1].rstrip("\n") == "-----END SSH SIGNATURE-----", "ok_ed25519_hello.sig: unexpected footer line")

# A3: whole base64 on one line (> 76 chars).
one_line_armored = ref.armor_encode(ok_hello_raw, line_len=10_000)
save_armored("neg_armor_line_too_long", one_line_armored)
add_vector(
    "neg_armor_line_too_long", "negative", "a", "hello", "sigs/neg_armor_line_too_long.sig", NS,
    parse_expect="ArmorLineTooLong", verify_expect=None, ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="sigs/ok_ed25519_hello.sig's blob re-armored with the entire base64 payload on a single line "
    "(well over the 76-character limit)",
)

# A4: one '*' substituted into line 2 (first base64 line after the header).
bad_b64_lines = list(hello_lines)
line2 = bad_b64_lines[1]
check(len(line2.rstrip("\n")) > 0, "ok_ed25519_hello.sig: line 2 unexpectedly empty")
bad_b64_lines[1] = "*" + line2[1:]
bad_b64_text = "".join(bad_b64_lines)
save_armored("neg_armor_bad_base64", bad_b64_text.encode("ascii"))
add_vector(
    "neg_armor_bad_base64", "negative", "a", "hello", "sigs/neg_armor_bad_base64.sig", NS,
    parse_expect="ArmorBadBase64", verify_expect=None, ssh_keygen_expect="reject",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="sigs/ok_ed25519_hello.sig with the first character of the second line replaced by '*'",
)

# A2: footer line removed.
no_footer_lines = [l for l in hello_lines if l.rstrip("\n") != "-----END SSH SIGNATURE-----"]
save_armored("neg_armor_missing_end", "".join(no_footer_lines).encode("ascii"))
add_vector(
    "neg_armor_missing_end", "negative", "a", "hello", "sigs/neg_armor_missing_end.sig", NS,
    parse_expect="ArmorMissingFooter", verify_expect=None, ssh_keygen_expect="reject",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="sigs/ok_ed25519_hello.sig with the '-----END SSH SIGNATURE-----' line removed",
)

# A1: header line removed.
no_header_lines = [l for l in hello_lines if l.rstrip("\n") != "-----BEGIN SSH SIGNATURE-----"]
save_armored("neg_armor_missing_begin", "".join(no_header_lines).encode("ascii"))
add_vector(
    "neg_armor_missing_begin", "negative", "a", "hello", "sigs/neg_armor_missing_begin.sig", NS,
    parse_expect="ArmorMissingHeader", verify_expect=None, ssh_keygen_expect="reject",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="sigs/ok_ed25519_hello.sig with the '-----BEGIN SSH SIGNATURE-----' line removed",
)

# A5: trailing text after the footer.
trailing_text = ok_hello_armored + b"junk\n"
save_armored("neg_armor_trailing_text", trailing_text)
add_vector(
    "neg_armor_trailing_text", "negative", "a", "hello", "sigs/neg_armor_trailing_text.sig", NS,
    parse_expect="ArmorTrailingData", verify_expect=None, ssh_keygen_expect="accept",
    allowed_signers_line=allowed_signers_line_for(PUBKEY_BLOB_A, b"ssh-ed25519"),
    provenance="sigs/ok_ed25519_hello.sig with the text 'junk\\n' appended after the footer line",
)


# ---------------------------------------------------------------------------
# allowed_signers fixture (contract §5.5).
# ---------------------------------------------------------------------------

B64_A = base64.b64encode(PUBKEY_BLOB_A).decode()
B64_B = base64.b64encode(PUBKEY_BLOB_B).decode()
B64_C = base64.b64encode(PUBKEY_BLOB_C).decode()

ALLOWED_SIGNERS_TEXT = (
    "# spacetime-sshsig allowed_signers fixture\n"
    "\n"
    f"alice ssh-ed25519 {B64_A} spacetime-sshsig-a\n"
    f'bob,carol namespaces="spacetime-sshsig-test-v1,spacetime-sshsig-other-v1" ssh-ed25519 {B64_B} two principals\n'
    # Option values are always double-quoted: ssh-keygen's sshsigopt_parse (opt_dequote) rejects an
    # unquoted value with "bad options: missing start quote" (verified, OpenSSH_10.2p1), and so does
    # the crate.
    f'root cert-authority,valid-after="20260101Z",valid-before="20301231235959Z" ssh-ed25519 {B64_A}\n'
    f'\tsk1 namespaces="spacetime-sshsig-test-v1" sk-ssh-ed25519@openssh.com {B64_C} yubikey\n'
)
ALLOWED_SIGNERS_PATH = write_bytes("allowed_signers", ALLOWED_SIGNERS_TEXT.encode("ascii"))

ALLOWED_SIGNERS_ENTRIES = [
    {
        "line": 3, "principals": ["alice"], "cert_authority": False, "namespaces": None,
        "valid_after": None, "valid_before": None, "key": "a", "comment": "spacetime-sshsig-a",
    },
    {
        "line": 4, "principals": ["bob", "carol"], "cert_authority": False,
        "namespaces": ["spacetime-sshsig-test-v1", "spacetime-sshsig-other-v1"],
        "valid_after": None, "valid_before": None, "key": "b", "comment": "two principals",
    },
    {
        "line": 5, "principals": ["root"], "cert_authority": True, "namespaces": None,
        "valid_after": "20260101Z", "valid_before": "20301231235959Z", "key": "a", "comment": None,
    },
    {
        "line": 6, "principals": ["sk1"], "cert_authority": False,
        "namespaces": ["spacetime-sshsig-test-v1"],
        "valid_after": None, "valid_before": None, "key": "c", "comment": "yubikey",
    },
]

ALLOWED_SIGNERS_BAD_LINES = [
    {"line": f"dave foo=1 ssh-ed25519 {B64_A}", "expect": "AllowedSignersUnknownOption"},
    {"line": "dave ssh-rsa AAAAB3NzaC1yc2E=", "expect": "UnknownKeyType"},
    {"line": "dave", "expect": "AllowedSignersLineInvalid"},
    {"line": f'dave namespaces="x ssh-ed25519 {B64_A}', "expect": "AllowedSignersLineInvalid"},
    # Unquoted option value: ssh-keygen says "missing start quote"; the crate must not be laxer.
    {"line": f"dave namespaces=spacetime-sshsig-test-v1 ssh-ed25519 {B64_A}", "expect": "AllowedSignersLineInvalid"},
    # ssh-keygen pattern syntax (negation / glob) is unsupported and rejected, never matched literally.
    {"line": f"dave,!dave ssh-ed25519 {B64_A}", "expect": "AllowedSignersLineInvalid"},
    {"line": f'* namespaces="git" ssh-ed25519 {B64_A}', "expect": "AllowedSignersLineInvalid"},
    {"line": f"dave ssh-ed25519 {B64_B}", "expect_decode": "ok"},
    {"line": f"dave sk-ssh-ed25519@openssh.com {B64_A}", "expect_decode": "PublicKeyTypeMismatch"},
]

# gen.py-side cross-check of allowed_signers line 3 / line 5 (alice, root)
# via `ssh-keygen -Y find-principals` (recorded in README, not asserted by
# Rust — contract §5.5).
fp_result = subprocess.run(
    ["ssh-keygen", "-Y", "find-principals", "-s", str(sig_path("ok_ed25519_hello")), "-f", str(ALLOWED_SIGNERS_PATH)],
    capture_output=True, text=True,
)
FIND_PRINCIPALS_OUTPUT = fp_result.stdout.strip()
principals_found = set(FIND_PRINCIPALS_OUTPUT.split())
# Verified fact (this machine, OpenSSH_10.2p1): `-Y find-principals` reports only "alice", not "root",
# even though both allowed_signers lines carry key a. A `cert-authority` entry is for verifying
# certificates signed by that key, not for matching a plain (non-certificate) SSHSIG signature made
# directly with the key — so it is correctly excluded here. This was not anticipated by the contract
# (§5.5 says "must print alice and root"); documented as an observed-behaviour correction below.
check(
    principals_found == {"alice"},
    f"ssh-keygen -Y find-principals: expected exactly {{'alice'}} (root's cert-authority entry does not "
    f"match a plain-key signature), got {FIND_PRINCIPALS_OUTPUT!r} (stderr: {fp_result.stderr!r})",
)


# ---------------------------------------------------------------------------
# Cross-check every vector with ssh-keygen -Y verify.
# ---------------------------------------------------------------------------

for v in vectors:
    cross_check(v)


# ---------------------------------------------------------------------------
# manifest.json
# ---------------------------------------------------------------------------

# `ssh -V` reliably prints "OpenSSH_X.Yp1, OpenSSL ..." to stderr regardless
# of arguments; `ssh-keygen -V` (no argument) only prints a usage error.
try:
    ssh_v = subprocess.run(["ssh", "-V"], capture_output=True, text=True)
    ssh_keygen_version = (ssh_v.stderr or ssh_v.stdout).strip() or "unknown"
except FileNotFoundError:
    ssh_keygen_version = "unknown"

manifest = {
    "schema": 1,
    "generator": f"gen.sh -> gen.py (python3, stdlib) + ed25519_ref.py; ssh-keygen {ssh_keygen_version} for provenance 'ssh-keygen: ...'",
    "namespace": NS,
    "other_namespace": NS_OTHER,
    "keys": {
        "a": {
            "type": "ssh-ed25519", "seed_hex": SEED_A.hex(), "public_key_hex": PK_A.hex(),
            "private_file": "keys/a", "public_file": "keys/a.pub", "fingerprint": FP_A,
        },
        "b": {
            "type": "ssh-ed25519", "seed_hex": SEED_B.hex(), "public_key_hex": PK_B.hex(),
            "private_file": "keys/b", "public_file": "keys/b.pub", "fingerprint": FP_B,
        },
        "c": {
            "type": "sk-ssh-ed25519@openssh.com", "application": APPLICATION_C.decode(),
            "seed_hex": SEED_C.hex(), "public_key_hex": PK_C.hex(),
            "public_file": "keys/c.pub", "fingerprint": FP_C,
        },
    },
    "messages": {"hello": "msgs/hello.txt", "empty": "msgs/empty.bin", "large": "msgs/large.bin"},
    "vectors": vectors,
    "allowed_signers": {
        "file": "allowed_signers",
        "entries": ALLOWED_SIGNERS_ENTRIES,
        "bad_lines": ALLOWED_SIGNERS_BAD_LINES,
        "find_principals_check": {
            "command": "ssh-keygen -Y find-principals -s sigs/ok_ed25519_hello.sig -f allowed_signers",
            "observed": FIND_PRINCIPALS_OUTPUT,
            "expect": ["alice"],
            "note": "root's cert-authority entry (same key a) does not match a plain-key signature via "
            "find-principals; verified on this machine, OpenSSH_10.2p1 (contract §5.5 anticipated 'root' "
            "too — documented divergence from that expectation).",
        },
    },
}

manifest_path = HERE / "manifest.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")

# Idempotency check: re-serializing must be byte-identical (guards against
# any accidental nondeterminism, e.g. dict ordering or float formatting).
reserialized = json.dumps(json.loads(manifest_path.read_text()), indent=2, sort_keys=False) + "\n"
check(reserialized == manifest_path.read_text(), "manifest.json is not stably round-trippable through json.dumps")


# ---------------------------------------------------------------------------
# Summary + exit status.
# ---------------------------------------------------------------------------

print("\n".join(SUMMARY))
print(f"\n{len(vectors)} vectors written ({sum(1 for v in vectors if v['kind']=='positive')} positive, "
      f"{sum(1 for v in vectors if v['kind']=='negative')} negative)")
print(f"manifest: {rel(manifest_path)}")
print(f"determinism seed (key a, hex): {SEED_A.hex()}")

if FAILURES:
    print(f"\n{len(FAILURES)} FAILURE(S):", file=sys.stderr)
    for f in FAILURES:
        print(f"  - {f}", file=sys.stderr)
    sys.exit(1)

print("\nOK: all assertions passed, all ssh-keygen cross-checks match the manifest table.")
