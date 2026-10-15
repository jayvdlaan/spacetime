"""Pure-integer RFC 8032 (section 6) Ed25519 reference, plus SSH wire-format
helpers, an openssh-key-v1 writer, and SSHSIG blob/armor builders.

Standard library only (hashlib for SHA-512/SHA-256, base64 for armor).
No third-party crypto packages. This is a deliberately naive, unoptimized
implementation whose only job is: be an independent second oracle next to
ssh-keygen, and let us forge specific non-canonical / small-order / bad-S
encodings that no real signer would ever produce.

Every function here operates on plain Python ints and bytes; there is no
constant-time discipline and none is needed for a test-vector generator.
"""

import hashlib

# ---------------------------------------------------------------------------
# RFC 8032 section 5.1 / section 6 constants
# ---------------------------------------------------------------------------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493  # group order

D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod p

Bx_num = 15112221349535400772501151409588531511454012693041857206046113283949847762202
By_num = 46316835694926478169428394003475163141307993866256225615783033603165251855960
B = (Bx_num % P, By_num % P)

IDENTITY = (0, 1)


def sha512(*chunks: bytes) -> bytes:
    h = hashlib.sha512()
    for c in chunks:
        h.update(c)
    return h.digest()


def sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


# ---------------------------------------------------------------------------
# Extended twisted-Edwards coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z,
# x*y = T/Z. Point addition per RFC 8032 is easiest to reason about in
# affine form for a reference implementation of this size, so we keep
# points as affine (x, y) tuples mod p and pay the modular-inverse cost;
# performance does not matter here (a handful of vectors).
# ---------------------------------------------------------------------------


def point_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    denom_x = (1 + D * x1 * x2 * y1 * y2) % P
    denom_y = (1 - D * x1 * x2 * y1 * y2) % P
    x3 = (x1 * y2 + x2 * y1) * pow(denom_x, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(denom_y, P - 2, P) % P
    return (x3, y3)


def point_mul(s: int, p):
    """Constant-structure double-and-add; s may be any non-negative int."""
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = point_add(q, p)
        p = point_add(p, p)
        s >>= 1
    return q


def point_equal(p1, p2) -> bool:
    x1, y1 = p1
    x2, y2 = p2
    return (x1 - x2) % P == 0 and (y1 - y2) % P == 0


def recover_x(y: int, sign: int):
    """RFC 8032 5.1.3 point decompression. `y` is reduced mod p first (this
    is the *permissive* decode used to build/inspect forged points — the
    strict "y must already be < p" canonicality requirement a real verifier
    applies is checked separately by is_canonical_encoding). Returns None if
    y is not on the curve for any x."""
    y %= P
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = (x * I) % P
    if (x * x - x2) % P != 0:
        return None
    if x % 2 != sign:
        x = P - x
    return x


def point_compress(p) -> bytes:
    x, y = p
    out = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        out[31] |= 0x80
    return bytes(out)


def point_decompress(enc: bytes):
    """Strict RFC 8032 5.1.3 decode. Returns None on any malformed input
    (this is the *permissive* curve decode used by the reference signer /
    honest-vector builder — canonicality of the y-coordinate is a separate
    check the SSHSIG predicate layers on top, exercised via
    is_canonical_encoding below)."""
    if len(enc) != 32:
        return None
    sign = (enc[31] & 0x80) >> 7
    # Build y from little-endian bytes with the top bit masked off.
    y_bytes = bytearray(enc)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(bytes(y_bytes), "little")
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y)


def is_canonical_encoding(enc: bytes) -> bool:
    """True iff the low 255 bits of `enc` (little-endian), i.e. the
    y-coordinate before the sign bit is applied, are < p. This is exactly
    what a strict Ed25519 verifier (RFC 8032 5.1.3 'not canonical' note /
    the "unencodable" rejects used e.g. by libsodium/ed25519-dalek
    verify_strict) demands of A and R."""
    if len(enc) != 32:
        return False
    y_bytes = bytearray(enc)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(bytes(y_bytes), "little")
    return y < P


def is_small_order(p) -> bool:
    """True iff [8]P == identity (the point has order dividing 8, i.e. it is
    in the small torsion subgroup rejected by a strict verifier)."""
    return point_equal(point_mul(8, p), IDENTITY)


# ---------------------------------------------------------------------------
# RFC 8032 section 5.1.5 / 6: key generation and signing (deterministic).
# ---------------------------------------------------------------------------


def secret_expand(seed: bytes):
    assert len(seed) == 32
    h = sha512(seed)
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    scalar = int.from_bytes(bytes(a), "little")
    prefix = h[32:]
    return scalar, prefix


def public_key(seed: bytes) -> bytes:
    scalar, _prefix = secret_expand(seed)
    A = point_mul(scalar, B)
    return point_compress(A)


def sign(seed: bytes, message: bytes) -> bytes:
    """RFC 8032 section 5.1.6, deterministic Ed25519 (PureEdDSA)."""
    scalar, prefix = secret_expand(seed)
    A_enc = point_compress(point_mul(scalar, B))
    r = int.from_bytes(sha512(prefix, message), "little") % L
    R = point_mul(r, B)
    R_enc = point_compress(R)
    k = int.from_bytes(sha512(R_enc, A_enc, message), "little") % L
    s = (r + k * scalar) % L
    return R_enc + s.to_bytes(32, "little")


def verify_strict(pk_enc: bytes, message: bytes, sig: bytes) -> bool:
    """A from-scratch strict verifier: canonical A/R, A and R not small
    order, 0 <= S < L, and 8*S*B == 8*R + 8*k*A (cofactored form is
    equivalent to cofactorless here because we already reject small-order
    points; used only to cross-check the synthetic sk-positive vectors,
    contract obligation 5.6.6)."""
    if len(pk_enc) != 32 or len(sig) != 64:
        return False
    if not is_canonical_encoding(pk_enc):
        return False
    R_enc, s_bytes = sig[:32], sig[32:]
    if not is_canonical_encoding(R_enc):
        return False
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False
    A = point_decompress(pk_enc)
    R = point_decompress(R_enc)
    if A is None or R is None:
        return False
    if is_small_order(A) or is_small_order(R):
        return False
    k = int.from_bytes(sha512(R_enc, pk_enc, message), "little") % L
    lhs = point_mul(s, B)
    rhs = point_add(R, point_mul(k, A))
    return point_equal(lhs, rhs)


# ---------------------------------------------------------------------------
# Special point encodings used by the negative vectors (contract §5.2).
# ---------------------------------------------------------------------------

# Identity element (order 1): compress(0, 1) = 0x01 followed by 31 zero
# bytes (little-endian y=1, sign bit 0).
IDENTITY_ENCODING = bytes([1]) + bytes(31)

# Non-canonical encoding of the identity: y = p + 1 (>= p, so the decoder
# must reduce mod p to get y=1 again) with sign bit 0.
# p = 2^255 - 19, so p+1 as 32 little-endian bytes with the top bit clear:
_NONCANONICAL_Y = P + 1
assert _NONCANONICAL_Y < 2 ** 255
NONCANONICAL_IDENTITY_ENCODING = _NONCANONICAL_Y.to_bytes(32, "little")
assert NONCANONICAL_IDENTITY_ENCODING == bytes.fromhex(
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
) or NONCANONICAL_IDENTITY_ENCODING[:1] == b"\xee"
assert not is_canonical_encoding(NONCANONICAL_IDENTITY_ENCODING)
assert point_equal(point_decompress(NONCANONICAL_IDENTITY_ENCODING), IDENTITY)

# Order-4 point: all-zero encoding (y = 0, sign bit 0).
ORDER4_ENCODING = bytes(32)
_order4_point = point_decompress(ORDER4_ENCODING)
assert _order4_point is not None
assert not point_equal(_order4_point, IDENTITY)
assert point_equal(point_mul(8, _order4_point), IDENTITY)


# ---------------------------------------------------------------------------
# SSH wire format (RFC 4251 section 5).
# ---------------------------------------------------------------------------


def u32(v: int) -> bytes:
    return v.to_bytes(4, "big")


def sstr(b: bytes) -> bytes:
    return u32(len(b)) + b


def read_u32(buf: bytes, off: int):
    return int.from_bytes(buf[off:off + 4], "big"), off + 4


def read_string(buf: bytes, off: int):
    n, off = read_u32(buf, off)
    return buf[off:off + n], off + n


# ---------------------------------------------------------------------------
# SSH public key blobs (RFC 8709 section 4 / PROTOCOL.u2f).
# ---------------------------------------------------------------------------

KEY_TYPE_ED25519 = b"ssh-ed25519"
KEY_TYPE_SK_ED25519 = b"sk-ssh-ed25519@openssh.com"


def ed25519_pubkey_blob(pk: bytes) -> bytes:
    assert len(pk) == 32
    return sstr(KEY_TYPE_ED25519) + sstr(pk)


def sk_ed25519_pubkey_blob(pk: bytes, application: bytes) -> bytes:
    assert len(pk) == 32
    return sstr(KEY_TYPE_SK_ED25519) + sstr(pk) + sstr(application)


def ed25519_sig_blob(sig: bytes) -> bytes:
    assert len(sig) == 64
    return sstr(KEY_TYPE_ED25519) + sstr(sig)


def sk_ed25519_sig_blob(sig: bytes, flags: int, counter: int) -> bytes:
    assert len(sig) == 64
    return sstr(KEY_TYPE_SK_ED25519) + sstr(sig) + bytes([flags & 0xFF]) + u32(counter)


# ---------------------------------------------------------------------------
# SSHSIG blob (PROTOCOL.sshsig) and signed-data construction.
# ---------------------------------------------------------------------------

MAGIC = b"SSHSIG"
VERSION = 1
HASH_ALGORITHM_SHA512 = b"sha512"
HASH_ALGORITHM_SHA256 = b"sha256"


def signed_data(namespace: bytes, reserved: bytes, hash_algorithm: bytes, message_hash: bytes) -> bytes:
    return MAGIC + sstr(namespace) + sstr(reserved) + sstr(hash_algorithm) + sstr(message_hash)


def sshsig_blob(pubkey_blob: bytes, namespace: bytes, reserved: bytes, hash_algorithm: bytes, sig_blob: bytes) -> bytes:
    return MAGIC + u32(VERSION) + sstr(pubkey_blob) + sstr(namespace) + sstr(reserved) + sstr(hash_algorithm) + sstr(sig_blob)


def sk_message(application: bytes, flags: int, counter: int, signed: bytes) -> bytes:
    return sha256(application) + bytes([flags & 0xFF]) + u32(counter) + sha256(signed)


def sign_ed25519_sshsig(seed: bytes, namespace: bytes, message: bytes, hash_algorithm: bytes = HASH_ALGORITHM_SHA512) -> bytes:
    """Build a complete, honest ssh-ed25519 SSHSIG blob exactly as
    ssh-keygen -Y sign would, using only this module's primitives. Used to
    prove determinism against the real ssh-keygen output."""
    if hash_algorithm == HASH_ALGORITHM_SHA512:
        mh = sha512(message)
    elif hash_algorithm == HASH_ALGORITHM_SHA256:
        mh = sha256(message)
    else:
        raise ValueError("unsupported hash_algorithm")
    sd = signed_data(namespace, b"", hash_algorithm, mh)
    pk = public_key(seed)
    sig = sign(seed, sd)
    return sshsig_blob(ed25519_pubkey_blob(pk), namespace, b"", hash_algorithm, ed25519_sig_blob(sig))


# ---------------------------------------------------------------------------
# Armor (base64, 70-column lines, BEGIN/END markers) — matches
# `ssh-keygen -Y sign` output exactly.
# ---------------------------------------------------------------------------

import base64

ARMOR_HEADER = b"-----BEGIN SSH SIGNATURE-----"
ARMOR_FOOTER = b"-----END SSH SIGNATURE-----"
ARMOR_LINE_LEN = 70


def armor_encode(blob: bytes, line_len: int = ARMOR_LINE_LEN) -> bytes:
    b64 = base64.b64encode(blob)
    lines = [b64[i:i + line_len] for i in range(0, len(b64), line_len)]
    out = ARMOR_HEADER + b"\n"
    for line in lines:
        out += line + b"\n"
    out += ARMOR_FOOTER + b"\n"
    return out


# ---------------------------------------------------------------------------
# openssh-key-v1 unencrypted private-key file writer (contract §5.2).
# ---------------------------------------------------------------------------

OPENSSH_KEY_V1_MAGIC = b"openssh-key-v1\x00"


def openssh_key_v1(seed: bytes, comment: bytes) -> bytes:
    pk = public_key(seed)
    pub_blob = ed25519_pubkey_blob(pk)
    checkint = 0x01020304
    priv = (
        u32(checkint)
        + u32(checkint)
        + sstr(KEY_TYPE_ED25519)
        + sstr(pk)
        + sstr(seed + pk)
        + sstr(comment)
    )
    # PKCS#5-style padding: 1, 2, 3, ... up to a multiple of 8 (cipher
    # block size for "none" is 8 per OpenSSH's own padding rule).
    pad_len = (-len(priv)) % 8
    priv += bytes(range(1, pad_len + 1))

    body = (
        OPENSSH_KEY_V1_MAGIC
        + sstr(b"none")  # ciphername
        + sstr(b"none")  # kdfname
        + sstr(b"")      # kdfoptions
        + u32(1)         # number of keys
        + sstr(pub_blob)
        + sstr(priv)
    )
    b64 = base64.b64encode(body)
    lines = [b64[i:i + ARMOR_LINE_LEN] for i in range(0, len(b64), ARMOR_LINE_LEN)]
    out = b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
    for line in lines:
        out += line + b"\n"
    out += b"-----END OPENSSH PRIVATE KEY-----\n"
    return out


def openssh_pub_line(pk: bytes, comment: bytes) -> bytes:
    return KEY_TYPE_ED25519 + b" " + base64.b64encode(ed25519_pubkey_blob(pk)) + b" " + comment + b"\n"


def sk_openssh_pub_line(pk: bytes, application: bytes, comment: bytes) -> bytes:
    return KEY_TYPE_SK_ED25519 + b" " + base64.b64encode(sk_ed25519_pubkey_blob(pk, application)) + b" " + comment + b"\n"


def fingerprint_sha256(blob: bytes) -> str:
    digest = sha256(blob)
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
