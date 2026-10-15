"""Self-contained, pure-stdlib age (age-encryption.org/v1) reference used only to
generate and cross-check this directory's test vectors. No third-party packages,
no import of any other crate's test helpers (contract §5.1: "no cross-crate
import") — the handful of Ed25519 / SSH-wire-format primitives this needs are
copied in from spacetime-sshsig's tests/vectors/ed25519_ref.py (a from-scratch
RFC 8032 reference; not linked at runtime by anything, only used here to build
vectors and cross-check against `rage`).

Implements: X25519 (RFC 7748 ladder), ChaCha20-Poly1305 (RFC 8439), HKDF-SHA-256
(RFC 5869, via hashlib), bech32 (BIP-173), the age header/STREAM wire format, both
age recipient recipes (X25519 and ssh-ed25519, the latter verified against rage
0.12.1 and Go agessh — see spacetime-age contract §0 D2 / §3.3), age ASCII armor,
and enough RFC 8032 machinery (point arithmetic, key derivation, the
openssh-key-v1 writer) to build the fixed ssh-ed25519 identity used by these
vectors deterministically, without shelling out to ssh-keygen.
"""
import hashlib
import hmac
import struct
import base64

# =====================================================================
# RFC 8032 Ed25519 point arithmetic, key derivation, SSH wire format
# (copied from spacetime-sshsig/tests/vectors/ed25519_ref.py; kept
# byte-for-byte identical in spirit, trimmed to what this file needs)
# =====================================================================

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493

D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)

Bx_num = 15112221349535400772501151409588531511454012693041857206046113283949847762202
By_num = 46316835694926478169428394003475163141307993866256225615783033603165251855960
Bpoint = (Bx_num % P, By_num % P)

IDENTITY_POINT = (0, 1)


def _sha512(*chunks: bytes) -> bytes:
    h = hashlib.sha512()
    for c in chunks:
        h.update(c)
    return h.digest()


def _point_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    denom_x = (1 + D * x1 * x2 * y1 * y2) % P
    denom_y = (1 - D * x1 * x2 * y1 * y2) % P
    x3 = (x1 * y2 + x2 * y1) * pow(denom_x, P - 2, P) % P
    y3 = (y1 * y2 + x1 * x2) * pow(denom_y, P - 2, P) % P
    return (x3, y3)


def _point_mul(s: int, p):
    q = IDENTITY_POINT
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p1, p2) -> bool:
    x1, y1 = p1
    x2, y2 = p2
    return (x1 - x2) % P == 0 and (y1 - y2) % P == 0


def _recover_x(y: int, sign: int):
    y %= P
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
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
    """Strict RFC 8032 §5.1.3 decode. Returns None on any malformed input."""
    if len(enc) != 32:
        return None
    sign = (enc[31] & 0x80) >> 7
    y_bytes = bytearray(enc)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(bytes(y_bytes), "little")
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y)


def is_canonical_encoding(enc: bytes) -> bool:
    if len(enc) != 32:
        return False
    y_bytes = bytearray(enc)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(bytes(y_bytes), "little")
    return y < P


def is_small_order(p) -> bool:
    return _point_equal(_point_mul(8, p), IDENTITY_POINT)


def secret_expand(seed: bytes):
    assert len(seed) == 32
    h = _sha512(seed)
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    scalar = int.from_bytes(bytes(a), "little")
    return scalar, h[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    scalar, _prefix = secret_expand(seed)
    a_point = _point_mul(scalar, Bpoint)
    return point_compress(a_point)


# ---- special point encodings for the "invalid" ed25519_to_x25519.json entries ----

IDENTITY_ENCODING = bytes([1]) + bytes(31)

_NONCANONICAL_Y = P + 1
NONCANONICAL_IDENTITY_ENCODING = _NONCANONICAL_Y.to_bytes(32, "little")
assert not is_canonical_encoding(NONCANONICAL_IDENTITY_ENCODING)
assert _point_equal(point_decompress(NONCANONICAL_IDENTITY_ENCODING), IDENTITY_POINT)

ORDER4_ENCODING = bytes(32)
assert is_small_order(point_decompress(ORDER4_ENCODING))
assert not _point_equal(point_decompress(ORDER4_ENCODING), IDENTITY_POINT)

_order2_point = (0, P - 1)
ORDER2_ENCODING = point_compress(_order2_point)
assert is_small_order(_order2_point) and not _point_equal(_order2_point, IDENTITY_POINT)

NONCANONICAL_SIGN_ENCODING = bytearray(NONCANONICAL_IDENTITY_ENCODING)
NONCANONICAL_SIGN_ENCODING[31] |= 0x80
NONCANONICAL_SIGN_ENCODING = bytes(NONCANONICAL_SIGN_ENCODING)


# ---- SSH wire format (RFC 4251 §5) ----

def u32(v: int) -> bytes:
    return v.to_bytes(4, "big")


def sstr(b: bytes) -> bytes:
    return u32(len(b)) + b


def read_u32(buf: bytes, off: int):
    return int.from_bytes(buf[off:off + 4], "big"), off + 4


def read_string(buf: bytes, off: int):
    n, off = read_u32(buf, off)
    return buf[off:off + n], off + n


KEY_TYPE_ED25519 = b"ssh-ed25519"
ARMOR_LINE_LEN = 70


def ed25519_pubkey_blob(pk: bytes) -> bytes:
    assert len(pk) == 32
    return sstr(KEY_TYPE_ED25519) + sstr(pk)


def openssh_key_v1(seed: bytes, comment: bytes) -> bytes:
    """Unencrypted openssh-key-v1 private-key file, byte-for-byte what OpenSSH
    itself would write for cipher "none" (verified against `ssh-keygen -lf` /
    `rage -i` acceptance in the experiment behind this contract, §9.4)."""
    pk = ed25519_public_key(seed)
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
    pad_len = (-len(priv)) % 8
    priv += bytes(range(1, pad_len + 1))
    body = (
        b"openssh-key-v1\x00"
        + sstr(b"none")
        + sstr(b"none")
        + sstr(b"")
        + u32(1)
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


def fingerprint_sha256(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


# =====================================================================
# X25519 (RFC 7748 §5)
# =====================================================================

def clamp(k: bytes) -> int:
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(bytes(k), "little")


def x25519(k: bytes, u: bytes) -> bytes:
    scalar = clamp(k)
    ub = bytearray(u)
    ub[31] &= 127
    x1 = int.from_bytes(bytes(ub), "little") % P
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    a24 = 121665
    for t in range(254, -1, -1):
        kt = (scalar >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        A = (x2 + z2) % P
        AA = A * A % P
        Bv = (x2 - z2) % P
        BB = Bv * Bv % P
        E = (AA - BB) % P
        C = (x3 + z3) % P
        Dv = (x3 - z3) % P
        DA = Dv * A % P
        CB = C * Bv % P
        x3 = pow((DA + CB) % P, 2, P)
        z3 = x1 * pow((DA - CB) % P, 2, P) % P
        x2 = AA * BB % P
        z2 = E * ((AA + a24 * E) % P) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


BASEPOINT = (9).to_bytes(32, "little")


# =====================================================================
# ChaCha20-Poly1305 (RFC 8439)
# =====================================================================

def _rotl(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl(s[b], 7)


def chacha20_block(key, counter, nonce):
    st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    st += list(struct.unpack("<8I", key))
    st += [counter] + list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + st[i]) & 0xffffffff for i in range(16)])


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce)
        blk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(blk, ks))
    return bytes(out)


def poly1305(key32, msg):
    r = int.from_bytes(key32[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key32[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        n = int.from_bytes(blk + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return b + b"\x00" * ((16 - len(b) % 16) % 16)


def aead_seal(key, nonce, aad, pt):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, pt)
    mac_data = _pad16(aad) + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct + poly1305(otk, mac_data)


def aead_open(key, nonce, aad, sealed):
    if len(sealed) < 16:
        raise ValueError("short")
    ct, tag = sealed[:-16], sealed[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    mac_data = _pad16(aad) + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    if not hmac.compare_digest(poly1305(otk, mac_data), tag):
        raise ValueError("tag mismatch")
    return chacha20(key, 1, nonce, ct)


# =====================================================================
# HKDF-SHA256 (RFC 5869)
# =====================================================================

def hkdf(salt, ikm, info, n):
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


# =====================================================================
# bech32 (BIP-173)
# =====================================================================

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(s):
    if s != s.lower() and s != s.upper():
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("bad separator")
    hrp, data = s[:pos], [CHARSET.index(c) for c in s[pos + 1:]]
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("checksum")
    data = data[:-6]
    acc, bits, out = 0, 0, bytearray()
    for v in data:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)
    if bits >= 5 or (acc & ((1 << bits) - 1)):
        raise ValueError("padding")
    return hrp, bytes(out)


def bech32_encode(hrp, data):
    acc, bits, vals = 0, 0, []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            vals.append((acc >> bits) & 31)
    if bits:
        vals.append((acc << (5 - bits)) & 31)
    pm = _polymod(_hrp_expand(hrp) + vals + [0] * 6) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[v] for v in vals + chk)


# =====================================================================
# age primitives: base64, recipient wrap/unwrap, header, STREAM, armor
# =====================================================================

def b64d(s: str) -> bytes:
    """Strict raw std base64: no padding, canonical, rejects anything else."""
    if "=" in s:
        raise ValueError("padding present")
    if len(s) % 4 == 1:
        raise ValueError("bad length")
    raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    if base64.b64encode(raw).rstrip(b"=").decode() != s:
        raise ValueError("non-canonical")
    return raw


def b64e(b: bytes) -> str:
    return base64.b64encode(b).rstrip(b"=").decode()


def age_recipient_from_identity(sk: bytes) -> bytes:
    return x25519(sk, BASEPOINT)


def x25519_recipient_str(sk: bytes) -> str:
    return bech32_encode("age", age_recipient_from_identity(sk))


def x25519_identity_str(sk: bytes) -> str:
    return bech32_encode("age-secret-key-", sk).upper()


def x25519_wrap(rng32: bytes, pk: bytes, file_key: bytes):
    eph = x25519(rng32, BASEPOINT)
    shared = x25519(rng32, pk)
    assert shared != b"\x00" * 32
    key = hkdf(eph + pk, shared, b"age-encryption.org/v1/X25519", 32)
    body = aead_seal(key, b"\x00" * 12, b"", file_key)
    return ("X25519", [b64e(eph)], body)


def x25519_unwrap(sk: bytes, share: bytes, body: bytes) -> bytes:
    pk = x25519(sk, BASEPOINT)
    shared = x25519(sk, share)
    if shared == b"\x00" * 32:
        raise ValueError("all-zero shared secret")
    key = hkdf(share + pk, shared, b"age-encryption.org/v1/X25519", 32)
    return aead_open(key, b"\x00" * 12, b"", body)


SSH_ED25519_INFO = b"age-encryption.org/v1/ssh-ed25519"


def ssh_wire_ed25519(pk: bytes) -> bytes:
    return sstr(b"ssh-ed25519") + sstr(pk)


def ed25519_pk_to_x25519(pk: bytes) -> bytes:
    pt = point_decompress(pk)
    assert pt is not None and is_canonical_encoding(pk)
    x, y = pt
    u = (1 + y) * pow((1 - y) % P, P - 2, P) % P
    return u.to_bytes(32, "little")


def ssh_ed25519_tag(pk: bytes) -> bytes:
    return hashlib.sha256(ssh_wire_ed25519(pk)).digest()[:4]


def ssh_ed25519_wrap(rng32: bytes, pk: bytes, file_key: bytes):
    """rage 0.12.1 src/ssh/recipient.rs / Go agessh recipe (spacetime-age
    contract §0 D2, §3.3 — NOT the naive reading of the age spec text):
    tweak = HKDF(salt = ssh wire pubkey, ikm = "", info = LABEL);
    shared = X25519(tweak, X25519(e, pk_mont));
    wrap key = HKDF(salt = eph || pk_mont, ikm = shared, info = LABEL)
    (the salt uses the *untweaked* pk_mont)."""
    wire = ssh_wire_ed25519(pk)
    tweak = hkdf(wire, b"", SSH_ED25519_INFO, 32)
    pk_mont = ed25519_pk_to_x25519(pk)
    eph = x25519(rng32, BASEPOINT)
    inner = x25519(rng32, pk_mont)
    assert inner != b"\x00" * 32
    shared = x25519(tweak, inner)
    assert shared != b"\x00" * 32
    key = hkdf(eph + pk_mont, shared, SSH_ED25519_INFO, 32)
    body = aead_seal(key, b"\x00" * 12, b"", file_key)
    return ("ssh-ed25519", [b64e(ssh_ed25519_tag(pk)), b64e(eph)], body)


def ssh_ed25519_unwrap(seed: bytes, tag: bytes, share: bytes, body: bytes) -> bytes:
    pk = ed25519_public_key(seed)
    if tag != ssh_ed25519_tag(pk):
        raise ValueError("tag mismatch (no match)")
    a = hashlib.sha512(seed).digest()[:32]  # clamped by x25519()
    wire = ssh_wire_ed25519(pk)
    tweak = hkdf(wire, b"", SSH_ED25519_INFO, 32)
    pk_mont = x25519(a, BASEPOINT)
    assert pk_mont == ed25519_pk_to_x25519(pk)
    inner = x25519(a, share)
    if inner == b"\x00" * 32:
        raise ValueError("all-zero")
    shared = x25519(tweak, inner)
    if shared == b"\x00" * 32:
        raise ValueError("all-zero")
    key = hkdf(share + pk_mont, shared, SSH_ED25519_INFO, 32)
    return aead_open(key, b"\x00" * 12, b"", body)


# ---- header / STREAM ----

MAGIC = b"age-encryption.org/v1\n"


def parse_header(data: bytes):
    """Returns (stanzas, mac, header_end, mac_input). Minimal strictness — the
    Rust crate is the strict implementation; this only needs to round-trip
    the vectors this file itself produces plus rage's honest output."""
    if not data.startswith(MAGIC):
        raise ValueError("bad magic")
    pos = len(MAGIC)
    stanzas = []
    while True:
        nl = data.index(b"\n", pos)
        line = data[pos:nl]
        if line.startswith(b"--- "):
            mac = b64d(line[4:].decode())
            assert len(mac) == 32
            return stanzas, mac, nl + 1, data[:pos + 3]
        assert line.startswith(b"-> ")
        args = line[3:].decode().split(" ")
        pos = nl + 1
        body = b""
        while True:
            nl = data.index(b"\n", pos)
            bl = data[pos:nl]
            pos = nl + 1
            body += b64d(bl.decode())
            if len(bl) < 64:
                break
        stanzas.append((args[0], args[1:], body))


def header_mac(file_key: bytes, header_through_dashes: bytes) -> bytes:
    key = hkdf(b"", file_key, b"header", 32)
    return hmac.new(key, header_through_dashes, hashlib.sha256).digest()


CHUNK = 65536


def stream_decrypt(file_key: bytes, payload: bytes) -> bytes:
    """Matches the release rule of contract §0 D6: a full 65552-byte chunk is
    tried with last=0 first and, on AEAD failure, retried with last=1 (this
    is the only case where a full chunk can legitimately be the final one,
    e.g. a plaintext that is an exact multiple of 64 KiB). Anything shorter
    than 65552 bytes remaining can only be the final chunk (last=1)."""
    nonce, body = payload[:16], payload[16:]
    assert len(nonce) == 16
    key = hkdf(nonce, file_key, b"payload", 32)
    out, counter, pos = b"", 0, 0
    while True:
        remaining = len(body) - pos
        if remaining >= CHUNK + 16:
            chunk = body[pos:pos + CHUNK + 16]
            n0 = counter.to_bytes(11, "big") + b"\x00"
            try:
                out += aead_open(key, n0, b"", chunk)
                pos += len(chunk)
                counter += 1
                continue
            except ValueError:
                n1 = counter.to_bytes(11, "big") + b"\x01"
                out += aead_open(key, n1, b"", chunk)
                break
        else:
            chunk = body[pos:]
            n1 = counter.to_bytes(11, "big") + b"\x01"
            out += aead_open(key, n1, b"", chunk)
            break
    return out


def stream_encrypt(file_key: bytes, nonce: bytes, pt: bytes) -> bytes:
    key = hkdf(nonce, file_key, b"payload", 32)
    out, counter, pos = nonce, 0, 0
    while True:
        chunk = pt[pos:pos + CHUNK]
        pos += CHUNK
        last = pos >= len(pt)
        n = counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")
        out += aead_seal(key, n, b"", chunk)
        counter += 1
        if last:
            break
    return out


def encode_stanza(t, args, body):
    s = ("-> " + " ".join([t] + args) + "\n").encode()
    b = b64e(body)
    while True:
        s += b[:64].encode() + b"\n"
        b = b[64:]
        if len(s.rsplit(b"\n", 2)[-2]) < 64:
            break
    return s


def encrypt(file_key, nonce, stanzas, pt):
    h = MAGIC
    for t, a, b in stanzas:
        h += encode_stanza(t, a, b)
    h += b"---"
    mac = header_mac(file_key, h)
    return h + b" " + b64e(mac).encode() + b"\n" + stream_encrypt(file_key, nonce, pt)


def decrypt(data, identities=(), ssh_seeds=()):
    stanzas, mac, hend, hdr = parse_header(data)
    file_key = None
    for t, args, body in stanzas:
        if t == "X25519":
            share = b64d(args[0]); assert len(share) == 32 and len(body) == 32
            for sk in identities:
                try:
                    file_key = x25519_unwrap(sk, share, body); break
                except ValueError as e:
                    if "all-zero" in str(e):
                        raise
        elif t == "ssh-ed25519":
            tag, share = b64d(args[0]), b64d(args[1]); assert len(tag) == 4 and len(share) == 32 and len(body) == 32
            for seed in ssh_seeds:
                try:
                    file_key = ssh_ed25519_unwrap(seed, tag, share, body); break
                except ValueError:
                    pass
        if file_key:
            break
    if file_key is None:
        raise ValueError("no match")
    if not hmac.compare_digest(header_mac(file_key, hdr), mac):
        raise ValueError("HMAC failure")
    return file_key, stream_decrypt(file_key, data[hend:])


# ---- ASCII armor (contract §3.6 / D15; encoder matches rage's output) ----

ARMOR_BEGIN = b"-----BEGIN AGE ENCRYPTED FILE-----"
ARMOR_END = b"-----END AGE ENCRYPTED FILE-----"


def armor_encode(data: bytes) -> bytes:
    b64 = base64.b64encode(data)
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    out = ARMOR_BEGIN + b"\n"
    for line in lines:
        out += line + b"\n"
    out += ARMOR_END + b"\n"
    return out


def armor_decode(armored: bytes) -> bytes:
    s = armored.strip()
    assert s.startswith(ARMOR_BEGIN) and s.endswith(ARMOR_END)
    body = s[len(ARMOR_BEGIN):-len(ARMOR_END)].strip()
    lines = [l for l in body.split(b"\n") if l]
    return base64.b64decode(b"".join(lines))


class CounterRng:
    """Byte-for-byte the `CounterRng(0)` test double the spacetime implementer
    writes (contract §4): fill_bytes emits the sequence 0, 1, 2, ... wrapping
    mod 256, and never resets between calls on the same instance. Verified
    against the contract's own pyref_both_det KAT (§5.3) in gen.py."""

    def __init__(self, start: int = 0):
        self.c = start % 256

    def bytes(self, n: int) -> bytes:
        out = bytes([(self.c + i) % 256 for i in range(n)])
        self.c = (self.c + n) % 256
        return out
