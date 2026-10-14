"""
sha256_core.py -- SHA-256's real Davies-Meyer compression function, exposed
directly as a (state, 64-byte block) -> state primitive, plus the standard
length-padding finalizer. This is what makes LogLink's digest literally
equal to SHA256(raw bytes) -- required for the Bitcoin-annex application,
where consensus only ever computes plain SHA256 of the witness bytes.

Verified byte-for-byte against hashlib.sha256 at the bottom of this file.
"""
import hashlib
import struct

STATE_SIZE = 32   # bytes (8 x 32-bit words)
BLOCK_SIZE = 64    # bytes -- SHA-256's real message block size

_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

IV_STD = bytes.fromhex(
    "6a09e667bb67ae85" "3c6ef372a54ff53a" "510e527f9b05688c" "1f83d9ab5be0cd19"
)  # the standard SHA-256 initial value, as 8 big-endian 32-bit words


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def compress(state: bytes, block: bytes) -> bytes:
    """The raw SHA-256 compression function C(state, block) -> state.
    state: 32 bytes (8 words). block: exactly 64 bytes (16 words).
    This is EXACTLY what SHA-256 calls once per 64-byte chunk internally;
    LogLink re-injects past *states* (not full re-hashes) as blocks here."""
    assert len(state) == STATE_SIZE
    assert len(block) == BLOCK_SIZE
    h = list(struct.unpack(">8I", state))
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hh + S1 + ch + _K[i] + w[i]) & 0xFFFFFFFF
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        hh, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
    out = [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return struct.pack(">8I", *out)


def length_padding_blocks(total_message_len: int) -> bytes:
    """The standard SHA-256 length-padding suffix (0x80, zeros, 64-bit bit
    length) for a message of total_message_len bytes -- this is the "one
    finalization" applied exactly once, at the very end, regardless of how
    many compression calls preceded it."""
    bit_len = total_message_len * 8
    pad = b"\x80"
    pad_len = (56 - (total_message_len + 1) % 64) % 64
    pad += b"\x00" * pad_len
    pad += struct.pack(">Q", bit_len)
    assert (total_message_len + len(pad)) % 64 == 0
    return pad


def sha256_via_compress(message: bytes) -> bytes:
    """Full SHA-256(message), built purely from compress() + padding, for
    cross-checking against hashlib.sha256."""
    padded = message + length_padding_blocks(len(message))
    state = IV_STD
    for i in range(0, len(padded), 64):
        state = compress(state, padded[i:i + 64])
    return state


if __name__ == "__main__":
    import os
    random_tests = [b"", b"a", b"abc", b"The quick brown fox jumps over the lazy dog"]
    for n in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1000, 4096]:
        random_tests.append(os.urandom(n))
    all_ok = True
    for msg in random_tests:
        mine = sha256_via_compress(msg).hex()
        ref = hashlib.sha256(msg).hexdigest()
        ok = mine == ref
        all_ok &= ok
        if not ok:
            print(f"MISMATCH len={len(msg)}: mine={mine} ref={ref}")
    print("sha256_core self-test:", "ALL PASSED" if all_ok else "FAILED",
          f"({len(random_tests)} messages, lengths spanning multiple block boundaries)")
