"""
loglink_annex.py -- LogLink built on SHA-256's *real* compression function
(64-byte blocks), so that:

    digest == hashlib.sha256(raw_structured_bytes).digest()

exactly -- i.e. the "structured file" IS the annex payload, and Bitcoin's
own SHA256(annex) (BIP-341's sha_annex) *is* the LogLink commitment, with
zero extra hashing and no consensus changes. Verified against hashlib at
the bottom of this file.

Reuses loglink.py's position()/block_len() formulas unchanged (they only
depend on item *counts*, not on byte/block size). Everything byte-level
(the compression function, block layout, proof construction/verification,
and crucially the standard length-padding finalization) is reimplemented
here against the real 64-byte block size.
"""
import hashlib
import math
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional

from loglink import position, block_len
from sha256_core import compress, length_padding_blocks, IV_STD, STATE_SIZE, BLOCK_SIZE

# Fixed padding suffix that turns a 32-byte checkpoint into a full 64-byte
# block, chosen to mirror SHA-256's own bit-padding convention (0x80 then
# zeros) purely for legibility/hygiene -- NOT load-bearing for security (see
# report S4 corollary): a 64-byte data element would need to end in exactly
# this 31-byte all-zero tail to even resemble a MID block, which changes
# nothing about the free-start-collision argument either way.
_MID_PAD = b"\x80" + b"\x00" * (BLOCK_SIZE - STATE_SIZE - 1)
assert len(_MID_PAD) == BLOCK_SIZE - STATE_SIZE


def pad_element(x: bytes) -> bytes:
    if len(x) < BLOCK_SIZE:
        return x + b"\x00" * (BLOCK_SIZE - len(x))
    assert len(x) == BLOCK_SIZE
    return x


def mid_block(checkpoint: bytes) -> bytes:
    assert len(checkpoint) == STATE_SIZE
    return checkpoint + _MID_PAD


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------
@dataclass
class StructuredFile:
    N: int
    L: int
    elements: List[bytes]
    raw_bytes: bytearray = field(default_factory=bytearray)   # the literal annex payload
    checkpoint: Dict[int, bytes] = field(default_factory=dict)
    ending: Dict[Tuple[int, int], bytes] = field(default_factory=dict)
    prewrap: Dict[Tuple[int, int], bytes] = field(default_factory=dict)
    raw_state: bytes = b""     # running compress() state, BEFORE finalization
    digest: bytes = b""        # == hashlib.sha256(raw_bytes).digest()


def build(elements: List[bytes]) -> StructuredFile:
    N = len(elements)
    L = int(round(math.log2(N)))
    assert 1 << L == N
    sf = StructuredFile(N=N, L=L, elements=[pad_element(e) for e in elements])
    state = IV_STD

    def emit_data(i):
        nonlocal state
        blk = sf.elements[i]
        sf.raw_bytes.extend(blk)
        state = compress(state, blk)

    def emit_mid(a):
        nonlocal state
        blk = mid_block(sf.checkpoint[a])
        sf.raw_bytes.extend(blk)
        state = compress(state, blk)

    def block(a, k):
        nonlocal state
        if a not in sf.checkpoint:
            sf.checkpoint[a] = state
        if k == 1:
            emit_data(a)
            emit_data(a + 1)
            sf.prewrap[(a, k)] = state
            emit_mid(a)
        else:
            half = 1 << (k - 1)
            block(a, k - 1)
            block(a + half, k - 1)
            sf.prewrap[(a, k)] = state
            emit_mid(a)
        sf.ending[(a, k)] = state

    block(0, L - 1)
    block(1 << (L - 1), L - 1)
    sf.raw_state = state

    # the ONE finalization, applied exactly once, for the whole file
    pad = length_padding_blocks(len(sf.raw_bytes))
    fstate = state
    for i in range(0, len(pad), BLOCK_SIZE):
        fstate = compress(fstate, pad[i:i + BLOCK_SIZE])
    sf.digest = fstate
    return sf


def total_raw_len(N: int) -> int:
    """Public: total annex-payload length in bytes for N elements -- pure
    function of N, needed by the verifier to reconstruct the finalization
    padding (which depends on total message length) without seeing the file."""
    L = int(round(math.log2(N)))
    M = 2 * N - 2   # total structured items (see report S1)
    return M * BLOCK_SIZE


# ---------------------------------------------------------------------------
# Single-element inclusion proof (identical control flow to loglink.py,
# re-derived here against the real compress()/finalization)
# ---------------------------------------------------------------------------
@dataclass
class Proof:
    index: int
    d0: bytes
    d1: bytes
    reveals: List[bytes] = field(default_factory=list)

    def nbytes(self) -> int:
        return 2 * BLOCK_SIZE + len(self.reveals) * STATE_SIZE


def build_proof(sf: StructuredFile, index: int) -> Proof:
    L = sf.L
    a0 = index - (index % 2)
    pf = Proof(index=index, d0=sf.elements[a0], d1=sf.elements[a0 + 1])
    half_top = 1 << (L - 1)

    def recurse(a, k, target):
        if k == 1:
            return
        half = 1 << (k - 1)
        if target < a + half:
            recurse(a, k - 1, target)
            pf.reveals.append(sf.prewrap[(a + half, k - 1)])
        else:
            pf.reveals.append(sf.ending[(a, k - 1)])
            recurse(a + half, k - 1, target)

    if a0 < half_top:
        recurse(0, L - 1, a0)
        pf.reveals.append(sf.prewrap[(half_top, L - 1)])
    else:
        pf.reveals.append(sf.ending[(0, L - 1)])
        recurse(half_top, L - 1, a0)
    return pf


def verify_proof(N: int, digest: bytes, index: int, data: bytes, pf: Proof) -> bool:
    """O(log N) compression-function calls, ending with the SAME standard
    finalization -- never touches the full annex, never needs a table."""
    L = int(round(math.log2(N)))
    if 1 << L != N:
        return False
    a0 = index - (index % 2)
    if pf.index != index:
        return False
    padded_data = pad_element(data)
    if index == a0 and padded_data != pf.d0:
        return False
    if index == a0 + 1 and padded_data != pf.d1:
        return False

    half_top = 1 << (L - 1)
    it = iter(pf.reveals)

    def eval_block(a, k, target, ckpt):
        if k == 1:
            s = compress(compress(ckpt, pf.d0), pf.d1)
            return compress(s, mid_block(ckpt))
        half = 1 << (k - 1)
        if target < a + half:
            left_end = eval_block(a, k - 1, target, ckpt)
            try:
                sib_prewrap = next(it)
            except StopIteration:
                return None
            right_end = compress(sib_prewrap, mid_block(left_end))
            return compress(right_end, mid_block(ckpt))
        else:
            try:
                left_end = next(it)
            except StopIteration:
                return None
            right_end = eval_block(a + half, k - 1, target, left_end)
            if right_end is None:
                return None
            return compress(right_end, mid_block(ckpt))

    try:
        if a0 < half_top:
            y = eval_block(0, L - 1, a0, IV_STD)
            if y is None:
                return False
            r2 = next(it)
            raw_state = compress(r2, mid_block(y))
        else:
            y_reveal = next(it)
            raw_state = eval_block(half_top, L - 1, a0, y_reveal)
            if raw_state is None:
                return False
    except StopIteration:
        return False

    if any(True for _ in it):
        return False

    pad = length_padding_blocks(total_raw_len(N))
    fstate = raw_state
    for i in range(0, len(pad), BLOCK_SIZE):
        fstate = compress(fstate, pad[i:i + BLOCK_SIZE])
    return fstate == digest


if __name__ == "__main__":
    import os
    import dataclasses
    for L in (2, 3, 4, 5, 6):
        N = 1 << L
        elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
        sf = build(elements)

        # THE key claim: digest == plain hashlib.sha256(annex payload)
        ref = hashlib.sha256(bytes(sf.raw_bytes)).digest()
        assert sf.digest == ref, "digest does not match hashlib.sha256(raw bytes)!"

        # position() unit test against this real-SHA-256 build too (not
        # just the toy loglink.py construction): brute-force each element's
        # true byte offset (divided by BLOCK_SIZE) from sf.raw_bytes/
        # sf.elements and check position(a) for every a, even and odd.
        pos_by_a = {}
        acc = 0
        def _walk(a, k):
            global acc
            if a not in pos_by_a:
                pos_by_a[a] = acc
            if k == 1:
                pos_by_a[a] = acc; acc += 1
                pos_by_a[a + 1] = acc; acc += 1
                acc += 1  # MID(a)
            else:
                half = 1 << (k - 1)
                _walk(a, k - 1)
                _walk(a + half, k - 1)
                acc += 1  # MID(a)
        acc = 0
        _walk(0, L - 1)
        _walk(1 << (L - 1), L - 1)
        for a in range(N):
            assert position(a) == pos_by_a[a], \
                f"position({a}) = {position(a)}, but item {a} is really at {pos_by_a[a]} (N={N})"

        ok_count = 0
        for i in range(N):
            pf = build_proof(sf, i)
            ok = verify_proof(N, sf.digest, i, elements[i], pf)
            assert ok, f"N={N} index={i} failed to verify"
            bad = bytearray(elements[i]); bad[0] ^= 1
            assert not verify_proof(N, sf.digest, i, bytes(bad), pf), "tamper accepted!"
            # tamper test: flip EVERY individual reveal, not just the data
            for j in range(len(pf.reveals)):
                bad_reveals = list(pf.reveals)
                r = bytearray(bad_reveals[j]); r[0] ^= 1
                bad_reveals[j] = bytes(r)
                pf2 = dataclasses.replace(pf, reveals=bad_reveals)
                assert not verify_proof(N, sf.digest, i, elements[i], pf2), \
                    f"tampered reveal #{j} accepted! (N={N}, index={i})"
            ok_count += 1

        # index-relabeling attack test (see loglink.py for the full
        # explanation): a proof built for one index of a pair must not
        # verify against the pair's other index, whether queried with that
        # other index's own genuine data or with the original index's data.
        for a0 in range(0, N, 2):
            pf_even = build_proof(sf, a0)
            other = a0 + 1
            assert not verify_proof(N, sf.digest, other, elements[other], pf_even), \
                f"index-relabeling: proof built for {a0} wrongly verified for {other}! N={N}"
            assert not verify_proof(N, sf.digest, other, elements[a0], pf_even), \
                f"index-relabeling: proof for {a0} accepted {a0}'s data as index {other}'s! N={N}"

        print(f"N={N:4d}: digest == hashlib.sha256(raw annex bytes)  [OK]   "
              f"position() verified for every index  [OK]   "
              f"all {ok_count} proofs verify, every data and reveal tamper rejected. "
              f"annex size = {len(sf.raw_bytes)} bytes, single proof = "
              f"{build_proof(sf, 0).nbytes()} bytes")
    print("\nloglink_annex self-test: ALL PASSED")
