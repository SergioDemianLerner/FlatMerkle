"""
loglink.py -- reference implementation + brute-force verifier for the
"LogLink" scheme: a logarithmic-space, logarithmic-verification-time
inclusion proof over a *linearly hashed* file, with no Merkle tree, built by
re-injecting past compression-function midstates ("free-start" reuse).

Everything in the accompanying report is checked by actually running this
code against a real SHA-256-based compression function -- not just argued
on paper.

CONVENTION: N = 2^L data elements D[0..N-1], hashed in ASCENDING order
(D[0] first, D[N-1] last, digest right after D[N-1]).  This is the mirror
image of the user's hand-drawn figure, which happens to draw its
highest-numbered element first (left) and element 0 last (right, next to
the digest).  The construction is identical either way; see report S1.
"""

import hashlib
import math
import random
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional

STATE_SIZE = 32  # bytes (matches SHA-256 output)


def C(state: bytes, block: bytes) -> bytes:
    """Toy Merkle-Damgard compression function C: {0,1}^w x {0,1}^w -> {0,1}^w.
    block may be a genuine data element OR a free-start re-injection of an
    earlier state.  Security of the whole scheme reduces to C being
    free-start-collision-resistant (Assumption 1, report S4)."""
    assert len(state) == STATE_SIZE and len(block) == STATE_SIZE
    return hashlib.sha256(b"\x01" + state + block).digest()


IV = hashlib.sha256(b"LogLink-IV").digest()


def pad(x: bytes) -> bytes:
    if len(x) < STATE_SIZE:
        return x + b"\x00" * (STATE_SIZE - len(x))
    assert len(x) == STATE_SIZE
    return x


def popcount(x: int) -> int:
    return bin(x).count("1")


def position(a: int) -> int:
    """Closed-form position of D[a] in the structured file, for ANY
    0 <= a < N (not just even a -- the formula itself does not need that
    restriction, though the only caller in this file, illustrate.py's
    drawing code, happens to only ever ask for even a, since that is all a
    single-element proof's base pair needs). O(1), no table."""
    return 2 * a - popcount(a)


def block_len(k: int) -> int:
    """# structured items in one full block covering 2^k elements, k>=1."""
    return (1 << (k + 1)) - 1


# ===========================================================================
# Construction  (report S1)
# ===========================================================================
@dataclass
class StructuredFile:
    N: int
    L: int
    elements: List[bytes]
    items: List[Tuple[str, int]] = field(default_factory=list)
    checkpoint: Dict[int, bytes] = field(default_factory=dict)   # a -> state before block(a,*)
    ending: Dict[Tuple[int, int], bytes] = field(default_factory=dict)  # (a,k)-> state after block(a,k)
    prewrap: Dict[Tuple[int, int], bytes] = field(default_factory=dict)  # (a,k)-> state right before block(a,k)'s own final MID(a) step
    digest: bytes = b""


def build(elements: List[bytes]) -> StructuredFile:
    N = len(elements)
    L = int(round(math.log2(N)))
    assert 1 << L == N, "N must be a power of two in this prototype"
    sf = StructuredFile(N=N, L=L, elements=[pad(e) for e in elements])
    state = IV

    def emit_data(i):
        nonlocal state
        sf.items.append(("D", i))
        state = C(state, sf.elements[i])

    def emit_mid(a):
        nonlocal state
        sf.items.append(("MID", a))
        state = C(state, sf.checkpoint[a])

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
    sf.digest = state
    return sf


# ===========================================================================
# Single-element inclusion proof  (report S2, S3)
# ===========================================================================
@dataclass
class Proof:
    index: int
    d0: bytes
    d1: bytes
    reveals: List[bytes] = field(default_factory=list)  # exactly L-1 opaque state values
    # 'tags' kept only for human-readable printing / debugging, not needed by the verifier
    tags: List[str] = field(default_factory=list)

    def nbytes(self) -> int:
        return 2 * len(self.d0) + len(self.reveals) * STATE_SIZE


def build_proof(sf: StructuredFile, index: int) -> Proof:
    L, N = sf.L, sf.N
    a0 = index - (index % 2)
    pf = Proof(index=index, d0=sf.elements[a0], d1=sf.elements[a0 + 1])

    half_top = 1 << (L - 1)
    target_in_first_half = a0 < half_top

    def recurse(a, k, target):
        """Emit reveals to go from block(a,k)'s own checkpoint up to
        block(a,k)'s ending, given target (=a0) lies inside block(a,k).
        Returns nothing; reveals are appended to pf.reveals in bottom-up
        order along target's path within this block (NOT including the
        base pair data, which is already in pf.d0/d1)."""
        if k == 1:
            return
        half = 1 << (k - 1)
        if target < a + half:
            recurse(a, k - 1, target)
            # Must reveal the sibling's PRE-wrap value (not its full ending):
            # the verifier folds in the target's own just-computed ending
            # via one more C() call, which is what actually binds the
            # target's data into the final result. Revealing the sibling's
            # full (already-wrapped) ending here would let a cheating
            # prover swap in arbitrary target data with no detectable
            # effect on the final check -- see report S4 for the security
            # argument this closes.
            pf.reveals.append(sf.prewrap[(a + half, k - 1)])
            pf.tags.append(f"sibling_prewrap(a={a+half},k={k-1}) [target in LEFT child]")
        else:
            pf.reveals.append(sf.ending[(a, k - 1)])
            pf.tags.append(f"sibling_end(a={a},k={k-1}) [target in RIGHT child, becomes ckpt]")
            recurse(a + half, k - 1, target)

    if target_in_first_half:
        recurse(0, L - 1, a0)
        pf.reveals.append(sf.prewrap[(half_top, L - 1)])
        pf.tags.append(f"TOP prewrap(a={half_top},k={L-1}) [target in FIRST half]")
    else:
        pf.reveals.append(sf.ending[(0, L - 1)])
        pf.tags.append(f"TOP ending(a=0,k={L-1}) = checkpoint[half] [target in SECOND half]")
        recurse(half_top, L - 1, a0)

    return pf


def verify_proof(N: int, digest: bytes, index: int, data: bytes, pf: Proof) -> bool:
    """Verifier: O(log N) compression-function calls. Never touches the
    full file, never uses a position table."""
    L = int(round(math.log2(N)))
    if 1 << L != N:
        return False
    a0 = index - (index % 2)
    if pf.index != index:
        return False
    if index == a0 and data != pf.d0:
        return False
    if index == a0 + 1 and data != pf.d1:
        return False

    half_top = 1 << (L - 1)
    target_in_first_half = a0 < half_top
    it = iter(pf.reveals)

    def eval_block(a, k, target, ckpt):
        """Returns ending(a,k) given target lies inside block(a,k) and ckpt
        = checkpoint[a] (the true state right before this block)."""
        if k == 1:
            s = C(C(ckpt, pf.d0), pf.d1)
            return C(s, ckpt)
        half = 1 << (k - 1)
        if target < a + half:
            left_end = eval_block(a, k - 1, target, ckpt)
            try:
                sib_prewrap = next(it)
            except StopIteration:
                raise ValueError("proof too short")
            right_end = C(sib_prewrap, left_end)  # fold target's verified value in
            return C(right_end, ckpt)
        else:
            try:
                left_end = next(it)
            except StopIteration:
                raise ValueError("proof too short")
            right_end = eval_block(a + half, k - 1, target, left_end)
            return C(right_end, ckpt)

    try:
        if target_in_first_half:
            y = eval_block(0, L - 1, a0, IV)
            r2 = next(it)
            computed = C(r2, y)
        else:
            y_reveal = next(it)
            computed = eval_block(half_top, L - 1, a0, y_reveal)
    except (ValueError, StopIteration):
        return False

    # any leftover reveals => malformed proof
    if any(True for _ in it):
        return False

    return computed == digest


# ===========================================================================
# Multi-proof (batch) construction  (report S6)
# ===========================================================================
def build_multiproof(sf: StructuredFile, indices: List[int]):
    """Returns (pairs_data, reveal_list) where pairs_data is a dict
    a0 -> (D[a0], D[a0+1]) for every distinct target pair, and reveal_list
    is the ordered list of opaque state reveals shared across all targets
    (each internal frontier value sent at most once)."""
    L, N = sf.L, sf.N
    half_top = 1 << (L - 1)
    targets = sorted(set(i - (i % 2) for i in indices))
    pairs_data = {a0: (sf.elements[a0], sf.elements[a0 + 1]) for a0 in targets}

    reveal_list: List[bytes] = []
    tags: List[str] = []

    def covers(a, k, tgt_set):
        """subset of tgt_set inside block(a,k)"""
        lo, hi = a, a + (1 << k) - 1
        return [t for t in tgt_set if lo <= t <= hi]

    def recurse(a, k, tgt_set):
        if not tgt_set:
            return
        if k == 1:
            return
        half = 1 << (k - 1)
        left = covers(a, k - 1, tgt_set)
        right = covers(a + half, k - 1, tgt_set)
        if left and right:
            recurse(a, k - 1, left)
            recurse(a + half, k - 1, right)
        elif left:
            recurse(a, k - 1, left)
            reveal_list.append(sf.prewrap[(a + half, k - 1)])
            tags.append(f"sibling_prewrap(a={a+half},k={k-1})")
        else:  # right only
            reveal_list.append(sf.ending[(a, k - 1)])
            tags.append(f"sibling_end/ckpt(a={a},k={k-1})")
            recurse(a + half, k - 1, right)

    left_targets = [t for t in targets if t < half_top]
    right_targets = [t for t in targets if t >= half_top]
    if left_targets and right_targets:
        recurse(0, L - 1, left_targets)
        recurse(half_top, L - 1, right_targets)
    elif left_targets:
        recurse(0, L - 1, left_targets)
        reveal_list.append(sf.prewrap[(half_top, L - 1)])
        tags.append(f"TOP sibling_prewrap(a={half_top},k={L-1})")
    else:
        reveal_list.append(sf.ending[(0, L - 1)])
        tags.append(f"TOP sibling_end/ckpt(a=0,k={L-1})")
        recurse(half_top, L - 1, right_targets)

    return pairs_data, reveal_list, tags


def verify_multiproof(N, digest, claims: Dict[int, bytes],
                      pairs_data: Dict[int, Tuple[bytes, bytes]], reveal_list: List[bytes]) -> bool:
    """VerifyMultiProof (paper, Section 7.1). `claims` is the verifier's
    OWN target set T with the data it wants checked, index -> data. The
    pair starts are derived from T alone -- never from the proof's own
    keys (the multi-target analogue of the single-proof a0 rule) -- and
    the proof must carry exactly one (d0, d1) pair per derived pair start,
    no more and no fewer."""
    L = int(round(math.log2(N)))
    if N < 4 or 1 << L != N:
        return False
    if not claims or any(t < 0 or t >= N for t in claims):
        return False
    targets = sorted({t - (t % 2) for t in claims})
    if set(pairs_data.keys()) != set(targets):
        return False
    for t, data in claims.items():
        d0, d1 = pairs_data[t - (t % 2)]
        if data != (d0 if t % 2 == 0 else d1):
            return False
    half_top = 1 << (L - 1)
    it = iter(reveal_list)

    def covers(a, k, tgt):
        lo, hi = a, a + (1 << k) - 1
        return [t for t in tgt if lo <= t <= hi]

    def eval_block(a, k, tgt_set, ckpt):
        if k == 1:
            (a0,) = tgt_set
            d0, d1 = pairs_data[a0]
            s = C(C(ckpt, d0), d1)
            return C(s, ckpt)
        half = 1 << (k - 1)
        left = covers(a, k - 1, tgt_set)
        right = covers(a + half, k - 1, tgt_set)
        if left and right:
            left_end = eval_block(a, k - 1, left, ckpt)
            right_end = eval_block(a + half, k - 1, right, left_end)
            return C(right_end, ckpt)
        elif left:
            left_end = eval_block(a, k - 1, left, ckpt)
            sib_prewrap = next(it)
            right_end = C(sib_prewrap, left_end)  # fold verified targets into the frontier value
            return C(right_end, ckpt)
        else:
            left_end = next(it)
            right_end = eval_block(a + half, k - 1, right, left_end)
            return C(right_end, ckpt)

    try:
        left_targets = [t for t in targets if t < half_top]
        right_targets = [t for t in targets if t >= half_top]
        if left_targets and right_targets:
            y = eval_block(0, L - 1, left_targets, IV)
            r2 = eval_block(half_top, L - 1, right_targets, y)
            computed = r2
        elif left_targets:
            y = eval_block(0, L - 1, left_targets, IV)
            r2 = next(it)
            computed = C(r2, y)
        else:
            y_reveal = next(it)
            computed = eval_block(half_top, L - 1, right_targets, y_reveal)
    except (StopIteration, ValueError, KeyError):
        return False

    if any(True for _ in it):
        return False
    return computed == digest


# ===========================================================================
# Self-test
# ===========================================================================
if __name__ == "__main__":
    random.seed(1)

    # position() unit test: brute-force each index's true item position
    # directly from sf.items (built by the recursive construction, no
    # closed-form formula involved) and check it against position(a) for
    # EVERY a, not just even a -- Lemma 2.1 only ever needed for even a
    # (build_proof/verify_proof branch on t < a+h and never call position()
    # or the a mod 2^(k+1) test at all; position() is used solely by
    # illustrate.py, for drawing/printing), but the formula itself holds
    # unrestricted.
    for L in (2, 3, 4, 5, 6):
        N = 1 << L
        elements = [hashlib.sha256(f"pos-{L}-{i}".encode()).digest() for i in range(N)]
        sf = build(elements)
        true_pos = {}
        for p, (kind, a) in enumerate(sf.items):
            if kind == "D" and a not in true_pos:
                true_pos[a] = p
        for a in range(N):
            assert position(a) == true_pos[a], \
                f"position({a}) = {position(a)}, but item {a} is really at {true_pos[a]} (N={N})"
    print(f"position(a) == 2a - popcount(a): verified against the built structured file "
          f"for every a (even and odd) at N in {{4,8,16,32,64}}  [OK]")

    for L in (2, 3, 4, 5, 6):
        N = 1 << L
        elements = [hashlib.sha256(f"elt-{L}-{i}".encode()).digest() for i in range(N)]
        sf = build(elements)
        ok_count = 0
        reveal_counts = []
        for i in range(N):
            pf = build_proof(sf, i)
            data = elements[i]
            ok = verify_proof(N, sf.digest, i, data, pf)
            assert ok, f"N={N} index={i} FAILED to verify"
            # tamper test: wrong data must fail
            bad = bytearray(data); bad[0] ^= 1
            assert not verify_proof(N, sf.digest, i, bytes(bad), pf), "tamper accepted!"
            # tamper test: flip EVERY individual reveal, one at a time (not
            # just one randomly chosen reveal) -- this is what actually
            # justifies claiming every revealed value in every proof is
            # tamper-tested, not merely a sample of them.
            for j in range(len(pf.reveals)):
                pf2 = Proof(pf.index, pf.d0, pf.d1, list(pf.reveals))
                r = bytearray(pf2.reveals[j]); r[0] ^= 1
                pf2.reveals[j] = bytes(r)
                assert not verify_proof(N, sf.digest, i, data, pf2), \
                    f"tampered reveal #{j} accepted! (N={N}, index={i})"
            reveal_counts.append(len(pf.reveals))
            ok_count += 1

        # index-relabeling attack test: a proof honestly built for the
        # EVEN index of a pair must not verify against the ODD index of
        # the same pair (or vice versa) even though it carries that other
        # index's own raw data as one of its two base-pair elements, and
        # even though the recursion path is identical for both (branch
        # decisions never look at the pair's own low bit). This is exactly
        # the attack a verifier that trusted a proof-supplied pair start
        # would fall for.
        for a0 in range(0, N, 2):
            pf_even = build_proof(sf, a0)       # built claiming index a0
            other = a0 + 1
            # Querying the OTHER index of the same pair, with that index's
            # OWN genuine data, using the proof built for a0: must fail.
            assert not verify_proof(N, sf.digest, other, elements[other], pf_even), \
                f"index-relabeling: proof built for {a0} wrongly verified for {other}! N={N}"
            # The more dangerous case: querying the other index while
            # supplying the WRONG data (a0's own data, i.e. the value a
            # relabeling attacker would substitute) must also fail.
            assert not verify_proof(N, sf.digest, other, elements[a0], pf_even), \
                f"index-relabeling: proof for {a0} accepted {a0}'s data as index {other}'s! N={N}"

        print(f"N={N:3d} L={L}: all {ok_count} single-element proofs verify OK; "
              f"reveal counts = {sorted(set(reveal_counts))} "
              f"(avg={sum(reveal_counts)/len(reveal_counts):.3f}, expected L-1={L-1})")

    # multiproof test
    N = 32
    L = 5
    elements = [hashlib.sha256(f"mp-{i}".encode()).digest() for i in range(N)]
    sf = build(elements)
    for trial in range(20):
        k = random.randint(1, 10)
        idxs = random.sample(range(N), k)
        pairs, reveals, tags = build_multiproof(sf, idxs)
        claims = {i: elements[i] for i in idxs}
        ok = verify_multiproof(N, sf.digest, claims, pairs, reveals)
        assert ok, f"multiproof failed for idxs={idxs}"

        # claimed data must match the pair element selected by the
        # verifier's own index parity
        t_bad = random.choice(idxs)
        bad_claims = dict(claims); bc = bytearray(claims[t_bad]); bc[0] ^= 1
        bad_claims[t_bad] = bytes(bc)
        assert not verify_multiproof(N, sf.digest, bad_claims, pairs, reveals), \
            f"multiproof accepted wrong claimed data! idxs={idxs}"
        # relabeling: claiming the OTHER index of a pair with this pair's
        # opposite element must fail (pair start derived from T, not pi)
        t0 = random.choice(idxs); other = t0 ^ 1
        if other not in claims:
            rel = dict(claims); del rel[t0]; rel[other] = elements[t0]
            assert not verify_multiproof(N, sf.digest, rel, pairs, reveals), \
                f"multiproof relabeling accepted! idxs={idxs}"
        # a proof carrying an extra, unclaimed pair must be rejected
        extra = next((a for a in range(0, N, 2) if a not in pairs), None)
        if extra is not None:
            ep = dict(pairs); ep[extra] = (elements[extra], elements[extra + 1])
            assert not verify_multiproof(N, sf.digest, claims, ep, reveals), \
                "multiproof with an extra unclaimed pair accepted!"

        # negative tests: tamper one data element, then (if any exist) one
        # shared reveal, and confirm rejection -- multiproofs previously had
        # no tamper test at all.
        tampered_a0 = random.choice(list(pairs.keys()))
        d0, d1 = pairs[tampered_a0]
        bad_d0 = bytearray(d0); bad_d0[0] ^= 1
        bad_pairs = dict(pairs); bad_pairs[tampered_a0] = (bytes(bad_d0), d1)
        assert not verify_multiproof(N, sf.digest, claims, bad_pairs, reveals), \
            f"multiproof accepted tampered data! idxs={idxs}"

        if reveals:
            j = random.randrange(len(reveals))
            bad_reveals = list(reveals)
            r = bytearray(bad_reveals[j]); r[0] ^= 1
            bad_reveals[j] = bytes(r)
            assert not verify_multiproof(N, sf.digest, claims, pairs, bad_reveals), \
                f"multiproof accepted tampered reveal #{j}! idxs={idxs}"
    print("multiproof: 20 random trials all verify OK; data, reveal, claimed-data, relabeling and extra-pair tamper tests all rejected")
    print("\nAll self-tests passed.")
