"""
fraud_proof.py -- detecting and proving, in O(log N) verifier work, that a
*published* structured file S' deviates from FlatMerkle's canonical layout
(i.e. contains a MID block whose content does not equal the true CK[a]
checkpoint it is supposed to re-inject).

Motivation (see the "malicious publisher" discussion): a publisher who
controls the exact bytes of S' can forge an *accepting* inclusion proof for
fake data at some index, by writing the wrong value into one MID block. The
forged proof itself looks completely normal to an ordinary verifier -- it
was never checked against the real file, only against the digest. This
module gives anyone who *can* see the full S' (a "watcher") a way to do the
O(N) work of finding the bad block(s) once, off-chain, and then produce a
short, O(log N) *fraud proof* that a lightweight on-chain verifier -- who
never sees more than a handful of 32/64-byte values -- can check in O(log N)
compression-function calls, conclusively proving S' is not canonically
built, without re-hashing the file.

Three pieces:

  scan_for_violations(N, raw_bytes)
      O(N): walks the file once, exactly like ordinary hashing, and
      records every MID block whose content disagrees with pad_b(CK[a]),
      the checkpoint that was captured the first time position a was
      reached (NOT the running state at the point the MID closes -- that
      is a different value, prewrap(a,k); conflating the two is exactly
      the class of bug this whole mechanism exists to catch).

  build_fraud_proof(scan, target, violated)
      O(log N): builds an ordinary-shaped BuildProof path for `target`
      (same sibling reveals, same two raw base-case data elements, all the
      way down -- this is exactly what an honest inclusion proof for that
      index would look like, reconstructed from the real file), plus the
      real bytes physically written at EVERY disputed MID(a,k) slot in
      `violated` -- a list of (a,k) pairs, each of which must be one of
      `target`'s own containing blocks (self_positions(L, target) computes
      this set; see below). Substituting at every violated self-position
      simultaneously (not just the deepest one) is what lets a fraud proof
      succeed against a chain of nested/multi-level violations on target's
      own path -- see the "Scope" note below for why substitution is
      restricted to self-positions specifically, and not sibling blocks
      encountered along the way.

  self_positions(L, target)
      Structural, no hashing: target's own containing blocks, i.e.
      block(a,k) for every level k=1..L-1 such that a <= target < a+2**k.
      These are the ONLY positions a fraud proof anchored at `target` can
      safely substitute real bytes for -- see the "Scope" note for why a
      sibling block's own closing position is NOT safe to substitute, even
      though it is visited (as an opaque reveal) along target's path.
      Exactly L-1 positions, O(log N).

  provable_set(scan, target)
      self_positions(scan.L, target) intersected with scan's actual
      violations -- exactly the `violated` list to pass to
      build_fraud_proof to get an accepting proof anchored at `target`.

  pick_provable_target(scan)
      Returns target = the `a` of the violation with the LARGEST `a`
      value among everything the scan found (or None if the scan found no
      violations). This specific choice is what makes fraud-proof
      *completeness* hold in general -- see the "Scope" note.

  verify_fraud_proof(N, digest, fp)
      O(log N): runs the *same* EvalBlock recursion an ordinary verifier
      runs -- so every checkpoint used anywhere in the fold is bound to
      the digest exactly as it always is (soundness is inherited
      unchanged from ordinary proof verification) -- except that at every
      claimed-violated level, instead of trusting the checkpoint the
      recursion itself computes, it substitutes the real bytes the proof
      supplies for that level, and separately records whether those real
      bytes agree with what the checkpoint says they should be. If the
      whole fold still reaches the digest (proving every other value used
      was genuine), every claimed-violated level was genuinely visited on
      target's own path, AND at least one of them actually disagreed,
      the file is proven non-canonical.

Everything here is checked against real SHA-256 (sha256_core.compress),
the same primitive used throughout the rest of the reference
implementation, so this is not a toy: the digests, proofs, and fraud
proofs constructed here are literal SHA-256 objects.

Scope note (what this does and does not prove):

1. Multi-level self-substitution (this module's `violated` list, computed
   by provable_set) closes the nested/chained gap a naive single-point
   proof has: if two or more violations lie on the SAME root-to-leaf path
   (e.g. block(0,1) and block(0,2) are both corrupted), a proof that only
   substitutes at the deepest one fails to reach the digest, because the
   ancestor level's real (also-corrupted) bytes differ from the canonical
   value the recursion would otherwise use there -- and a proof that only
   substitutes at the ancestor fails for the symmetric reason. Substituting
   real bytes at every violated level on target's own chain simultaneously
   closes this gap.

   Substitution is deliberately restricted to target's own containing
   blocks (self_positions), never a sibling block's own closing step,
   even though such a sibling is visited along the way (its prewrap is
   revealed, then its closing step is recomputed canonically in-line,
   never checked against the file). Allowing substitution there too looks
   tempting -- it is what closes the remaining single-violation gap below
   -- but it silently breaks binding: the sibling's canonical closing step
   is the ONLY place the checkpoint value threaded down from target's own
   base data is ever used again once computed, so replacing it with an
   unconstrained claimed value severs every earlier value on target's
   chain (target's own base elements included) from the digest entirely,
   letting a forger supply fabricated base data and reach an accepting
   proof against a fully canonical file, with no collision needed at all.
   (An earlier design attempted exactly this and was caught by a
   tamper-injection test: flipping a bit of the proof's own base element
   left verification unaffected, which is only possible if that element
   was never actually bound to the digest.) So a violation that sits on a
   sibling's own closing step, for a given target, is simply not provable
   via that target -- see point 2 for why this does not weaken
   completeness.

2. Completeness still holds in general, via a specific, always-safe choice
   of target: pick target = the `a` of the violation with the LARGEST `a`
   value among everything the scan found (pick_provable_target). Every
   *other* violation's block-range lies either inside one of this target's
   own containing blocks (so it is itself a self-position, safely
   provable) or, at every level where this target's path branches left,
   strictly to the right of the sibling encountered there (since the
   sibling's whole range has a larger `a` than the chosen target's, and
   the chosen target's `a` is the maximum) -- so that sibling, and
   everything inside it, is guaranteed canonical, and the ordinary
   recursion's in-line canonical recomputation there is simply correct.
   The chosen target's own self-chain is therefore never blocked by
   anything happening elsewhere in the file: at least one accepting
   O(log N) fraud proof always exists for any non-canonical file, without
   ever touching a sibling's closing step.

3. Localization is weaker than it may look, even restricted to
   self-substitution. An accepting fraud proof with a recorded mismatch
   proves the committed file is non-canonical SOMEWHERE (up to a
   free-start collision) -- it does not, by itself, prove that every
   individual level flagged as "violated" is truly where the corruption
   lives, versus an attacker choosing to substitute a bogus claim at an
   innocent level while relying on fabricated (but digest-consistent)
   data elsewhere on the same path to make the whole fold still land on
   the real digest. Binding (the single-element analogue) pins down the
   outermost accepted (index, data) pair for an ORDINARY, unmodified
   verifier execution; it does not, on its own, pin down every
   intermediate reveal fed into this module's MODIFIED, multi-substitution
   recursion. Treat an accepting fraud proof as proof that "this file
   should be rejected," not as a certified pointer to the exact corrupted
   byte range.
"""
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from loglink import position, block_len
from illustrate import layout, Item
from sha256_core import compress, length_padding_blocks, IV_STD, STATE_SIZE, BLOCK_SIZE
from loglink_annex import mid_block, pad_element, total_raw_len


# ---------------------------------------------------------------------------
# Scanning: find every position where a MID's content disagrees with
# pad_b(CK[a]), the block's true entry checkpoint. O(N), one linear pass.
# ---------------------------------------------------------------------------
@dataclass
class Violation:
    a: int              # block start index of the offending block(a,k)
    k: int                # level
    pos: int               # item position (0-indexed) of the offending MID
    true_checkpoint: bytes  # CK[a]: the real state entering position(a)
    actual_bytes: bytes      # the real bytes physically written there


@dataclass
class ScanResult:
    N: int
    L: int
    raw_bytes: bytes
    items: List[Item]
    state_before: List[bytes]   # state_before[pos] = running state entering item at `pos`
    state_after: List[bytes]    # state_after[pos]  = running state leaving item at `pos`
    mid_pos: Dict[Tuple[int, int], int]  # (a,k) -> item position of MID(a,k)
    data_pos: Dict[int, int]              # i -> item position of D[i]
    checkpoint: Dict[int, bytes]          # a -> CK[a]
    violations: List[Violation]

    def prewrap_of(self, a: int, k: int) -> bytes:
        return self.state_before[self.mid_pos[(a, k)]]

    def ending_of(self, a: int, k: int) -> bytes:
        return self.state_after[self.mid_pos[(a, k)]]

    def data_of(self, i: int) -> bytes:
        off = self.data_pos[i] * BLOCK_SIZE
        return self.raw_bytes[off:off + BLOCK_SIZE]

    def mid_bytes_of(self, a: int, k: int) -> bytes:
        off = self.mid_pos[(a, k)] * BLOCK_SIZE
        return self.raw_bytes[off:off + BLOCK_SIZE]


def scan_for_violations(N: int, raw_bytes: bytes) -> ScanResult:
    """O(N): walk the file exactly like ordinary SHA-256 hashing (using
    the file's *actual* bytes throughout, right or wrong -- this is
    precisely what the real digest computation does), and record every
    MID whose content disagrees with pad_b(CK[a]). Continuing with the
    actual bytes after a violation (rather than the value that *should*
    have been there) is what lets a single pass find multiple,
    independent violations -- nested or not -- without one masking
    another."""
    L = int(round(math.log2(N)))
    assert 1 << L == N, "N must be a power of two"
    items = layout(N)
    M = len(items)
    assert len(raw_bytes) == M * BLOCK_SIZE, "raw_bytes length does not match N"

    state_before: List[Optional[bytes]] = [None] * M
    state_after: List[Optional[bytes]] = [None] * M
    mid_pos: Dict[Tuple[int, int], int] = {}
    data_pos: Dict[int, int] = {}
    checkpoint: Dict[int, bytes] = {}
    violations: List[Violation] = []

    state = IV_STD
    for it in items:
        state_before[it.pos] = state
        if it.kind == "D":
            data_pos[it.a] = it.pos
            if it.a not in checkpoint:
                checkpoint[it.a] = state   # CK[a]: captured once, the first time position(a) is reached
        off = it.pos * BLOCK_SIZE
        actual = bytes(raw_bytes[off:off + BLOCK_SIZE])
        if it.kind == "MID":
            mid_pos[(it.a, it.k)] = it.pos
            expected = mid_block(checkpoint[it.a])
            if actual != expected:
                violations.append(Violation(a=it.a, k=it.k, pos=it.pos,
                                             true_checkpoint=checkpoint[it.a], actual_bytes=actual))
        state = compress(state, actual)   # always advance using the REAL bytes
        state_after[it.pos] = state

    return ScanResult(N=N, L=L, raw_bytes=raw_bytes, items=items, state_before=state_before,
                       state_after=state_after, mid_pos=mid_pos, data_pos=data_pos,
                       checkpoint=checkpoint, violations=violations)


def self_positions(L: int, target: int) -> List[Tuple[int, int]]:
    """Structural (no hashing, no scan needed): target's own containing
    blocks -- block(a,k) for every level k=1..L-1 such that a <= target <
    a + 2**k. These are the ONLY positions a fraud proof anchored at
    `target` can safely substitute real bytes for (see the module
    docstring's Scope note for why a sibling block's own closing step,
    also visited along target's path, is deliberately excluded). Exactly
    L-1 positions, O(log N)."""
    half_top = 1 << (L - 1)
    base = half_top if target >= half_top else 0
    positions: List[Tuple[int, int]] = []
    k = L - 1
    while k >= 1:
        width = 1 << k
        a = base + ((target - base) // width) * width
        positions.append((a, k))
        k -= 1
    return positions


def anchored_levels(L: int, target: int, violated) -> set:
    """Structural (no hashing): the subset of target's own containing
    levels (a_k, k), a_k = floor(target / 2**k) * 2**k, whose checkpoint
    argument is *anchored* -- i.e. still consumed by at least one
    compression call that is NOT overridden by a disputed-level
    substitution, so that the fold-to-digest check pins it down:

        bnd(1) = True                (the base case consumes ckpt in
                                      C(ckpt, d0) whether or not its
                                      closing fold is substituted)
        bnd(k) = (a_k, k) not in V
                 or (bit_{k-1}(target) == 0 and bnd(k-1))   2 <= k <= L-1
        additionally bnd(L-1) = True when target < 2**(L-1): the top-level
        left root's checkpoint is the public constant IV, fixed by the
        verifier itself.

    A disputed level whose checkpoint is NOT anchored has a checkpoint
    that feeds no compression call at all once its own closing fold is
    substituted (in a right branch the child is seeded with a separately
    revealed value, not with ckpt), so the prover can set it to anything
    and fabricate a mismatch against a perfectly canonical file.
    verify_fraud_proof therefore still SUBSTITUTES at unanchored disputed
    levels (needed to reach the digest when an ancestor is genuinely
    corrupted), but only COUNTS a mismatch at anchored ones.

    See simulate_fraud_proofs.py, Case J, for the attack this closes."""
    V = set(violated)
    out = set()
    prev = True
    for k in range(1, L):
        a = (target >> k) << k
        if k == 1:
            b = True
        else:
            b = ((a, k) not in V) or ((((target >> (k - 1)) & 1) == 0) and prev)
        if k == L - 1 and target < (1 << (L - 1)):
            b = True
        if b:
            out.add((a, k))
        prev = b
    return out


def provable_set(scan: ScanResult, target: int) -> List[Tuple[int, int]]:
    """Convenience helper for a watcher: self_positions(scan.L, target)
    intersected with the violations the scan actually found -- exactly the
    `violated` list to pass to build_fraud_proof to get an accepting proof
    anchored at `target`."""
    reachable = set(self_positions(scan.L, target))
    found = {(v.a, v.k) for v in scan.violations}
    return sorted(reachable & found, key=lambda ak: ak[1])


def pick_provable_target(scan: ScanResult) -> Optional[int]:
    """Returns target = the `a` of the violation with the largest `a`
    value among everything the scan found, or None if the scan found no
    violations. provable_set(scan, this target) is then always non-empty
    and always yields an accepting fraud proof, regardless of what else in
    the file is independently corrupted -- see the module docstring's
    Scope note (point 2) for why this specific choice is always safe."""
    if not scan.violations:
        return None
    return max(v.a for v in scan.violations)


def chain_for_target(scan: ScanResult, target: int) -> List[Tuple[int, int]]:
    """Deprecated alias, kept for backward compatibility: the older name
    for what is now provable_set. New code should call provable_set
    directly."""
    return provable_set(scan, target)


# ---------------------------------------------------------------------------
# Fraud proof: build (O(log N)) and verify (O(log N))
# ---------------------------------------------------------------------------
@dataclass
class FraudProof:
    N: int
    target: int                 # the index whose own root-to-leaf path this proof walks
    violated: Tuple[Tuple[int, int], ...]   # every (a,k) substituted along that path
    d0: bytes                    # real D[a0], a0 = target - (target % 2)
    d1: bytes                     # real D[a0+1]
    reveals: List[bytes]           # ordinary BuildProof-shaped sibling reveals, target = `target`
    actual_mid_bytes: Dict[Tuple[int, int], bytes]   # (a,k) -> real bytes physically at MID(a,k)

    def nbytes(self) -> int:
        return (2 * BLOCK_SIZE + len(self.reveals) * STATE_SIZE
                + len(self.violated) * BLOCK_SIZE)


def build_fraud_proof(scan: ScanResult, target: int,
                       violated: Sequence[Tuple[int, int]]) -> FraudProof:
    """O(log N) (well, O(log N + |violated|), and |violated| <= L-1): an
    ordinary, full BuildProof-shaped reveal path for `target` (exactly
    L-1 reveals, exactly like a real inclusion proof), reconstructed from
    the real file's own honestly-recomputed prewrap/ending values, plus
    the real bytes physically present at every disputed MID(a,k) in
    `violated`. Every (a,k) in `violated` MUST be one of `target`'s own
    containing blocks -- self_positions(L, target) computes this set (this
    is asserted, not silently corrected) -- `provable_set` computes a
    valid list automatically from a scan."""
    L = scan.L
    half_top = 1 << (L - 1)
    reveals: List[bytes] = []
    violated = list(violated)
    valid_positions = set(self_positions(L, target))
    for (a, k) in violated:
        assert (a, k) in valid_positions, (
            f"({a},{k}) is not one of target {target}'s own containing "
            f"blocks (self_positions) -- a fraud proof cannot substitute a "
            f"sibling block's closing step, see the module docstring's "
            f"Scope note")

    def recurse(a, k, t):
        if k == 1:
            return
        half = 1 << (k - 1)
        if t < a + half:
            recurse(a, k - 1, t)
            reveals.append(scan.prewrap_of(a + half, k - 1))
        else:
            reveals.append(scan.ending_of(a, k - 1))
            recurse(a + half, k - 1, t)

    if target < half_top:
        recurse(0, L - 1, target)
        reveals.append(scan.prewrap_of(half_top, L - 1))
    else:
        reveals.append(scan.ending_of(0, L - 1))
        recurse(half_top, L - 1, target)

    a0 = target - (target % 2)
    actual_mid_bytes = {(a, k): scan.mid_bytes_of(a, k) for (a, k) in violated}
    return FraudProof(N=scan.N, target=target, violated=tuple(sorted(violated)),
                       d0=scan.data_of(a0), d1=scan.data_of(a0 + 1),
                       reveals=reveals, actual_mid_bytes=actual_mid_bytes)


def verify_fraud_proof(N: int, digest: bytes, fp: FraudProof,
                        count_calls: Optional[List[int]] = None) -> bool:
    """O(log N) compression calls. Runs exactly the same recursive fold an
    ordinary verifier runs for target index fp.target -- so every
    checkpoint used anywhere in this computation is bound to the digest
    exactly as it always is in ordinary proof verification -- except that
    at every level in fp.violated, the checkpoint the recursion would
    normally fold in is replaced by fp.actual_mid_bytes[(a,k)] (the real
    bytes claimed to sit directly in the file), and whether those two
    values actually agree is recorded per level. Accepts only if: the
    fold still reaches the digest (every non-violated value used was
    genuine), every claimed-violated (a,k) was genuinely visited on
    target's own path (not a bogus, off-path claim), and at least one
    claimed-violated level actually disagreed with the canonical value."""
    L = int(round(math.log2(N)))
    if 1 << L != N:
        return False
    if fp.target < 0 or fp.target >= N:
        return False

    def C(state, block):
        if count_calls is not None:
            count_calls[0] += 1
        return compress(state, block)

    half_top = 1 << (L - 1)
    it = iter(fp.reveals)
    violated_set = set(fp.violated)
    if set(fp.actual_mid_bytes.keys()) != violated_set:
        return False   # exactly one supplied byte string per disputed level
    if any(len(b) != BLOCK_SIZE for b in fp.actual_mid_bytes.values()):
        return False
    anchored = anchored_levels(L, fp.target, violated_set)
    levels_reached = set()
    mismatch_found = [False]

    def maybe_substitute(a, k, ckpt, honest_closing_block):
        if (a, k) in violated_set:
            levels_reached.add((a, k))
            claimed = fp.actual_mid_bytes[(a, k)]
            # A mismatch only counts where ckpt is anchored (see
            # anchored_levels): at an unanchored disputed level ckpt feeds
            # no non-substituted compression call, so it is a free
            # variable and comparing against it proves nothing.
            if claimed != honest_closing_block and (a, k) in anchored:
                mismatch_found[0] = True
            return claimed
        return honest_closing_block

    def eval_block(a, k, target, ckpt):
        if k == 1:
            s = C(C(ckpt, fp.d0), fp.d1)
            closing_block = maybe_substitute(a, k, ckpt, mid_block(ckpt))
            return C(s, closing_block)
        half = 1 << (k - 1)
        if target < a + half:
            left_end = eval_block(a, k - 1, target, ckpt)
            if left_end is None:
                return None
            try:
                sib_prewrap = next(it)
            except StopIteration:
                return None
            # Sibling block(a+half, k-1) is not yet closed here: its own
            # closing step is always recomputed canonically as
            # pad_b(left_end), deliberately NEVER substituted -- see the
            # module docstring's Scope note for why substituting here
            # would sever left_end (and everything upstream of it on
            # target's own chain, including the base data) from the
            # digest entirely, breaking binding. A violation actually
            # sitting at this position is simply not provable via this
            # target; pick_provable_target always avoids that situation.
            sib_closing = mid_block(left_end)
            right_end = C(sib_prewrap, sib_closing)
            closing_block = maybe_substitute(a, k, ckpt, mid_block(ckpt))
            return C(right_end, closing_block)
        else:
            try:
                left_end = next(it)
            except StopIteration:
                return None
            right_end = eval_block(a + half, k - 1, target, left_end)
            if right_end is None:
                return None
            closing_block = maybe_substitute(a, k, ckpt, mid_block(ckpt))
            return C(right_end, closing_block)

    try:
        if fp.target < half_top:
            y = eval_block(0, L - 1, fp.target, IV_STD)
            if y is None:
                return False
            r2 = next(it)
            # Top-level sibling (the right root block(half_top, L-1)) is
            # the same kind of not-yet-closed sibling as above -- its
            # closing step is likewise always canonical, never substituted.
            top_closing = mid_block(y)
            raw_state = C(r2, top_closing)
        else:
            y_reveal = next(it)
            raw_state = eval_block(half_top, L - 1, fp.target, y_reveal)
            if raw_state is None:
                return False
    except StopIteration:
        return False

    if any(True for _ in it):
        return False   # leftover reveals: malformed proof, reject

    if levels_reached != violated_set:
        return False   # some claimed-violated (a,k) was never actually on
                        # target's own path: malformed/dishonest claim

    pad = length_padding_blocks(total_raw_len(N))
    fstate = raw_state
    for i in range(0, len(pad), BLOCK_SIZE):
        fstate = C(fstate, pad[i:i + BLOCK_SIZE])

    if fstate != digest:
        # Binding check failed: this reveal path (including the two base
        # data elements) does not fold to the real digest, so nothing here
        # is proven -- reject as a malformed/dishonest fraud claim, not as
        # evidence the file is invalid.
        return False

    # Binding succeeded: every non-violated value used, and the real
    # base-case data, are now proven genuine (up to finding a free-start
    # collision) -- exactly the same guarantee ordinary proof soundness
    # gives. The fraud claim holds iff at least one claimed-violated level
    # actually disagreed with the canonical value.
    return mismatch_found[0]
