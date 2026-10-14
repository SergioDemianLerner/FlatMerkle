"""
simulate_fraud_proofs.py -- builds deliberately-cheated structured files
(one or more corrupted MID blocks each), confirms the fraud scanner finds
exactly the corrupted positions and nothing else, confirms every resulting
fraud proof verifies, confirms honest files and honest sub-claims produce
no (false-positive) fraud, confirms tampered fraud proofs are rejected,
confirms NESTED/chained violations on one path are correctly handled by
multi-level self-substitution, confirms that a violation sitting on a
SIBLING's own closing step (rather than one of a given target's own
containing blocks) is correctly refused by build_fraud_proof/deliberately
left unprovable via that target (substituting there would break binding --
see fraud_proof.py's module docstring), and confirms that
pick_provable_target's max-`a` strategy nonetheless always finds SOME
accepting proof regardless of what else in the file is independently
corrupted. Also measures the actual compression-call cost of verification
against a full O(N) rehash, across several N.
"""
import dataclasses
import hashlib
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))

from sha256_core import compress, length_padding_blocks, IV_STD, BLOCK_SIZE, STATE_SIZE
from loglink_annex import pad_element, mid_block
from illustrate import layout
from fraud_proof import (scan_for_violations, build_fraud_proof, verify_fraud_proof,
                          provable_set, self_positions, pick_provable_target, Violation,
                          anchored_levels)

random.seed(12345)


def build_with_cheats(elements, cheats):
    """Mirrors loglink_annex.build()'s recursion exactly, except that for
    every (a,k) in `cheats`, the MID(a,k) block written is random garbage
    instead of the honest checkpoint -- and everything AFTER that point is
    still built *honestly relative to the new, corrupted reality* (i.e.
    this models a sophisticated attacker who commits to an alternate
    version of the file and keeps it internally consistent from that point
    forward, rather than a sloppy one whose corruption cascades into an
    unintended pile of extra violations)."""
    N = len(elements)
    L = int(round(math.log2(N)))
    assert 1 << L == N
    elements = [pad_element(e) for e in elements]
    raw = bytearray()
    checkpoint = {}
    state = IV_STD

    def emit_data(i):
        nonlocal state
        blk = elements[i]
        raw.extend(blk)
        state = compress(state, blk)

    def emit_mid(a, k):
        nonlocal state
        if (a, k) in cheats:
            fake = os.urandom(STATE_SIZE)
            blk = mid_block(fake)
        else:
            blk = mid_block(checkpoint[a])
        raw.extend(blk)
        state = compress(state, blk)

    def block(a, k):
        nonlocal state
        if a not in checkpoint:
            checkpoint[a] = state
        if k == 1:
            emit_data(a)
            emit_data(a + 1)
            emit_mid(a, k)
        else:
            half = 1 << (k - 1)
            block(a, k - 1)
            block(a + half, k - 1)
            emit_mid(a, k)

    block(0, L - 1)
    block(1 << (L - 1), L - 1)
    raw_state = state

    pad = length_padding_blocks(len(raw))
    fstate = raw_state
    for i in range(0, len(pad), BLOCK_SIZE):
        fstate = compress(fstate, pad[i:i + BLOCK_SIZE])
    digest = fstate

    assert digest == hashlib.sha256(bytes(raw)).digest()
    return bytes(raw), digest


def full_rehash_call_count(raw_bytes):
    """Naive baseline: how many compress() calls a full rehash needs, for
    comparison against the fraud proof's O(log N) verification cost."""
    state = IV_STD
    calls = 0
    for i in range(0, len(raw_bytes), BLOCK_SIZE):
        state = compress(state, raw_bytes[i:i + BLOCK_SIZE])
        calls += 1
    return calls


def describe(v: Violation) -> str:
    return f"block(a={v.a}, k={v.k})@pos{v.pos}"


def valid_mid_positions(N):
    """All (a,k) that are genuine MID slots for this N, straight from the
    structural layout (no hashing needed)."""
    return [(it.a, it.k) for it in layout(N) if it.kind == "MID"]


def pick_independent_cheats(N, levels):
    """Pick one (a,k) per level in `levels`, such that no two chosen
    block(a,k) ranges nest inside one another (i.e. every violation sits
    on its own separate root-to-leaf path, with nothing corrupted either
    above or below it). This is the "independent, unrelated cheats in
    different subtrees" scenario Case D/E test, as distinct from Case F's
    deliberately-NESTED chain. Processes the largest (most space-hungry)
    levels first so later, smaller picks always have room."""
    positions = valid_mid_positions(N)
    by_level = {}
    for (a, k) in positions:
        by_level.setdefault(k, []).append(a)
    chosen = []
    ranges = []
    for k in sorted(levels, reverse=True):
        for a in by_level.get(k, []):
            lo, hi = a, a + (1 << k) - 1
            if all(hi < r0 or lo > r1 for (r0, r1) in ranges):
                chosen.append((a, k))
                ranges.append((lo, hi))
                break
        else:
            raise RuntimeError(f"no independent slot found for level {k} at N={N}")
    return chosen


def run_case(title, N, elements, cheats):
    print(f"\n=== {title} (N={N}, cheats={sorted(cheats)}) ===")
    raw, digest = build_with_cheats(elements, cheats)

    scan = scan_for_violations(N, raw)
    found = {(v.a, v.k) for v in scan.violations}
    print(f"  scan found {len(scan.violations)} violation(s): "
          f"{[describe(v) for v in scan.violations]}")
    assert found == cheats, f"scanner found {found}, expected {cheats}"

    rehash_calls = full_rehash_call_count(raw)
    L = int(round(math.log2(N)))

    for v in scan.violations:
        target = v.a
        violated = [(v.a, v.k)]
        fp = build_fraud_proof(scan, target, violated)
        calls = [0]
        ok = verify_fraud_proof(N, digest, fp, count_calls=calls)
        print(f"  fraud proof for {describe(v)}: {len(fp.reveals)} reveals, "
              f"{fp.nbytes()} bytes, {calls[0]} compression calls "
              f"(full rehash would need {rehash_calls}) -> verified={ok}")
        assert ok, "genuine fraud proof failed to verify!"
        assert calls[0] <= 2 * L + 6, f"verification used more than O(log N) calls: {calls[0]} vs L={L}"

        # Tamper the fraud proof itself: the binding (fold-to-digest) check
        # must reject it outright -- not just fail to find fraud, but
        # actively refuse to trust an unbound claim. This is exactly the
        # class of bug (an unverified value silently accepted) an earlier,
        # truncated design had: here every one of d0, d1, and every reveal
        # is used in a real compression call all the way to the digest, so
        # tampering any of them must break the fold.
        bad_d0 = bytearray(fp.d0); bad_d0[0] ^= 1
        fp_bad_d0 = dataclasses.replace(fp, d0=bytes(bad_d0))
        assert not verify_fraud_proof(N, digest, fp_bad_d0), \
            "tampered fraud proof (bad d0) was WRONGLY accepted!"

        bad_d1 = bytearray(fp.d1); bad_d1[0] ^= 1
        fp_bad_d1 = dataclasses.replace(fp, d1=bytes(bad_d1))
        assert not verify_fraud_proof(N, digest, fp_bad_d1), \
            "tampered fraud proof (bad d1) was WRONGLY accepted!"

        if fp.reveals:
            for idx in range(len(fp.reveals)):
                bad_reveals = list(fp.reveals)
                bi = bytearray(bad_reveals[idx]); bi[0] ^= 1
                bad_reveals[idx] = bytes(bi)
                fp_bad_r = dataclasses.replace(fp, reveals=bad_reveals)
                assert not verify_fraud_proof(N, digest, fp_bad_r), \
                    f"tampered fraud proof (bad reveal #{idx}) was WRONGLY accepted!"

        # Tampering actual_mid_bytes to match what the checkpoint says it
        # "should" be must make verify_fraud_proof report NO fraud (since
        # that is now, by the tampered claim, a truthful non-accusation) --
        # this is not a soundness break, just confirms the fraud
        # determination really does hinge on this one field.
        honest_actual = mid_block(v.true_checkpoint)
        if honest_actual != fp.actual_mid_bytes[(v.a, v.k)]:
            fp_hide = dataclasses.replace(
                fp, actual_mid_bytes={**fp.actual_mid_bytes, (v.a, v.k): honest_actual})
            hidden_ok = verify_fraud_proof(N, digest, fp_hide)
            assert hidden_ok is False, \
                "fraud proof with actual_mid_bytes replaced by the honest value still reported fraud!"

        # A bogus, off-path claim (an (a,k) that never actually occurs on
        # target's own recursion path) must be rejected outright, not
        # silently ignored.
        bogus_level = (v.a, v.k + 10)  # not a real block, and not on the path
        fp_bogus = dataclasses.replace(
            fp, violated=fp.violated + (bogus_level,),
            actual_mid_bytes={**fp.actual_mid_bytes, bogus_level: b"\x00" * BLOCK_SIZE})
        assert not verify_fraud_proof(N, digest, fp_bogus), \
            "fraud proof with a bogus off-path violated-level claim was WRONGLY accepted!"

    return scan, digest


def run_honest_case(N):
    print(f"\n=== Honest file, no cheats (N={N}) ===")
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    raw, digest = build_with_cheats(elements, cheats=set())
    scan = scan_for_violations(N, raw)
    print(f"  scan found {len(scan.violations)} violation(s) -- expected 0")
    assert len(scan.violations) == 0

    # Negative control: build a "fraud proof" for a position that is
    # actually fine (true checkpoint + true actual bytes agree) and confirm
    # verify_fraud_proof correctly reports NO fraud.
    any_a, any_k = valid_mid_positions(N)[0]
    fp = build_fraud_proof(scan, any_a, [(any_a, any_k)])
    ok = verify_fraud_proof(N, digest, fp)
    print(f"  fraud proof built for a genuinely-VALID block(a={any_a},k={any_k}): "
          f"verify_fraud_proof returned {ok} (must be False -- no fraud to find)")
    assert ok is False


def run_nested_case(title, N, elements, cheats):
    """Case F: two or more violations CHAINED/NESTED on the same
    root-to-leaf path (e.g. block(0,1) and block(0,2) both corrupted for
    N=8) -- the case a single-level substitution provably cannot handle.
    Demonstrates: (1) a fraud proof substituting only the deepest
    violation fails to reach the digest; (2) a fraud proof substituting
    only the shallowest (ancestor) violation also fails; (3) a fraud proof
    substituting EVERY violated level on the chain simultaneously
    succeeds, and every tamper variant of it is still rejected."""
    print(f"\n=== {title} (N={N}, cheats={sorted(cheats)}) ===")
    raw, digest = build_with_cheats(elements, cheats)
    scan = scan_for_violations(N, raw)
    found = {(v.a, v.k) for v in scan.violations}
    print(f"  scan found {len(scan.violations)} violation(s): {sorted(found)}")
    assert found == cheats, f"scanner found {found}, expected {cheats}"

    # All cheats here share the same `a` by construction (nested chain).
    target = next(iter(cheats))[0]
    assert all(a == target for (a, _k) in cheats), "test setup: cheats must share the same a"
    deepest_k = min(k for (_a, k) in cheats)
    shallow_ks = [k for (_a, k) in cheats if k != deepest_k]

    # (1) Single-level substitution at ONLY the deepest violation: must
    # fail to reach the digest, because the (also-corrupted) ancestor
    # level still uses the canonical value instead of its own real bytes.
    fp_deep_only = build_fraud_proof(scan, target, [(target, deepest_k)])
    ok_deep_only = verify_fraud_proof(N, digest, fp_deep_only)
    print(f"  single-substitution at deepest violation only (k={deepest_k}): "
          f"verified={ok_deep_only} (must be False)")
    assert ok_deep_only is False, \
        "BUG: single-level substitution at only the deepest nested violation " \
        "should NOT verify, but did -- multi-level substitution is not being tested"

    # (2) Single-level substitution at ONLY a shallower (ancestor)
    # violation: must also fail, symmetric reason.
    for k in shallow_ks:
        fp_shallow_only = build_fraud_proof(scan, target, [(target, k)])
        ok_shallow_only = verify_fraud_proof(N, digest, fp_shallow_only)
        print(f"  single-substitution at ancestor violation only (k={k}): "
              f"verified={ok_shallow_only} (must be False)")
        assert ok_shallow_only is False, \
            f"BUG: single-level substitution at only ancestor k={k} should NOT verify, but did"

    # (3) Multi-level substitution at EVERY violated level on the chain:
    # must succeed.
    chain = provable_set(scan, target)
    print(f"  provable_set({target}) = {chain}")
    assert set(chain) == cheats, f"provable_set found {chain}, expected {sorted(cheats)}"
    rehash_calls = full_rehash_call_count(raw)
    fp_full = build_fraud_proof(scan, target, chain)
    calls = [0]
    ok_full = verify_fraud_proof(N, digest, fp_full, count_calls=calls)
    print(f"  multi-level substitution at all {len(chain)} violated levels: "
          f"{fp_full.nbytes()} bytes, {calls[0]} compression calls "
          f"(full rehash would need {rehash_calls}) -> verified={ok_full}")
    assert ok_full, "BUG: multi-level substitution across the full nested chain should verify, but did not"

    L = int(round(math.log2(N)))
    assert calls[0] <= 2 * L + 6 + len(chain), \
        f"verification used more than O(log N) calls: {calls[0]} vs L={L}"

    # Tamper tests on the full (working) multi-level proof.
    bad_d0 = bytearray(fp_full.d0); bad_d0[0] ^= 1
    assert not verify_fraud_proof(N, digest, dataclasses.replace(fp_full, d0=bytes(bad_d0))), \
        "tampered nested fraud proof (bad d0) was WRONGLY accepted!"

    for idx in range(len(fp_full.reveals)):
        bad_reveals = list(fp_full.reveals)
        bi = bytearray(bad_reveals[idx]); bi[0] ^= 1
        bad_reveals[idx] = bytes(bi)
        assert not verify_fraud_proof(N, digest, dataclasses.replace(fp_full, reveals=bad_reveals)), \
            f"tampered nested fraud proof (bad reveal #{idx}) was WRONGLY accepted!"

    for level in chain:
        bad_bytes = dict(fp_full.actual_mid_bytes)
        b = bytearray(bad_bytes[level]); b[0] ^= 1
        bad_bytes[level] = bytes(b)
        assert not verify_fraud_proof(N, digest, dataclasses.replace(fp_full, actual_mid_bytes=bad_bytes)), \
            f"tampered nested fraud proof (bad actual_mid_bytes at {level}) was WRONGLY accepted!"

    # Replacing ALL claimed levels' actual bytes with the honest canonical
    # value must report no fraud (a truthful non-accusation).
    honest_bytes = {level: mid_block(scan.checkpoint[level[0]]) for level in chain}
    fp_hide = dataclasses.replace(fp_full, actual_mid_bytes=honest_bytes)
    assert verify_fraud_proof(N, digest, fp_hide) is False, \
        "nested fraud proof with all actual_mid_bytes replaced by honest values still reported fraud!"

    print("  all nested-violation checks passed")


def run_unreachable_sibling_case(title, N, elements, blocked_target, cheats):
    """Case H/I: a violation SET where one violation sits on a SIBLING's own
    closing step relative to `blocked_target` -- i.e. is NOT one of
    blocked_target's own containing blocks. Demonstrates: (1)
    build_fraud_proof refuses to let blocked_target substitute at that
    sibling position at all (self_positions does not include it -- this is
    asserted, not silently allowed); (2) even a proof that ONLY claims
    blocked_target's own genuinely-violated self-positions still fails to
    verify, because the reconstruction still passes through the
    (unclaimed, wrongly-assumed-canonical) sibling on the way to the
    digest; (3) pick_provable_target instead selects the violation with
    the largest `a` (which is never a sibling-position casualty of
    anything else in the file -- see fraud_proof.py's module docstring),
    and THAT proof succeeds; (4) tamper variants of the working proof,
    including the base data d0, are still correctly rejected -- confirming
    the max-`a` strategy never falls into the binding-breaking trap a
    sibling-closing substitution would."""
    print(f"\n=== {title} (N={N}, blocked_target={blocked_target}, cheats={sorted(cheats)}) ===")
    raw, digest = build_with_cheats(elements, cheats)
    scan = scan_for_violations(N, raw)
    found = {(v.a, v.k) for v in scan.violations}
    print(f"  scan found {len(scan.violations)} violation(s): {sorted(found)}")
    assert found == cheats, f"scanner found {found}, expected {cheats}"

    L = int(round(math.log2(N)))
    self_only = set(self_positions(L, blocked_target))
    sibling_cheats = found - self_only
    assert sibling_cheats, "test setup: expected at least one cheat outside blocked_target's self_positions"

    # (1) build_fraud_proof must refuse to let blocked_target claim a
    # sibling position at all.
    for (a, k) in sibling_cheats:
        try:
            build_fraud_proof(scan, blocked_target, [(a, k)])
            raise AssertionError(
                f"BUG: build_fraud_proof let target {blocked_target} claim sibling position "
                f"({a},{k}), which is not one of its own containing blocks")
        except AssertionError as e:
            if "not one of" not in str(e):
                raise
            print(f"  build_fraud_proof correctly refused sibling claim ({a},{k}) for target {blocked_target}")

    # (2) A proof claiming only blocked_target's own (genuinely violated)
    # self-positions still fails to verify, because reconstruction still
    # silently assumes the unclaimed sibling is canonical.
    self_violated = sorted(self_only & found, key=lambda ak: ak[1])
    fp_blocked = build_fraud_proof(scan, blocked_target, self_violated)
    ok_blocked = verify_fraud_proof(N, digest, fp_blocked)
    print(f"  target={blocked_target}, self-positions-only {self_violated}: "
          f"verified={ok_blocked} (must be False -- blocked by unrelated sibling corruption)")
    assert ok_blocked is False, \
        "target's self-only proof unexpectedly verified despite an unclaimed, corrupted sibling on its path"

    # (3) pick_provable_target selects the violation with the largest `a`,
    # which is always safely self-only-provable regardless of anything
    # else in the file.
    rehash_calls = full_rehash_call_count(raw)
    target = pick_provable_target(scan)
    print(f"  pick_provable_target(scan) = {target}")
    pset = provable_set(scan, target)
    print(f"  provable_set(scan, {target}) = {pset}")
    assert pset, "pick_provable_target's own target must have a non-empty provable_set"
    fp_full = build_fraud_proof(scan, target, pset)
    calls = [0]
    ok_full = verify_fraud_proof(N, digest, fp_full, count_calls=calls)
    print(f"  target={target}, full self-chain substitution ({len(pset)} levels): "
          f"{fp_full.nbytes()} bytes, {calls[0]} compression calls "
          f"(full rehash would need {rehash_calls}) -> verified={ok_full}")
    assert ok_full, "BUG: pick_provable_target's own proof should verify, but did not"
    assert calls[0] <= 2 * L + 6 + len(pset), \
        f"verification used more than O(log N) calls: {calls[0]} vs L={L}"

    # (4) Tamper tests on the working proof -- including d0, which must
    # remain genuinely bound to the digest (this is exactly the check that
    # would catch a binding break from an unsafe sibling substitution).
    bad_d0 = bytearray(fp_full.d0); bad_d0[0] ^= 1
    assert not verify_fraud_proof(N, digest, dataclasses.replace(fp_full, d0=bytes(bad_d0))), \
        "tampered fraud proof (bad d0) was WRONGLY accepted! (base data not bound to digest)"

    bad_d1 = bytearray(fp_full.d1); bad_d1[0] ^= 1
    assert not verify_fraud_proof(N, digest, dataclasses.replace(fp_full, d1=bytes(bad_d1))), \
        "tampered fraud proof (bad d1) was WRONGLY accepted!"

    for idx in range(len(fp_full.reveals)):
        bad_reveals = list(fp_full.reveals)
        bi = bytearray(bad_reveals[idx]); bi[0] ^= 1
        bad_reveals[idx] = bytes(bi)
        assert not verify_fraud_proof(N, digest, dataclasses.replace(fp_full, reveals=bad_reveals)), \
            f"tampered fraud proof (bad reveal #{idx}) was WRONGLY accepted!"

    for level in pset:
        bad_bytes = dict(fp_full.actual_mid_bytes)
        b = bytearray(bad_bytes[level]); b[0] ^= 1
        bad_bytes[level] = bytes(b)
        assert not verify_fraud_proof(N, digest, dataclasses.replace(fp_full, actual_mid_bytes=bad_bytes)), \
            f"tampered fraud proof (bad actual_mid_bytes at {level}) was WRONGLY accepted!"

    # Replacing ALL claimed levels' actual bytes with the honest canonical
    # value must report no fraud.
    honest_bytes = {level: mid_block(scan.checkpoint[level[0]]) for level in pset}
    fp_hide = dataclasses.replace(fp_full, actual_mid_bytes=honest_bytes)
    assert verify_fraud_proof(N, digest, fp_hide) is False, \
        "fraud proof with all actual_mid_bytes replaced by honest values still reported fraud!"

    print("  all max-a-target checks passed")


def run_free_checkpoint_case(Ns=(8, 16, 32)):
    """Case J -- free-checkpoint accusations against canonical files.
    Dispute a level (a,k) on target t's own path, supplying the TRUE MID
    bytes, and replace one or two reveals with arbitrary values. If
    (a,k)'s checkpoint is a revealed value consumed only by its (now
    substituted) closing fold -- an unanchored level -- the fold still
    reaches the real digest while pad_b(ckpt) != true bytes, so a verifier
    that counted mismatches at every disputed level would wrongly accept.
    Under the anchoring rule every such accusation must be rejected."""
    print("\n=== Case J: free-checkpoint accusations against canonical files ===")
    import itertools
    tried = unanchored_hits = 0
    for N in Ns:
        L = int(round(math.log2(N)))
        raw, digest = build_with_cheats([os.urandom(BLOCK_SIZE) for _ in range(N)], set())
        scan = scan_for_violations(N, raw)
        assert not scan.violations
        for t in range(N):
            sp = self_positions(L, t)
            for r in range(1, len(sp) + 1):
                for V in itertools.combinations(sp, r):
                    if set(V) - anchored_levels(L, t, V):
                        unanchored_hits += 1
                    fp = build_fraud_proof(scan, t, list(V))
                    for m in (1, 2):
                        for S in itertools.combinations(range(len(fp.reveals)), m):
                            rv = list(fp.reveals)
                            for i in S:
                                rv[i] = os.urandom(STATE_SIZE)
                            tried += 1
                            assert not verify_fraud_proof(
                                N, digest, dataclasses.replace(fp, reveals=rv)), \
                                f"free-checkpoint accusation ACCEPTED: N={N} t={t} V={V} S={S}"
    print(f"  {tried} tampered accusations against canonical files "
          f"({unanchored_hits} (t,V) configurations contain an unanchored "
          f"disputed level): all rejected")


def run_random_completeness_case(trials=300):
    """Case K -- completeness under the anchoring rule: for random
    non-canonical files (random cheat sets, nested or not, any levels),
    the max-a target with its full provable_set must always verify."""
    print("\n=== Case K: randomized completeness under the anchoring rule ===")
    rng = random.Random(2026)
    for _ in range(trials):
        N = rng.choice((4, 8, 16, 32, 64))
        positions = valid_mid_positions(N)
        cheats = set(rng.sample(positions, rng.randint(1, min(5, len(positions)))))
        raw, digest = build_with_cheats([os.urandom(BLOCK_SIZE) for _ in range(N)], cheats)
        scan = scan_for_violations(N, raw)
        t = pick_provable_target(scan)
        fp = build_fraud_proof(scan, t, provable_set(scan, t))
        assert verify_fraud_proof(N, digest, fp), f"completeness failed: N={N} cheats={cheats}"
    print(f"  {trials} random non-canonical files: max-a target proof verified every time")


if __name__ == "__main__":
    print("FlatMerkle fraud-proof simulation")
    print("=" * 70)

    for N in (16, 32, 64):
        run_honest_case(N)

    # --- Case A: the exact B1 attack -- corrupt only the file's very
    # last MID (the top-level right root's own closing checkpoint). ---
    N = 32
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    L = int(round(math.log2(N)))
    top_right = (1 << (L - 1), L - 1)
    run_case("Case A: B1-style attack on the file's last block", N, elements, {top_right})

    # --- Case B: a single internal, low-level (base-pair) MID cheated. ---
    N = 32
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    positions = valid_mid_positions(N)
    base_level = next((a, k) for (a, k) in positions if k == 1)
    run_case("Case B: single internal base-level MID cheated", N, elements, {base_level})

    # --- Case C: a single internal, mid-level MID cheated. ---
    N = 64
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    positions = valid_mid_positions(N)
    mid_level = next((a, k) for (a, k) in positions if k == 2)
    run_case("Case C: single internal mid-level MID cheated", N, elements, {mid_level})

    # --- Case D: multiple, simultaneous, unrelated cheats in different
    # subtrees (and different levels) of the same file -- one violation per
    # level, guaranteed to sit on mutually independent root-to-leaf paths
    # (no ancestor/descendant pair among them). ---
    N = 64
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    L = int(round(math.log2(N)))
    cheats = set(pick_independent_cheats(N, range(1, L)))
    print(f"\n(selected cheat set for Case D: {sorted(cheats)})")
    run_case("Case D: independent simultaneous cheats across every level", N, elements, cheats)

    # --- Case E: larger N, several independent cheats incl. the top level,
    # to see O(log N) scaling more clearly. ---
    N = 1024
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    L = int(round(math.log2(N)))
    cheats = set(pick_independent_cheats(N, [1, 3, 6, L - 1]))
    print(f"\n(selected cheat set for Case E: {sorted(cheats)})")
    run_case("Case E: N=1024, independent cheats at various levels incl. top", N, elements, cheats)

    # --- Case F: NESTED/chained violations on one root-to-leaf path --
    # exactly the counterexample structure that defeats single-level
    # substitution: block(0,1) and block(0,2) both corrupted for N=8. ---
    N = 8
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    run_nested_case("Case F: nested violations, N=8, block(0,1) and block(0,2)",
                     N, elements, {(0, 1), (0, 2)})

    # --- Case G: a deeper nested chain -- three levels corrupted on one
    # path, N=16. ---
    N = 16
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    run_nested_case("Case G: nested violations, N=16, three levels on one path",
                     N, elements, {(0, 1), (0, 2), (0, 3)})

    # --- Case H: a violation on target=0's own self-position (0,1) AND an
    # UNRELATED violation on the sibling block(4,2) encountered when
    # target=0's path branches left at the top level, N=8. target=0's own
    # proof is blocked (reconstruction still silently assumes (4,2) is
    # canonical) -- but pick_provable_target picks target=4 (the larger
    # `a`), whose self-only proof is completely unaffected. ---
    N = 8
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    run_unreachable_sibling_case(
        "Case H: target=0 blocked by unrelated sibling (4,2); max-a target=4 unaffected",
        N, elements, blocked_target=0, cheats={(0, 1), (4, 2)})

    # --- Case I: a deeper combination -- a full nested self-chain on
    # target=0's own path, PLUS an independent violation on the top-level
    # right sibling block(8,3), N=16. target=0's proof is blocked the same
    # way; pick_provable_target picks target=8 instead. ---
    N = 16
    elements = [os.urandom(BLOCK_SIZE) for _ in range(N)]
    run_unreachable_sibling_case(
        "Case I: target=0's nested self-chain blocked by unrelated sibling (8,3); max-a target=8 unaffected",
        N, elements, blocked_target=0, cheats={(0, 1), (0, 2), (8, 3)})

    run_free_checkpoint_case()
    run_random_completeness_case()

    print("\n" + "=" * 70)
    print("ALL FRAUD-PROOF SIMULATION CASES PASSED")
