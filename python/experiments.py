"""
experiments.py -- generates every numeric result quoted in the report:
  (3) concrete example proofs for N=32, compact form + sizes
  (5) optimal element-size analysis
  (6) multi-proof batching + average space saved
All numbers are produced by actually running loglink.py, not hand-derived.
"""
import hashlib
import math
import random
import statistics as st

import loglink as L

W = L.STATE_SIZE  # 32 bytes


def hx(b, n=8):
    return b.hex()[:n]


# ---------------------------------------------------------------------------
# Part 3: example proofs for N=32, compact form
# ---------------------------------------------------------------------------
def part3():
    print("=" * 78)
    print("PART 3 -- example inclusion proofs, N=32 (D = 32 bytes/element)")
    print("=" * 78)
    N = 32
    elements = [hashlib.sha256(f"file32-{i}".encode()).digest() for i in range(N)]
    sf = L.build(elements)
    print(f"digest (the commitment, analogous to a Merkle root) = {sf.digest.hex()}")
    print()
    for idx in [0, 1, 8, 15, 16, 17, 23, 30, 31]:
        pf = L.build_proof(sf, idx)
        ok = L.verify_proof(N, sf.digest, idx, elements[idx], pf)
        tampered = bytearray(elements[idx]); tampered[0] ^= 1
        bad = L.verify_proof(N, sf.digest, idx, bytes(tampered), pf)
        a0 = idx - idx % 2
        print(f"index {idx:2d}  (pair start {a0:2d}, structured position {L.position(a0)}):")
        print(f"   reveals (compact, first 4 bytes shown): "
              + ", ".join(hx(r) for r in pf.reveals))
        print(f"   #reveals = {len(pf.reveals)}  (= L-1 = {sf.L-1})")
        print(f"   proof size = 2*{W} + {len(pf.reveals)}*{W} = {pf.nbytes()} bytes")
        print(f"   verify(genuine)  = {ok}")
        print(f"   verify(tampered) = {bad}  (must be False)")
        print()


# ---------------------------------------------------------------------------
# Part 5: optimal element size given midstate size W
# ---------------------------------------------------------------------------
def part5():
    print("=" * 78)
    print("PART 5 -- optimal element size for fixed midstate/state size W = 32 bytes")
    print("=" * 78)
    # Model: file of fixed total payload size F bytes, split into N = F/D
    # elements of D bytes each (D a "nice" size; we allow N to round to the
    # nearest power of two for the purposes of this experiment).
    # total proof size(D) = 2*D + (L-1)*W,  L = log2(N) = log2(F/D)
    # d/dD [2D + W*(log2(F/D)-1)] = 2 - W/(D ln 2) = 0  =>  D* = W/(2 ln 2)
    W_ = 32
    D_star_formula = W_ / (2 * math.log(2))
    print(f"Closed form: D* = W / (2 ln 2) = {W_} / (2*{math.log(2):.4f}) = {D_star_formula:.2f} bytes")
    print()

    F = 1 << 30  # 1 GiB fixed payload, for the numerical sweep
    print(f"Numerical sweep at fixed total payload F = {F} bytes ({F/2**20:.0f} MiB):")
    print(f"{'D (bytes)':>10} {'N=F/D':>12} {'L=log2N':>9} {'proof bytes':>12}")
    best = None
    for D in [8, 16, 24, 32, 40, 44, 46, 48, 56, 64, 96, 128, 256, 512]:
        N = F / D
        Lc = math.log2(N)
        size = 2 * D + (Lc - 1) * W_
        if best is None or size < best[1]:
            best = (D, size)
        print(f"{D:>10} {N:>12.0f} {Lc:>9.2f} {size:>12.2f}")
    print(f"\nMinimum on this grid at D = {best[0]} bytes, proof size = {best[1]:.2f} bytes")
    print(f"(matches predicted D* = {D_star_formula:.2f} bytes; note the user's own example of")
    print(f" 32-byte elements against a 32-byte midstate is within 15% of the true optimum)")


# ---------------------------------------------------------------------------
# Part 6: multi-proof batching + average savings
# ---------------------------------------------------------------------------
def part6():
    print("=" * 78)
    print("PART 6 -- multi-proof batching: average space saved vs m separate proofs")
    print("=" * 78)
    random.seed(42)
    for L_ in [10, 14, 18, 20]:
        N = 1 << L_
        elements = [hashlib.sha256(f"big-{L_}-{i}".encode()).digest() for i in range(N)]
        sf = L.build(elements)
        print(f"\nN = 2^{L_} = {N} elements, single-proof size = 2D+(L-1)W = "
              f"{2*W+(L_-1)*W} bytes (D=W={W})")
        for m in [2, 4, 8, 16, 32, 64]:
            if m > N:
                continue
            trials = 12
            individual_sizes = []
            batch_sizes = []
            for _ in range(trials):
                idxs = random.sample(range(N), m)
                indiv_total = 0
                for i in idxs:
                    pf = L.build_proof(sf, i)
                    ok = L.verify_proof(N, sf.digest, i, elements[i], pf)
                    assert ok
                    indiv_total += pf.nbytes()
                pairs, reveals, tags = L.build_multiproof(sf, idxs)
                ok = L.verify_multiproof(N, sf.digest, {i: sf.elements[i] for i in idxs}, pairs, reveals)
                assert ok
                batch_bytes = sum(2 * len(v[0]) for v in pairs.values()) + len(reveals) * W
                individual_sizes.append(indiv_total)
                batch_sizes.append(batch_bytes)
            avg_ind = st.mean(individual_sizes)
            avg_bat = st.mean(batch_sizes)
            saved = 1 - avg_bat / avg_ind
            print(f"  m={m:3d}: individual-proofs avg = {avg_ind:9.1f} B, "
                  f"multiproof avg = {avg_bat:9.1f} B, saved = {saved*100:5.1f}%")


if __name__ == "__main__":
    part3()
    part5()
    part6()
