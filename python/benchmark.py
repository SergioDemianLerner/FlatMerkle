"""
benchmark.py -- construction-speed comparison: LogLink structured file vs.
Merkle tree, over the SAME ~1,048,576 (2^20) elements, using the IDENTICAL
hand-rolled SHA-256 compression function (sha256_core.compress) for every
hash performed on either side -- same language (Python), same
implementation, same optimization effort, no library shortcuts on one side
and not the other.

Three constructions are timed:
  1. LogLink structured file (loglink_annex.build): 2N-2 compress() calls,
     ONE finalization for the whole file.
  2. "Same-convention" Merkle tree: leaf = compress(IV, element), internal
     node = compress(IV, left||right) -- exactly 1 compress() call per
     node, no per-node padding. This isolates the tree-vs-chain question
     with no artificial handicap on the tree.
  3. "Standard" Merkle tree: leaf = SHA256(element), internal node =
     SHA256(left||right) -- i.e. what essentially every real Merkle tree
     implementation (including Bitcoin's own transaction Merkle tree)
     actually does: each node gets its own full, independently padded
     hash. With 64-byte inputs this costs 2 compress() calls per node
     instead of 1.

Run as separate phases (each writes its timing to bench_results.json) so
no single run has to carry the whole ~10 minute cost:
    python3 benchmark.py setup
    python3 benchmark.py loglink
    python3 benchmark.py merkle_fast
    python3 benchmark.py merkle_standard
    python3 benchmark.py report
"""
import json
import os
import sys
import time

from sha256_core import compress, length_padding_blocks, IV_STD, STATE_SIZE, BLOCK_SIZE

N = int(os.environ.get("BENCH_N", 1 << 20))  # 1,048,576 -- nearest power of two to 1,000,000
ELEM_PATH = f"bench_elements_{N}.bin"
RESULTS_PATH = f"bench_results_{N}.json"


def load_results():
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            return json.load(f)
    return {}


def save_result(key, value):
    r = load_results()
    r[key] = value
    with open(RESULTS_PATH, "w") as f:
        json.dump(r, f, indent=2)


def load_elements():
    with open(ELEM_PATH, "rb") as f:
        data = f.read()
    assert len(data) == N * BLOCK_SIZE
    return [data[i * BLOCK_SIZE:(i + 1) * BLOCK_SIZE] for i in range(N)]


# ---------------------------------------------------------------------------
def phase_setup():
    import random
    random.seed(12345)
    with open(ELEM_PATH, "wb") as f:
        for _ in range(N):
            f.write(random.getrandbits(BLOCK_SIZE * 8).to_bytes(BLOCK_SIZE, "big"))
    print(f"wrote {N} x {BLOCK_SIZE}-byte elements ({N*BLOCK_SIZE/1e6:.1f} MB) to {ELEM_PATH}")


# ---------------------------------------------------------------------------
def phase_loglink():
    import loglink_annex
    elements = load_elements()
    calls_before = _CallCounter.count
    t0 = time.perf_counter()
    sf = loglink_annex.build(elements)
    t1 = time.perf_counter()
    calls = _CallCounter.count - calls_before
    save_result("loglink", {
        "N": N, "seconds": t1 - t0, "compress_calls": calls,
        "digest": sf.digest.hex(),
    })
    print(f"LogLink build: N={N} time={t1-t0:.2f}s calls={calls} "
          f"({calls/(t1-t0):.0f} calls/s)")


# ---------------------------------------------------------------------------
def _pow2_ceil_log2(n):
    L = 0
    while (1 << L) < n:
        L += 1
    return L


def phase_merkle_fast():
    """Same-convention tree: 1 compress() call per node, no per-node padding."""
    elements = load_elements()
    calls_before = _CallCounter.count
    t0 = time.perf_counter()
    level = [compress(IV_STD, e) for e in elements]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(compress(IV_STD, level[i] + level[i + 1]))
        level = nxt
    root = level[0]
    t1 = time.perf_counter()
    calls = _CallCounter.count - calls_before
    save_result("merkle_fast", {
        "N": N, "seconds": t1 - t0, "compress_calls": calls,
        "root": root.hex(),
    })
    print(f"Merkle (same-convention) build: N={N} time={t1-t0:.2f}s calls={calls} "
          f"({calls/(t1-t0):.0f} calls/s)")


def full_sha256_via_compress(data: bytes) -> bytes:
    padded = data + length_padding_blocks(len(data))
    state = IV_STD
    for i in range(0, len(padded), BLOCK_SIZE):
        state = compress(state, padded[i:i + BLOCK_SIZE])
    return state


def phase_merkle_standard():
    """Standard tree: every node is its own fully-padded SHA-256, exactly
    like calling hashlib.sha256(x).digest() per node in a typical
    real-world implementation -- just built on our own compress() so the
    primitive is identical to the other two phases."""
    elements = load_elements()
    calls_before = _CallCounter.count
    t0 = time.perf_counter()
    level = [full_sha256_via_compress(e) for e in elements]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(full_sha256_via_compress(level[i] + level[i + 1]))
        level = nxt
    root = level[0]
    t1 = time.perf_counter()
    calls = _CallCounter.count - calls_before
    save_result("merkle_standard", {
        "N": N, "seconds": t1 - t0, "compress_calls": calls,
        "root": root.hex(),
    })
    print(f"Merkle (standard, padded-per-node) build: N={N} time={t1-t0:.2f}s calls={calls} "
          f"({calls/(t1-t0):.0f} calls/s)")


# ---------------------------------------------------------------------------
def phase_report():
    r = load_results()
    print(json.dumps(r, indent=2))
    if all(k in r for k in ("loglink", "merkle_fast", "merkle_standard")):
        ll, mf, ms = r["loglink"], r["merkle_fast"], r["merkle_standard"]
        print("\n--- summary (N = %d) ---" % N)
        print(f"{'method':30s} {'seconds':>10s} {'compress calls':>16s} {'calls/element':>14s}")
        for name, d in [("LogLink structured file", ll),
                        ("Merkle, same convention", mf),
                        ("Merkle, standard (padded/node)", ms)]:
            print(f"{name:30s} {d['seconds']:10.2f} {d['compress_calls']:16d} "
                  f"{d['compress_calls']/N:14.3f}")
        print(f"\nLogLink vs same-convention Merkle: "
              f"{mf['seconds']/ll['seconds']:.3f}x  (ratio of Merkle time to LogLink time)")
        print(f"LogLink vs standard Merkle:        "
              f"{ms['seconds']/ll['seconds']:.3f}x  (ratio of Merkle time to LogLink time)")


# ---------------------------------------------------------------------------
# instrument compress() call count without touching sha256_core.py
class _CallCounter:
    count = 0


_real_compress = compress


def _counted_compress(state, block):
    _CallCounter.count += 1
    return _real_compress(state, block)


compress = _counted_compress
import sha256_core
sha256_core.compress = _counted_compress
import loglink_annex as _la
_la.compress = _counted_compress


if __name__ == "__main__":
    phase = sys.argv[1] if len(sys.argv) > 1 else "report"
    {
        "setup": phase_setup,
        "loglink": phase_loglink,
        "merkle_fast": phase_merkle_fast,
        "merkle_standard": phase_merkle_standard,
        "report": phase_report,
    }[phase]()
