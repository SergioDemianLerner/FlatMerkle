"""
illustrate.py -- reusable generator for LogLink structured-file diagrams,
in the same visual style as the original hand-drawn figure: data elements as
filled circles, midstate re-injections as labelled boxes, distance-2^k
"jump" arcs drawn above the row, with arrowheads pointing at the element
each arc's checkpoint refers back to.

Two structural (hash-free) layout functions mirror loglink.py's recursive
construction exactly, so the picture is guaranteed to match what loglink.py
actually builds/proves -- and one drawing function, draw_structured_file(),
that both renders the whole file and, given a target index, highlights
every value consumed by that index's inclusion proof.

Usage:
    from illustrate import draw_structured_file
    draw_structured_file(32, target_index=15, out_path="proof15.png")
"""
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Circle, FancyArrowPatch
from matplotlib.path import Path
import matplotlib.patches as mpatches

from loglink import position, block_len  # reuse the exact same formulas


# ---------------------------------------------------------------------------
# Structural (hash-free) layout: mirrors loglink.build()'s recursion exactly
# ---------------------------------------------------------------------------
@dataclass
class Item:
    kind: str            # 'D' or 'MID'
    pos: int              # 0-indexed position in the structured file
    a: int                 # for 'D': the element index itself; for 'MID': block start
    k: Optional[int] = None      # level, MID only (distance = 2**k)
    target_pos: Optional[int] = None  # MID only: position of D[a] (arc arrowhead)
    label: str = ""         # MID only: display label (see is_left_child below)


def is_left_child(a: int, k: int) -> bool:
    """True iff block(a,k) is the LEFT child at its own level -- i.e. its
    ending gets promoted to sf.checkpoint[a + 2**k] and reused as-is
    elsewhere (a single, well-defined position). False means it's the RIGHT
    child: its ending only ever feeds its own parent's closing MID and is
    NEVER separately checkpointed anywhere else -- so it has no honest
    single-index name, only a span. (Matches reveal_label()'s sib_end/
    sib_prewrap split exactly, and the top-level pair of roots for the same
    reason: block(0,L-1) is 'left', block(half_top,L-1) is 'right'.)"""
    return (a % (1 << (k + 1))) == 0


def mid_label(a: int, k: int) -> str:
    """'CK' for checkpoint -- deliberately not 'MS' ('midstate'), which
    reads as 'the state associated with processing element N' and invites
    exactly the misreading this box triggered ('CK2' after D[0],D[1] reads
    as 'the checkpoint at boundary 2', not 'the midstate of element 2')."""
    if is_left_child(a, k):
        return f"CK{a + (1 << k)}"
    return f"CK[{a}-{a + (1 << k) - 1}]"


def layout(N: int) -> List[Item]:
    """Structural equivalent of loglink.build(): same order, same positions,
    no hashing. Used purely to draw the picture."""
    L = int(round(math.log2(N)))
    assert 1 << L == N
    items: List[Item] = []
    pos = 0

    def emit_data(i):
        nonlocal pos
        items.append(Item(kind="D", pos=pos, a=i))
        pos += 1

    def emit_mid(a, k):
        nonlocal pos
        items.append(Item(kind="MID", pos=pos, a=a, k=k, target_pos=position(a),
                           label=mid_label(a, k)))
        pos += 1

    def block(a, k):
        if k == 1:
            emit_data(a)
            emit_data(a + 1)
            emit_mid(a, 1)
        else:
            half = 1 << (k - 1)
            block(a, k - 1)
            block(a + half, k - 1)
            emit_mid(a, k)

    block(0, L - 1)
    block(1 << (L - 1), L - 1)
    return items


def proof_trace(N: int, target_index: int):
    """Structural equivalent of loglink.build_proof(): returns
    (base_a0, [(kind, a, k), ...]) where kind is 'sib_end' (full ending,
    becomes checkpoint) or 'sib_prewrap' (pre-close value, combined with the
    just-verified value) or the two TOP-level variants, in emission order --
    same recursion as build_proof(), no hashing needed."""
    L = int(round(math.log2(N)))
    a0 = target_index - (target_index % 2)
    half_top = 1 << (L - 1)
    steps = []

    def recurse(a, k, target):
        if k == 1:
            return
        half = 1 << (k - 1)
        if target < a + half:
            recurse(a, k - 1, target)
            steps.append(("sib_prewrap", a + half, k - 1))
        else:
            steps.append(("sib_end", a, k - 1))
            recurse(a + half, k - 1, target)

    if a0 < half_top:
        recurse(0, L - 1, a0)
        steps.append(("top_prewrap", half_top, L - 1))
    else:
        steps.append(("top_end", 0, L - 1))
        recurse(half_top, L - 1, a0)

    return a0, steps


def resolve_highlight_positions(N: int, target_index: int):
    """Turns proof_trace()'s abstract steps into concrete structured-file
    positions to highlight (every one of them is either an existing MID box
    or an existing data circle -- nothing invented for the picture).
    Returns an ordered list of (step_number, position, note)."""
    a0, steps = proof_trace(N, target_index)
    out = [(0, position(a0), "base"), (0, position(a0) + 1, "base")]
    for i, (kind, a, k) in enumerate(steps, start=1):
        if kind in ("sib_end", "top_end"):
            # ending(a,k) = state right after the MID(a) box closing block(a,k)
            p = position(a) + block_len(k) - 1
            out.append((i, p, f"ending(a={a},k={k})"))
        else:  # sib_prewrap / top_prewrap
            # prewrap(a,k) = state right before that same MID(a) box, i.e.
            # right after the PREVIOUS item (the right child's own close,
            # or -- at k==1 -- the pair's 2nd data element)
            p = position(a) + block_len(k) - 2
            out.append((i, p, f"prewrap(a={a},k={k})"))
    return out


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------
DATA_FILL = "#f5c896"
DATA_FILL_HI = "#e8483c"
MID_FILL = "white"
MID_FILL_HI = "#ffd9d4"
EDGE = "#333333"
EDGE_HI = "#c0392b"
ARC_COLOR = "#555555"
ARC_COLOR_HI = "#c0392b"


def draw_structured_file(N: int, target_index: Optional[int] = None,
                          title: Optional[str] = None,
                          out_path: str = "structured_file.png",
                          item_w: float = 1.0, dpi: int = 160):
    """Render the LogLink structured file for N (=2^L) original elements,
    in the visual style of the source figure: data elements as circles
    labelled by original index, midstate re-injections as boxes labelled
    'CK<n>' (checkpoint n) or 'CK[a-b]' (pre-close span a..b), and jump
    arcs above the row (height ~ level, label = distance
    = 2^level) with an arrowhead on the element each arc's checkpoint
    refers back to.

    If target_index is given, highlights (in red) exactly the elements and
    midstate boxes whose value is consumed by that index's inclusion proof
    -- both data elements of its pair, and one box per level of the proof
    (see resolve_highlight_positions). A step-number is printed above each
    highlighted item so the proof's order is readable.

    Returns out_path.
    """
    items = layout(N)
    M = len(items)
    L = int(round(math.log2(N)))

    highlight = {}
    if target_index is not None:
        for step, p, note in resolve_highlight_positions(N, target_index):
            highlight[p] = (step, note)
    # stagger step-number labels over 3 rows when highlighted items are
    # close together in x, so labels for nearby positions don't collide
    hi_positions_sorted = sorted(highlight.keys())
    stagger_row = {}
    for i, p in enumerate(hi_positions_sorted):
        stagger_row[p] = i % 3

    row_y = 0.0
    r = 0.36 * item_w

    # --- non-uniform horizontal layout ---------------------------------
    # A MID box holding a range label ("CK[a-b]") needs more horizontal
    # room than a single-index one ("CK14") or a data circle, so items are
    # no longer placed on a fixed p*item_w grid: each item gets its own
    # half-width, and consecutive items are packed edge-to-edge plus a
    # fixed gap. This is what actually prevents range-label boxes that sit
    # next to each other (a common pattern near the middle of each half)
    # from clipping their own text or overlapping their neighbor.
    def half_width_and_fontsize(it: "Item"):
        if it.kind == "D":
            return r, 8.5
        is_range = "[" in it.label
        if not is_range:
            return r, 7.0
        rest = it.label[2:]  # e.g. "[8-15]" -- the part after "CK"
        fontsize = 6.5 if len(rest) <= 5 else (6.0 if len(rest) == 6 else 5.3)
        box_w = max(2 * r, 0.145 * item_w * len(rest) + 0.22 * item_w)
        return box_w / 2, fontsize

    gap = 0.14 * item_w
    half_widths = []
    fontsizes = []
    for it in items:
        hw, fs = half_width_and_fontsize(it)
        half_widths.append(hw)
        fontsizes.append(fs)

    centers = [0.0] * M
    centers[0] = half_widths[0]
    for i in range(1, M):
        centers[i] = centers[i - 1] + half_widths[i - 1] + gap + half_widths[i]
    total_w = centers[-1] + half_widths[-1]

    fig_w = max(10, total_w * 0.62 + 1.5)
    fig_h = 3.2 + 0.42 * L
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=dpi)

    # arc lane heights: one lane per level k, increasing with k
    lane_gap = 0.55
    base_lane = 0.75

    def x_of(p):
        return centers[p]

    # --- draw arcs first (so item glyphs sit on top of their stubs) ---
    for it in items:
        if it.kind != "MID":
            continue
        x_src = x_of(it.pos)
        x_dst = x_of(it.target_pos)
        y_lane = base_lane + (it.k - 1) * lane_gap
        hi = it.pos in highlight
        color = ARC_COLOR_HI if hi else ARC_COLOR
        lw = 2.4 if hi else 1.1
        z = 5 if hi else 2
        # elbow path: up from source, left to above target, down into target
        verts = [(x_src, row_y + r * 0.9), (x_src, y_lane),
                 (x_dst, y_lane), (x_dst, row_y + r * 1.15)]
        codes = [Path.MOVETO, Path.LINETO, Path.LINETO, Path.LINETO]
        path = Path(verts, codes)
        patch = mpatches.PathPatch(path, facecolor="none", edgecolor=color,
                                    lw=lw, zorder=z)
        ax.add_patch(patch)
        # arrowhead into target
        ax.annotate("", xy=(x_dst, row_y + r * 0.95), xytext=(x_dst, row_y + r * 1.2),
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=lw,
                                     mutation_scale=12), zorder=z)
        # distance label at the horizontal segment's midpoint
        xm = (x_src + x_dst) / 2
        ax.text(xm, y_lane + 0.08, str(1 << it.k), ha="center", va="bottom",
                 fontsize=8, color=color, zorder=z)
        ax.plot([xm], [y_lane], marker="o", ms=2, color=color, zorder=z)

    # --- draw items ---
    for it in items:
        x = x_of(it.pos)
        hw = half_widths[it.pos]
        fs = fontsizes[it.pos]
        hi = it.pos in highlight
        if it.kind == "D":
            fc = DATA_FILL_HI if hi else DATA_FILL
            ec = EDGE_HI if hi else EDGE
            circ = Circle((x, row_y), r, facecolor=fc, edgecolor=ec,
                           lw=2 if hi else 1.2, zorder=6)
            ax.add_patch(circ)
            ax.text(x, row_y, str(it.a), ha="center", va="center",
                     fontsize=fs, zorder=7)
        else:
            fc = MID_FILL_HI if hi else MID_FILL
            ec = EDGE_HI if hi else EDGE
            box_w = 2 * hw
            box_h = 2 * r
            box = FancyBboxPatch((x - box_w / 2, row_y - box_h / 2), box_w, box_h,
                                  boxstyle="square,pad=0", facecolor=fc,
                                  edgecolor=ec, lw=2 if hi else 1.2, zorder=6)
            ax.add_patch(box)
            lbl = it.label.replace("CK", "CK\n", 1) if it.label else f"CK\n{it.a}"
            ax.text(x, row_y, lbl, ha="center", va="center",
                     fontsize=fs, zorder=7)
        if hi:
            step, note = highlight[it.pos]
            row = stagger_row[it.pos]
            ax.text(x, row_y - r - 0.30 - 0.26 * row, f"step {step}", ha="center",
                     va="top", fontsize=7.5, color=EDGE_HI, weight="bold",
                     zorder=7)

    top = base_lane + max(0, L - 1) * lane_gap + 0.5
    ax.set_xlim(-half_widths[0] - gap, total_w + gap)
    ax.set_ylim(-r - 0.9 - 0.26 * 2, top)
    ax.axis("off")

    ttl = title or f"FlatMerkle structured file, N={N} elements"
    if target_index is not None:
        ttl += f"  --  inclusion proof path for original index {target_index}"
    ax.set_title(ttl, fontsize=12)

    # legend
    handles = [
        mpatches.Patch(facecolor=DATA_FILL, edgecolor=EDGE, label="data element"),
        mpatches.Patch(facecolor=MID_FILL, edgecolor=EDGE, label="midstate re-injection (MID)"),
    ]
    if target_index is not None:
        handles += [
            mpatches.Patch(facecolor=DATA_FILL_HI, edgecolor=EDGE_HI, label="revealed in this proof (data)"),
            mpatches.Patch(facecolor=MID_FILL_HI, edgecolor=EDGE_HI, label="revealed in this proof (state)"),
        ]
    ax.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, -0.24 - 0.05 * L),
              ncol=4, fontsize=8, frameon=False)

    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    return out_path


# ---------------------------------------------------------------------------
# Verification-order diagram: the ACTUAL sequence of C() calls the verifier
# performs, in execution order. This is deliberately a separate diagram from
# draw_structured_file(): the structured-file picture shows the file's own
# native jump-back links (where each revealed value lives), but the
# verifier never "walks" those arcs -- it folds the target pair together
# with the revealed values in one straight chain of C() calls. Mirrors
# verify_proof()'s eval_block() control flow exactly (symbolically, no
# hashing), so it can't drift out of sync with the real verifier.
# ---------------------------------------------------------------------------
@dataclass
class Call:
    left: str
    right: str
    result: str
    note: str = ""


def symbolic_verification_chain(N: int, target_index: int) -> List[Call]:
    L = int(round(math.log2(N)))
    a0 = target_index - (target_index % 2)
    half_top = 1 << (L - 1)
    calls: List[Call] = []
    counter = [0]

    def new_label():
        counter[0] += 1
        return f"t{counter[0]}"

    def eval_block(a, k, target, ckpt_label):
        if k == 1:
            l1 = new_label()
            calls.append(Call(ckpt_label, f"D[{a}]", l1, "process 1st element of pair"))
            l2 = new_label()
            calls.append(Call(l1, f"D[{a+1}]", l2, "process 2nd element of pair"))
            l3 = new_label()
            calls.append(Call(l2, ckpt_label, l3, f"re-inject checkpoint[{a}] (closes base pair)"))
            return l3
        half = 1 << (k - 1)
        if target < a + half:
            left_end = eval_block(a, k - 1, target, ckpt_label)
            sib = f"reveal:prewrap(a={a+half},k={k-1})"
            combo = new_label()
            calls.append(Call(sib, left_end, combo, "fold sibling's pre-close state with our verified result"))
            res = new_label()
            calls.append(Call(combo, ckpt_label, res, f"re-inject checkpoint[{a}] (closes block a={a},k={k})"))
            return res
        else:
            sib = f"reveal:ending(a={a},k={k-1})"
            res = eval_block(a + half, k - 1, target, sib)
            res2 = new_label()
            calls.append(Call(res, ckpt_label, res2, f"re-inject checkpoint[{a}] (closes block a={a},k={k})"))
            return res2

    if a0 < half_top:
        y = eval_block(0, L - 1, a0, "IV")
        r2 = f"reveal:prewrap(a={half_top},k={L-1})"
        d = "DIGEST"
        calls.append(Call(r2, y, d, "final combine with the separately-revealed other-half value"))
    else:
        y_reveal = f"reveal:ending(a=0,k={L-1})"
        y = eval_block(half_top, L - 1, a0, y_reveal)
        calls[-1].result = "DIGEST"
        calls[-1].note += " [[this call's result IS the digest]]"

    return calls


def draw_verification_chain(N: int, target_index: int,
                             out_path: str = "verification_chain.png",
                             dpi: int = 160):
    """Draws the straight-line sequence of C() calls the verifier actually
    performs for target_index, left to right, ending at DIGEST. This is the
    direct answer to 'how do you get from the target element to the
    digest?' -- it's a fold over revealed values, not a walk along the
    structured-file's own drawn jump-back arcs."""
    calls = symbolic_verification_chain(N, target_index)
    n = len(calls)
    fig_w = max(10, 3.3 * n)
    fig, ax = plt.subplots(figsize=(fig_w, 3.6), dpi=dpi)

    box_w, box_h = 1.6, 0.6
    gap = 1.7
    y0 = 0.0

    def draw_box(cx, cy, text, fc="#eef2f7", ec="#333333", fontsize=9, bold=False):
        b = FancyBboxPatch((cx - box_w / 2, cy - box_h / 2), box_w, box_h,
                            boxstyle="round,pad=0.04,rounding_size=0.06",
                            facecolor=fc, edgecolor=ec, lw=1.4, zorder=3)
        ax.add_patch(b)
        ax.text(cx, cy, text, ha="center", va="center", fontsize=fontsize,
                 zorder=4, weight="bold" if bold else "normal")

    x = 0.0
    for i, c in enumerate(calls):
        is_last = (i == n - 1)
        cx_op = x + gap
        # left/right operand labels feeding into this call
        ax.text(cx_op - 0.35, y0 + 0.55, c.left, ha="center", fontsize=7.5, color="#555555")
        ax.text(cx_op + 0.35, y0 + 0.55, c.right, ha="center", fontsize=7.5, color="#555555")
        draw_box(cx_op, y0, f"C(...)\n= {c.result}",
                  fc="#ffe0dc" if is_last else "#eef2f7",
                  ec="#c0392b" if is_last else "#333333",
                  bold=is_last)
        ax.text(cx_op, y0 - 0.55, c.note, ha="center", fontsize=6.3, color="#666666", wrap=True)
        if i > 0:
            ax.annotate("", xy=(cx_op - box_w / 2, y0), xytext=(x, y0),
                        arrowprops=dict(arrowstyle="-|>", color="#333333", lw=1.2))
        x = cx_op + box_w / 2

    ax.set_xlim(-0.5, x + 1.0)
    ax.set_ylim(-1.3, 1.3)
    ax.axis("off")
    ax.set_title(f"Verifier's actual call chain to prove index {target_index}  "
                  f"(N={N}) -- a straight fold, not an arc walk", fontsize=11)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    return out_path


def reveal_label(kind: str, a: int, k: int) -> str:
    """The human-readable label for one reveal. The two kinds name
    genuinely different values (Definition 3.1: prewrap(a,k) and
    ending(a,k) are one compression call apart, not interchangeable), so
    they are NOT both just `mid_label(a, k)`:

    - 'sib_end'/'top_end': the value revealed is literally ending(a,k) --
      exactly what mid_label(a,k) already represents (a single promoted
      index CK{a+2**k} if block(a,k) is itself a left child, else the span
      CK[a..a+2**k-1]).

    - 'sib_prewrap'/'top_prewrap': the value revealed is prewrap(a,k) --
      NOT ending(a,k), and NOT block(a,k)'s own span. For k>=2, the
      identity prewrap(a,k) = ending(a+2**(k-1), k-1) (block(a,k)'s own
      right child's ending, one level deeper) gives it a proper CK-range
      name -- but that name is mid_label(a+2**(k-1), k-1), the RIGHT
      CHILD's span, not mid_label(a, k), block(a,k)'s OWN span (an earlier
      version of this function returned the latter, which is simply the
      wrong value: CK[a..a+2**k-1] names ending(a,k), and ending(a,k) is
      never revealed at this point in the proof -- prewrap(a,k) is one
      compression call earlier). For k==1, block(a,k) is a base case with
      no child to name: prewrap(a,1) genuinely has no CK-range name and is
      written out literally.
    """
    if kind in ("sib_end", "top_end"):
        return mid_label(a, k)
    if k >= 2:
        half = 1 << (k - 1)
        return mid_label(a + half, k - 1)
    return f"prewrap({a},{k})"


def proof_as_stored(N: int, target_index: int):
    """The literal, ordered contents of the Proof object for target_index --
    exactly what build_proof()/Proof.reveals produces and what a verifier
    receives, in wire order: (kind, label, note) tuples, 'D' first (the two
    raw elements), then one 'CK' entry per level of the proof."""
    a0, steps = proof_trace(N, target_index)
    out = [("D", f"D[{a0}]", "raw element"), ("D", f"D[{a0+1}]", "raw element")]
    for kind, a, k in steps:
        label = reveal_label(kind, a, k)
        flavor = "becomes new checkpoint" if kind in ("sib_end", "top_end") else "combined with verified value"
        out.append(("CK", label, f"distance {1 << k} -- {flavor}"))
    return a0, out


def draw_proof_as_stored(N: int, target_index: int, out_path: str = "proof_stored.png",
                          data_bytes: int = 32, state_bytes: int = 32, dpi: int = 160):
    """Renders the proof exactly as it is stored / transmitted: a flat,
    ordered strip of boxes -- D[a0], D[a0+1], then each MS reveal in wire
    order, left to right, with no arcs and no tree -- because that's what
    the Proof object and the wire format actually are (Part 3: 'compact
    proof format = (index, D[a0], D[a0+1], reveals[0..L-2]), nothing else')."""
    a0, entries = proof_as_stored(N, target_index)
    n = len(entries)
    box_w, box_h = 1.5, 0.9
    gap = 0.55
    # Range labels ("CK[a-b]") are noticeably longer than single-index ones
    # ("CK14") or the raw-element circles; give each entry its own box width
    # instead of a single fixed width, so the range boxes don't clip their text.
    widths = []
    for kind, label, note in entries:
        if kind == "D":
            widths.append(box_h)  # circle diameter
        elif "[" in label:
            widths.append(max(box_w, 0.34 * len(label) + 0.5))
        else:
            widths.append(box_w)
    fig_w = max(8, sum(widths) + gap * (n - 1) + 1.5)
    fig, ax = plt.subplots(figsize=(fig_w, 3.0), dpi=dpi)

    x = 0.0
    centers = []
    total_bytes = 0
    for (kind, label, note), w in zip(entries, widths):
        cx = x + w / 2
        centers.append(cx)
        if kind == "D":
            circ = Circle((cx, 0), box_h / 2, facecolor=DATA_FILL_HI, edgecolor=EDGE_HI,
                           lw=1.8, zorder=4)
            ax.add_patch(circ)
            nbytes = data_bytes
        else:
            box = FancyBboxPatch((cx - w / 2, -box_h / 2), w, box_h,
                                  boxstyle="square,pad=0", facecolor=MID_FILL_HI,
                                  edgecolor=EDGE_HI, lw=1.8, zorder=4)
            ax.add_patch(box)
            nbytes = state_bytes
        total_bytes += nbytes
        ax.text(cx, 0.05, label, ha="center", va="center", fontsize=9.5, weight="bold", zorder=5)
        ax.text(cx, -box_h / 2 - 0.16, f"{nbytes}B", ha="center", va="top", fontsize=7, color="#666666")
        ax.text(cx, box_h / 2 + 0.55, note, ha="center", va="bottom", fontsize=6.6,
                 color="#555555", rotation=0, wrap=True)
        x += w + gap

    for i in range(len(centers) - 1):
        ax.annotate("", xy=(centers[i + 1] - widths[i + 1] / 2 - 0.03, 0), xytext=(centers[i] + widths[i] / 2 + 0.03, 0),
                    arrowprops=dict(arrowstyle="-", color="#999999", lw=1.0))

    ax.set_xlim(-0.5, x + 0.2)
    ax.set_ylim(-1.4, 1.7)
    ax.axis("off")
    ax.set_title(f"Proof for index {target_index} (N={N}), exactly as stored/transmitted  --  "
                  f"{n} items, {total_bytes} bytes total", fontsize=11)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    return out_path


if __name__ == "__main__":
    draw_structured_file(8, target_index=3, out_path="demo_n8_idx3.png")
    draw_structured_file(32, target_index=15, out_path="demo_n32_idx15.png")
    print("done")
