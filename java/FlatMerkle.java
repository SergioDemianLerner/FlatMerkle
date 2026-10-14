import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * FlatMerkle -- logarithmic-space inclusion proofs over a single linear
 * (real SHA-256) hash stream, built directly on Sha256Core.compress() so
 * that:
 *
 * <pre>digest == SHA256(rawStructuredBytes)</pre>
 *
 * exactly -- i.e. the "structured file" IS the payload you'd hash normally;
 * there is no separate commitment step. This is a straight, line-for-line
 * port of the Python reference implementation (loglink_annex.py /
 * "LogLink"), described in the accompanying paper as FlatMerkle. See
 * FlatMerkleTest for the self-test (build, prove, verify, and tamper-reject
 * every index for several N), and a cross-check against the Python
 * reference's digest for identical input.
 */
public final class FlatMerkle {

    private FlatMerkle() {}

    // -------------------------------------------------------------------
    // position() / blockLen() -- pure functions of index counts only,
    // independent of hashing. See the paper, Lemma "Position formula".
    // -------------------------------------------------------------------

    /** 0-indexed position of original element a in the structured file (a must be even). */
    public static int position(int a) {
        return 2 * a - Integer.bitCount(a);
    }

    /** Total structured-file items in a fully closed block covering 2^k elements. */
    public static int blockLen(int k) {
        return (1 << (k + 1)) - 1;
    }

    /** True iff block(a,k) is the LEFT child at its own level (see the paper, Section 2.3). */
    static boolean isLeftChild(int a, int k) {
        return (a % (1 << (k + 1))) == 0;
    }

    private static long key(int a, int k) {
        return ((long) a << 8) | (k & 0xFF);
    }

    // -------------------------------------------------------------------
    // Padding helpers
    // -------------------------------------------------------------------

    private static final byte[] MID_PAD;
    static {
        MID_PAD = new byte[Sha256Core.BLOCK_SIZE - Sha256Core.STATE_SIZE];
        MID_PAD[0] = (byte) 0x80; // rest already zero -- cosmetic only, not load-bearing (see paper, security corollary)
    }

    static byte[] padElement(byte[] x) {
        if (x.length == Sha256Core.BLOCK_SIZE) return x;
        if (x.length > Sha256Core.BLOCK_SIZE) {
            throw new IllegalArgumentException("element longer than block size");
        }
        byte[] out = new byte[Sha256Core.BLOCK_SIZE];
        System.arraycopy(x, 0, out, 0, x.length);
        return out;
    }

    static byte[] midBlock(byte[] checkpoint) {
        if (checkpoint.length != Sha256Core.STATE_SIZE) {
            throw new IllegalArgumentException("checkpoint must be 32 bytes");
        }
        byte[] out = new byte[Sha256Core.BLOCK_SIZE];
        System.arraycopy(checkpoint, 0, out, 0, Sha256Core.STATE_SIZE);
        System.arraycopy(MID_PAD, 0, out, Sha256Core.STATE_SIZE, MID_PAD.length);
        return out;
    }

    /** Total annex-payload length in bytes for N elements -- needed to reconstruct finalization padding. */
    public static long totalRawLen(int n) {
        long m = 2L * n - 2;
        return m * Sha256Core.BLOCK_SIZE;
    }

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    public static final class StructuredFile {
        public final int n;
        public final int l;
        public final byte[][] elements;
        public final byte[] rawBytes;   // the literal structured-file payload
        public final byte[] rawState;   // running compress() state, BEFORE finalization
        public final byte[] digest;     // == SHA256(rawBytes)

        final Map<Integer, byte[]> checkpoint;
        final Map<Long, byte[]> ending;
        final Map<Long, byte[]> prewrap;

        private StructuredFile(int n, int l, byte[][] elements, byte[] rawBytes, byte[] rawState,
                                byte[] digest, Map<Integer, byte[]> checkpoint,
                                Map<Long, byte[]> ending, Map<Long, byte[]> prewrap) {
            this.n = n;
            this.l = l;
            this.elements = elements;
            this.rawBytes = rawBytes;
            this.rawState = rawState;
            this.digest = digest;
            this.checkpoint = checkpoint;
            this.ending = ending;
            this.prewrap = prewrap;
        }
    }

    private static final class Builder {
        final byte[][] elements;
        final Map<Integer, byte[]> checkpoint = new HashMap<>();
        final Map<Long, byte[]> ending = new HashMap<>();
        final Map<Long, byte[]> prewrap = new HashMap<>();
        final ByteArrayOutputStream rawBytes = new ByteArrayOutputStream();
        byte[] state;

        Builder(byte[][] elements) {
            this.elements = elements;
            this.state = Sha256Core.IV_STD.clone();
        }

        void emitData(int i) {
            byte[] blk = elements[i];
            rawBytes.write(blk, 0, blk.length);
            state = Sha256Core.compress(state, blk);
        }

        void emitMid(int a) {
            byte[] blk = midBlock(checkpoint.get(a));
            rawBytes.write(blk, 0, blk.length);
            state = Sha256Core.compress(state, blk);
        }

        void block(int a, int k) {
            checkpoint.putIfAbsent(a, state.clone());
            if (k == 1) {
                emitData(a);
                emitData(a + 1);
                prewrap.put(key(a, k), state.clone());
                emitMid(a);
            } else {
                int half = 1 << (k - 1);
                block(a, k - 1);
                block(a + half, k - 1);
                prewrap.put(key(a, k), state.clone());
                emitMid(a);
            }
            ending.put(key(a, k), state.clone());
        }
    }

    public static StructuredFile build(byte[][] elementsIn) {
        int n = elementsIn.length;
        int l = (int) Math.round(Math.log(n) / Math.log(2));
        if ((1 << l) != n) throw new IllegalArgumentException("N must be a power of two");

        byte[][] elements = new byte[n][];
        for (int i = 0; i < n; i++) elements[i] = padElement(elementsIn[i]);

        Builder b = new Builder(elements);
        b.block(0, l - 1);
        b.block(1 << (l - 1), l - 1);
        byte[] rawState = b.state.clone();

        byte[] rawBytesArr = b.rawBytes.toByteArray();
        byte[] pad = Sha256Core.lengthPaddingBlocks(rawBytesArr.length);
        byte[] fstate = rawState;
        for (int i = 0; i < pad.length; i += Sha256Core.BLOCK_SIZE) {
            fstate = Sha256Core.compress(fstate, Arrays.copyOfRange(pad, i, i + Sha256Core.BLOCK_SIZE));
        }

        return new StructuredFile(n, l, elements, rawBytesArr, rawState, fstate,
                b.checkpoint, b.ending, b.prewrap);
    }

    // -------------------------------------------------------------------
    // Single-element inclusion proof
    // -------------------------------------------------------------------

    public static final class Proof {
        public final int index;
        public final byte[] d0;
        public final byte[] d1;
        public final List<byte[]> reveals = new ArrayList<>();

        Proof(int index, byte[] d0, byte[] d1) {
            this.index = index;
            this.d0 = d0;
            this.d1 = d1;
        }

        public int nbytes() {
            return 2 * Sha256Core.BLOCK_SIZE + reveals.size() * Sha256Core.STATE_SIZE;
        }
    }

    private static void recurseProof(StructuredFile sf, Proof pf, int a, int k, int target) {
        if (k == 1) return;
        int half = 1 << (k - 1);
        if (target < a + half) {
            recurseProof(sf, pf, a, k - 1, target);
            pf.reveals.add(sf.prewrap.get(key(a + half, k - 1)));
        } else {
            pf.reveals.add(sf.ending.get(key(a, k - 1)));
            recurseProof(sf, pf, a + half, k - 1, target);
        }
    }

    public static Proof buildProof(StructuredFile sf, int index) {
        int l = sf.l;
        int a0 = index - (index % 2);
        Proof pf = new Proof(index, sf.elements[a0], sf.elements[a0 + 1]);
        int halfTop = 1 << (l - 1);

        if (a0 < halfTop) {
            recurseProof(sf, pf, 0, l - 1, a0);
            pf.reveals.add(sf.prewrap.get(key(halfTop, l - 1)));
        } else {
            pf.reveals.add(sf.ending.get(key(0, l - 1)));
            recurseProof(sf, pf, halfTop, l - 1, a0);
        }
        return pf;
    }

    // -------------------------------------------------------------------
    // Verification
    // -------------------------------------------------------------------

    /** Thrown when a proof runs out of reveals before the recursion completes; caught once, at the top. */
    private static final class ProofExhausted extends RuntimeException {}

    private static byte[] nextReveal(Iterator<byte[]> it) {
        if (!it.hasNext()) throw new ProofExhausted();
        return it.next();
    }

    private static byte[] evalBlock(Proof pf, Iterator<byte[]> it, int a, int k, int target, byte[] ckpt) {
        if (k == 1) {
            byte[] s = Sha256Core.compress(Sha256Core.compress(ckpt, pf.d0), pf.d1);
            return Sha256Core.compress(s, midBlock(ckpt));
        }
        int half = 1 << (k - 1);
        if (target < a + half) {
            byte[] leftEnd = evalBlock(pf, it, a, k - 1, target, ckpt);
            byte[] sibPrewrap = nextReveal(it);
            byte[] rightEnd = Sha256Core.compress(sibPrewrap, midBlock(leftEnd));
            return Sha256Core.compress(rightEnd, midBlock(ckpt));
        } else {
            byte[] leftEnd = nextReveal(it);
            byte[] rightEnd = evalBlock(pf, it, a + half, k - 1, target, leftEnd);
            return Sha256Core.compress(rightEnd, midBlock(ckpt));
        }
    }

    /**
     * O(log N) compression-function calls, ending with the same standard
     * finalization -- never touches the full structured file, never needs a
     * lookup table.
     */
    public static boolean verifyProof(int n, byte[] digest, int index, byte[] data, Proof pf) {
        int l = (int) Math.round(Math.log(n) / Math.log(2));
        if ((1 << l) != n) return false;
        int a0 = index - (index % 2);
        if (pf.index != index) return false;

        byte[] paddedData = padElement(data);
        if (index == a0 && !Arrays.equals(paddedData, pf.d0)) return false;
        if (index == a0 + 1 && !Arrays.equals(paddedData, pf.d1)) return false;

        int halfTop = 1 << (l - 1);
        Iterator<byte[]> it = pf.reveals.iterator();

        try {
            byte[] rawState;
            if (a0 < halfTop) {
                byte[] y = evalBlock(pf, it, 0, l - 1, a0, Sha256Core.IV_STD);
                byte[] r2 = nextReveal(it);
                rawState = Sha256Core.compress(r2, midBlock(y));
            } else {
                byte[] yReveal = nextReveal(it);
                rawState = evalBlock(pf, it, halfTop, l - 1, a0, yReveal);
            }
            if (it.hasNext()) return false; // extra, unused reveals: reject

            byte[] pad = Sha256Core.lengthPaddingBlocks(totalRawLen(n));
            byte[] fstate = rawState;
            for (int i = 0; i < pad.length; i += Sha256Core.BLOCK_SIZE) {
                fstate = Sha256Core.compress(fstate, Arrays.copyOfRange(pad, i, i + Sha256Core.BLOCK_SIZE));
            }
            return Arrays.equals(fstate, digest);
        } catch (ProofExhausted e) {
            return false;
        }
    }
}
