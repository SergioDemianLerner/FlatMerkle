import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * SHA-256's real Davies-Meyer compression function, exposed directly as a
 * (state, 64-byte block) -&gt; state primitive, plus the standard
 * length-padding finalizer. This is a straight port of sha256_core.py, kept
 * bit-for-bit identical to the Python reference so that FlatMerkle.java's
 * digests match the Python implementation exactly on identical input --
 * verified against both java.security.MessageDigest and the Python
 * reference at the bottom of this file (see FlatMerkleTest).
 */
public final class Sha256Core {

    public static final int STATE_SIZE = 32; // bytes (8 x 32-bit words)
    public static final int BLOCK_SIZE = 64;  // bytes -- SHA-256's real message block size

    private Sha256Core() {}

    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /** The standard SHA-256 initial value, as 8 big-endian 32-bit words. */
    public static final byte[] IV_STD = {
        0x6a, 0x09, (byte) 0xe6, 0x67, (byte) 0xbb, 0x67, (byte) 0xae, (byte) 0x85,
        0x3c, 0x6e, (byte) 0xf3, 0x72, (byte) 0xa5, 0x4f, (byte) 0xf5, 0x3a,
        0x51, 0x0e, 0x52, 0x7f, (byte) 0x9b, 0x05, 0x68, (byte) 0x8c,
        0x1f, (byte) 0x83, (byte) 0xd9, (byte) 0xab, 0x5b, (byte) 0xe0, (byte) 0xcd, 0x19
    };

    private static int rotr(int x, int n) {
        return Integer.rotateRight(x, n);
    }

    /**
     * The raw SHA-256 compression function C(state, block) -&gt; state.
     * state: exactly 32 bytes (8 words). block: exactly 64 bytes (16 words).
     * This is exactly what SHA-256 calls once per 64-byte chunk internally;
     * FlatMerkle re-injects past *states* (not full re-hashes) as blocks here.
     */
    public static byte[] compress(byte[] state, byte[] block) {
        if (state.length != STATE_SIZE) throw new IllegalArgumentException("state must be 32 bytes");
        if (block.length != BLOCK_SIZE) throw new IllegalArgumentException("block must be 64 bytes");

        int[] h = new int[8];
        ByteBuffer sbuf = ByteBuffer.wrap(state);
        for (int i = 0; i < 8; i++) h[i] = sbuf.getInt();

        int[] w = new int[64];
        ByteBuffer bbuf = ByteBuffer.wrap(block);
        for (int i = 0; i < 16; i++) w[i] = bbuf.getInt();
        for (int i = 16; i < 64; i++) {
            int s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            int s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            int s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            int ch = (e & f) ^ (~e & g);
            int temp1 = hh + s1 + ch + K[i] + w[i];
            int s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int temp2 = s0 + maj;
            hh = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        int[] out = {h[0] + a, h[1] + b, h[2] + c, h[3] + d, h[4] + e, h[5] + f, h[6] + g, h[7] + hh};
        ByteBuffer obuf = ByteBuffer.allocate(STATE_SIZE);
        for (int x : out) obuf.putInt(x);
        return obuf.array();
    }

    /**
     * The standard SHA-256 length-padding suffix (0x80, zeros, 64-bit bit
     * length) for a message of totalMessageLen bytes -- the "one
     * finalization" applied exactly once, at the very end, regardless of how
     * many compression calls preceded it.
     */
    public static byte[] lengthPaddingBlocks(long totalMessageLen) {
        long bitLen = totalMessageLen * 8;
        int padLen = (int) (((56 - (totalMessageLen + 1) % 64) % 64 + 64) % 64);
        byte[] pad = new byte[1 + padLen + 8];
        pad[0] = (byte) 0x80;
        ByteBuffer.wrap(pad, 1 + padLen, 8).putLong(bitLen);
        if ((totalMessageLen + pad.length) % 64 != 0) {
            throw new IllegalStateException("padding did not align to 64 bytes");
        }
        return pad;
    }

    /** Full SHA-256(message), built purely from compress() + padding, for cross-checking against MessageDigest. */
    public static byte[] sha256ViaCompress(byte[] message) {
        byte[] pad = lengthPaddingBlocks(message.length);
        byte[] padded = new byte[message.length + pad.length];
        System.arraycopy(message, 0, padded, 0, message.length);
        System.arraycopy(pad, 0, padded, message.length, pad.length);
        byte[] state = IV_STD.clone();
        for (int i = 0; i < padded.length; i += 64) {
            state = compress(state, Arrays.copyOfRange(padded, i, i + 64));
        }
        return state;
    }

    /** Self-test: verifies byte-for-byte against java.security.MessageDigest. */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest ref = MessageDigest.getInstance("SHA-256");
        java.util.Random rnd = new java.util.Random(42);
        int[] lengths = {0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1000, 4096};
        boolean allOk = true;
        for (int n : lengths) {
            byte[] msg = new byte[n];
            rnd.nextBytes(msg);
            byte[] mine = sha256ViaCompress(msg);
            byte[] expected = ref.digest(msg);
            boolean ok = Arrays.equals(mine, expected);
            allOk &= ok;
            if (!ok) {
                System.out.println("MISMATCH len=" + n);
            }
        }
        System.out.println("Sha256Core self-test: " + (allOk ? "ALL PASSED" : "FAILED")
                + " (" + lengths.length + " messages, lengths spanning multiple block boundaries)");
    }
}
