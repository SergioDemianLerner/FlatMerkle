import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

/**
 * Self-test for FlatMerkle.java, mirroring loglink_annex.py's own
 * __main__ block: for N = 4..64, build a structured file, confirm
 * digest == SHA256(raw structured bytes) via java.security.MessageDigest,
 * then prove and verify *every* index, and confirm tamper-rejection on
 * both the target data and every individual revealed value.
 *
 * Run: java Main.java   (JDK 11+, single-file source launch -- no separate
 * compile step needed) or javac *.java && java Main if you prefer a normal
 * build.
 */
public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        boolean allOk = true;

        for (int l = 2; l <= 6; l++) {
            int n = 1 << l;
            Random rnd = new Random(1000 + l);
            byte[][] elements = new byte[n][];
            for (int i = 0; i < n; i++) {
                elements[i] = new byte[Sha256Core.BLOCK_SIZE];
                rnd.nextBytes(elements[i]);
            }

            FlatMerkle.StructuredFile sf = FlatMerkle.build(elements);

            byte[] expected = sha256.digest(sf.rawBytes);
            boolean digestOk = Arrays.equals(sf.digest, expected);
            allOk &= digestOk;
            if (!digestOk) {
                System.out.println("N=" + n + ": digest MISMATCH vs SHA256(raw bytes)!");
            }

            int okCount = 0;
            for (int i = 0; i < n; i++) {
                FlatMerkle.Proof pf = FlatMerkle.buildProof(sf, i);
                boolean ok = FlatMerkle.verifyProof(n, sf.digest, i, elements[i], pf);
                if (!ok) {
                    allOk = false;
                    System.out.println("N=" + n + " index=" + i + " FAILED TO VERIFY");
                }

                // tamper the target data: must be rejected
                byte[] bad = elements[i].clone();
                bad[0] ^= 1;
                if (FlatMerkle.verifyProof(n, sf.digest, i, bad, pf)) {
                    allOk = false;
                    System.out.println("N=" + n + " index=" + i + " TAMPERED DATA ACCEPTED!");
                }

                // tamper every individual revealed value: each must be rejected
                for (int r = 0; r < pf.reveals.size(); r++) {
                    FlatMerkle.Proof tampered = new FlatMerkle.Proof(pf.index, pf.d0, pf.d1);
                    for (int j = 0; j < pf.reveals.size(); j++) {
                        byte[] v = pf.reveals.get(j).clone();
                        if (j == r) v[0] ^= 1;
                        tampered.reveals.add(v);
                    }
                    if (FlatMerkle.verifyProof(n, sf.digest, i, elements[i], tampered)) {
                        allOk = false;
                        System.out.println("N=" + n + " index=" + i + " reveal[" + r + "] tamper ACCEPTED!");
                    }
                }
                okCount++;
            }

            System.out.printf("N=%3d: digest == SHA256(raw bytes) [%s]   all %d proofs verify, "
                            + "all tamper tests rejected. structured-file size = %d bytes, "
                            + "single proof = %d bytes%n",
                    n, digestOk ? "OK" : "FAIL", okCount, sf.rawBytes.length, FlatMerkle.buildProof(sf, 0).nbytes());
        }

        System.out.println();
        System.out.println(allOk ? "Main self-test: ALL PASSED" : "Main self-test: FAILED");

        // Fixed, deterministic input for cross-checking against the Python
        // reference implementation bit-for-bit (see cross_check.py):
        // elements[i] = 64 bytes, every byte equal to i, for N=32.
        int n = 32;
        byte[][] elements = new byte[n][];
        for (int i = 0; i < n; i++) {
            byte[] e = new byte[Sha256Core.BLOCK_SIZE];
            Arrays.fill(e, (byte) i);
            elements[i] = e;
        }
        FlatMerkle.StructuredFile sf = FlatMerkle.build(elements);
        StringBuilder hex = new StringBuilder();
        for (byte b : sf.digest) hex.append(String.format("%02x", b));
        System.out.println();
        System.out.println("CROSS_CHECK_DIGEST=" + hex);
    }
}
